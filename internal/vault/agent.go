package vault

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/asturale/request-access/internal/host"
	"github.com/asturale/request-access/internal/proto"
)

// SocketPath is where the agent listens; any local user may connect, the
// agent decides per secret who may ask.
var SocketPath = envOr("REQUEST_ACCESS_VAULT_SOCKET", "/run/request-access/vault.sock")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// AgentRequest and AgentAnswer are one JSON line each over the socket. The
// secret travels base64-encoded, so any bytes survive.
type AgentRequest struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type AgentAnswer struct {
	Secret string `json:"secret,omitempty"` // standard base64
	Env    string `json:"env,omitempty"`
	Error  string `json:"error,omitempty"`
}

const (
	maxPendingPerUser = 3    // open requests per local user
	maxConnections    = 32   // connections served at once
	maxRequestBytes   = 4096 // one request line
	maxReason         = 200  // characters
	maxDetail         = 256  // characters
)

// Agent serves secret requests from local users. It runs as root because it
// signs requests with the host key and reads the secret files; it never
// holds a usable secret except for the moment it hands one over.
type Agent struct {
	Logf    func(string, ...any)
	mu      sync.Mutex
	pending map[uint32]int
	slots   chan struct{}
}

// Serve listens on SocketPath until the listener fails.
func (a *Agent) Serve() error {
	if a.Logf == nil {
		a.Logf = log.Printf
	}
	a.pending = map[uint32]int{}
	a.slots = make(chan struct{}, maxConnections)
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(SocketPath)
	ln, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		return err
	}
	a.Logf("vault agent listening on %s", SocketPath)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case a.slots <- struct{}{}:
			go func() {
				defer func() { <-a.slots }()
				a.handle(c.(*net.UnixConn))
			}()
		default:
			c.Close() // busy
		}
	}
}

func (a *Agent) handle(c *net.UnixConn) {
	defer c.Close()
	reply := func(ans AgentAnswer) {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = json.NewEncoder(c).Encode(ans)
	}
	cred, err := peerCred(c)
	if err != nil {
		reply(AgentAnswer{Error: "cannot identify the caller"})
		return
	}
	if !a.reserve(cred.Uid) {
		reply(AgentAnswer{Error: "too many open requests"})
		return
	}
	defer a.release(cred.Uid)
	u, err := user.LookupId(strconv.Itoa(int(cred.Uid)))
	if err != nil {
		reply(AgentAnswer{Error: "unknown user"})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, maxRequestBytes)).ReadBytes('\n')
	if err != nil {
		reply(AgentAnswer{Error: "bad request"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req AgentRequest
	if json.Unmarshal(line, &req) != nil {
		reply(AgentAnswer{Error: "bad request"})
		return
	}
	s, err := Load(req.Name)
	// Unknown and forbidden look the same to the caller.
	if err != nil || !s.Allows(u) {
		a.Logf("vault: %s asked for %q: refused", u.Username, req.Name)
		reply(AgentAnswer{Error: fmt.Sprintf("no secret %q for %s", req.Name, u.Username)})
		return
	}
	reason := clean(req.Reason, maxReason)
	a.Logf("vault: %s asks for %q (reason %q)", u.Username, s.Name, reason)
	value, err := Request(s, u.Username, reason, clean(commandOf(cred.Pid), maxDetail))
	if err != nil {
		a.Logf("vault: %s / %q: %v", u.Username, s.Name, err)
		reply(AgentAnswer{Error: err.Error()})
		return
	}
	a.Logf("vault: %s / %q: released", u.Username, s.Name)
	reply(AgentAnswer{Secret: base64.StdEncoding.EncodeToString(value), Env: s.Env})
	clear(value)
}

func (a *Agent) reserve(uid uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending[uid] >= maxPendingPerUser {
		return false
	}
	a.pending[uid]++
	return true
}

func (a *Agent) release(uid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending[uid]--
}

// Request asks the approver to release one secret and waits for the answer.
// The request is signed with the host key; the approver's browser checks
// that signature against the hosts stored inside the locked vault key,
// decrypts the secret with the vault password and seals it to a key made for
// this request only. The result must match the secret's commitment.
func Request(s *Secret, username, reason, detail string) ([]byte, error) {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Vault == nil {
		return nil, errors.New("no vault key pinned")
	}
	reply, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	replyKey := EncodePublicKey(reply.PublicKey())
	nonce := proto.Nonce()
	sig := ed25519.Sign(key, RequestMessage(cfg.Name, username, s.Name, reason, detail, replyKey, nonce, s.Box))
	client := cfg.Client(key)
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	err = client.Do("POST", "/v1/vault/request", map[string]any{
		"name": s.Name, "user": username, "reason": reason, "detail": detail,
		"box": s.Box, "reply_key": replyKey, "vault_key": cfg.Vault.Key,
		"nonce": nonce, "sig": b64.EncodeToString(sig),
	}, &created)
	if err != nil {
		return nil, err
	}
	var st struct {
		Status string `json:"status"`
		Sealed *Box   `json:"sealed"`
	}
	if err := waitFor(client, "/v1/vault/request/"+created.ID, created.Expires, &st, func() string { return st.Status }); err != nil {
		return nil, fmt.Errorf("not released: %w", err)
	}
	opened, err := Open(reply, st.Sealed, ReleaseAAD(nonce, s.Name))
	if err != nil {
		return nil, err
	}
	value, err := s.split(opened)
	if err != nil {
		clear(opened)
		return nil, err
	}
	out := append([]byte{}, value...)
	clear(opened)
	return out, nil
}

// Ask is the client side: it asks the local agent for a secret.
func Ask(name, reason string) (value []byte, env string, err error) {
	c, err := net.Dial("unix", SocketPath)
	if err != nil {
		return nil, "", fmt.Errorf("vault agent not reachable (%w); is request-access-vault running?", err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(AgentRequest{Name: name, Reason: reason}); err != nil {
		return nil, "", err
	}
	var ans AgentAnswer
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&ans); err != nil {
		return nil, "", fmt.Errorf("no answer from the vault agent: %w", err)
	}
	if ans.Error != "" {
		return nil, "", errors.New(ans.Error)
	}
	value, err = base64.StdEncoding.DecodeString(ans.Secret)
	return value, ans.Env, err
}

func peerCred(c *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, serr
}

// commandOf is the caller's command line, shown to the approver. The caller
// controls it, so it is informative only; the user name is not.
func commandOf(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

// clean makes text safe to sign and show: valid UTF-8, no control
// characters, at most n characters.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}
