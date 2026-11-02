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
	// Hold asks the agent to keep the secret for this many seconds between
	// uses, for this user and session (see hold.go); the host config caps
	// it, and the approver decides.
	Hold int64 `json:"hold,omitempty"`
	// Forget drops the caller's held secrets (all, or only Name).
	Forget bool `json:"forget,omitempty"`
}

type AgentAnswer struct {
	Secret string `json:"secret,omitempty"` // standard base64
	Env    string `json:"env,omitempty"`
	// Held says how the secret was held: "new" (released and now held for
	// HeldFor seconds between uses) or "reused" (served from a hold).
	Held    string `json:"held,omitempty"`
	HeldFor int64  `json:"held_for,omitempty"`
	Dropped int    `json:"dropped,omitempty"` // for Forget
	Error   string `json:"error,omitempty"`
}

const (
	maxPendingPerUser = 3    // open requests per local user
	maxConnections    = 32   // connections served at once
	maxRequestBytes   = 4096 // one request line
	maxReason         = 200  // characters
	maxDetail         = 256  // characters
)

// Agent serves secret requests from local users. It runs as root because it
// signs requests with the host key and reads the secret files. It holds a
// usable secret only for the moment it hands one over, or, when the caller
// asked and the approver agreed, in memory for the hold's terms.
type Agent struct {
	Logf    func(string, ...any)
	mu      sync.Mutex
	pending map[uint32]int
	slots   chan struct{}
	holds   holds
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
	go func() {
		for range time.Tick(30 * time.Second) {
			a.holds.sweep(time.Now())
		}
	}()
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
	if req.Forget {
		n := a.holds.forget(cred.Uid, req.Name)
		a.Logf("vault: %s dropped %d held secret(s)", u.Username, n)
		reply(AgentAnswer{Dropped: n})
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
	detail := clean(commandOf(cred.Pid), maxDetail)
	var key holdKey
	var terms string
	var idle, total int64
	if req.Hold > 0 {
		if scope := sessionScope(cred.Pid); scope != "" {
			key = holdKey{uid: cred.Uid, name: s.Name, commit: s.Commit, scope: scope}
			if value, env, id, gen, ok := a.holds.get(key, time.Now()); ok {
				// Every reuse is reported; if the approver revoked the hold,
				// or the report fails, ask again instead. The hold may also
				// have been forgotten or ended while the report was out.
				err := Reused(id, reason, detail)
				if err == nil && !a.holds.still(key, gen, time.Now()) {
					err = errors.New("dropped meanwhile")
				}
				if err == nil {
					a.Logf("vault: %s / %q: served from hold", u.Username, s.Name)
					reply(AgentAnswer{Secret: base64.StdEncoding.EncodeToString(value), Env: env, Held: "reused"})
					clear(value)
					return
				}
				clear(value)
				a.holds.drop(key)
				a.Logf("vault: %s / %q: hold ended: %v", u.Username, s.Name, err)
			}
			if cfg, _, _, err := host.LoadConfig(); err == nil {
				maxHold, maxLease := cfg.Vault.HoldLimits()
				idle, total, terms = holdTerms(req.Hold, maxHold, maxLease)
			}
		}
	}
	a.Logf("vault: %s asks for %q (reason %q, hold %q)", u.Username, s.Name, reason, terms)
	value, held, id, err := Request(s, u.Username, reason, detail, terms)
	if err != nil {
		a.Logf("vault: %s / %q: %v", u.Username, s.Name, err)
		reply(AgentAnswer{Error: err.Error()})
		return
	}
	ans := AgentAnswer{Secret: base64.StdEncoding.EncodeToString(value), Env: s.Env}
	if held {
		now := time.Now()
		a.holds.put(key, &heldSecret{
			value: append([]byte{}, value...), env: s.Env, request: id,
			idle: time.Duration(idle) * time.Second, until: now.Add(time.Duration(total) * time.Second), lastUsed: now,
		})
		ans.Held, ans.HeldFor = "new", idle
	}
	a.Logf("vault: %s / %q: released (held: %v)", u.Username, s.Name, held)
	reply(ans)
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
//
// With hold terms (see HoldTerms), the approver may agree to let the agent
// hold the secret; held then says whether they did. id is the Worker's
// request id, under which reuse of a hold is reported.
func Request(s *Secret, username, reason, detail, hold string) (value []byte, held bool, id string, err error) {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return nil, false, "", err
	}
	if cfg.Vault == nil {
		return nil, false, "", errors.New("no vault key pinned")
	}
	reply, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, "", err
	}
	replyKey := EncodePublicKey(reply.PublicKey())
	nonce := proto.Nonce()
	sig := ed25519.Sign(key, RequestMessage(cfg.Name, username, s.Name, reason, detail, replyKey, nonce, s.Box, hold))
	client := cfg.Client(key)
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	body := map[string]any{
		"name": s.Name, "user": username, "reason": reason, "detail": detail,
		"box": s.Box, "reply_key": replyKey, "vault_key": cfg.Vault.Key,
		"nonce": nonce, "sig": b64.EncodeToString(sig),
	}
	if hold != "" {
		body["hold"] = hold
	}
	if err = client.Do("POST", "/v1/vault/request", body, &created); err != nil {
		return nil, false, "", err
	}
	var st struct {
		Status string `json:"status"`
		Sealed *Box   `json:"sealed"`
	}
	if err := waitFor(client, "/v1/vault/request/"+created.ID, created.Expires, &st, func() string { return st.Status }); err != nil {
		return nil, false, "", fmt.Errorf("not released: %w", err)
	}
	// Sealed for a hold only if the approver agreed to the signed terms.
	var opened []byte
	if hold != "" {
		if opened, err = Open(reply, st.Sealed, HeldReleaseAAD(nonce, s.Name, hold)); err == nil {
			held = true
		}
	}
	if !held {
		if opened, err = Open(reply, st.Sealed, ReleaseAAD(nonce, s.Name)); err != nil {
			return nil, false, "", err
		}
	}
	v, err := s.split(opened)
	if err != nil {
		clear(opened)
		return nil, false, "", err
	}
	out := append([]byte{}, v...)
	clear(opened)
	return out, held, created.ID, nil
}

// Reused reports to the approver that a held secret is used again, and fails
// if they revoked the hold.
func Reused(id, reason, detail string) error {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return err
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := cfg.Client(key).Do("POST", "/v1/vault/held/"+id, map[string]any{
		"reason": reason, "detail": detail, "nonce": proto.Nonce(),
	}, &out); err != nil {
		return err
	}
	if out.Status != "held" {
		return fmt.Errorf("hold %s", out.Status)
	}
	return nil
}

// Ask is the client side: it asks the local agent for a secret, to be held
// for hold between uses if that is not zero.
func Ask(name, reason string, hold time.Duration) (value []byte, ans AgentAnswer, err error) {
	ans, err = ask(AgentRequest{Name: name, Reason: reason, Hold: int64(hold / time.Second)})
	if err != nil {
		return nil, ans, err
	}
	value, err = base64.StdEncoding.DecodeString(ans.Secret)
	ans.Secret = ""
	return value, ans, err
}

// Forget asks the agent to drop the caller's held secrets (name "" for all).
func Forget(name string) (int, error) {
	ans, err := ask(AgentRequest{Name: name, Forget: true})
	return ans.Dropped, err
}

func ask(req AgentRequest) (AgentAnswer, error) {
	var ans AgentAnswer
	c, err := net.Dial("unix", SocketPath)
	if err != nil {
		return ans, fmt.Errorf("vault agent not reachable (%w); is request-access-vault running?", err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return ans, err
	}
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&ans); err != nil {
		return ans, fmt.Errorf("no answer from the vault agent: %w", err)
	}
	if ans.Error != "" {
		return ans, errors.New(ans.Error)
	}
	return ans, nil
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
