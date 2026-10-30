package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/asturale/request-access/internal/host"
	"github.com/asturale/request-access/internal/proto"
)

// Secret is one file in /etc/request-access/vault: who may ask for it, and
// the secret itself, sealed to the vault key. Root can read the file but not
// the secret.
type Secret struct {
	Name  string   `json:"name"`
	Users []string `json:"users"`         // user names, or "@group"
	Env   string   `json:"env,omitempty"` // variable name for "vault run"
	Box   *Box     `json:"box"`
	// Commit is SHA-256(salt || secret), where the 32-byte salt is sealed
	// inside the box with the secret. A released secret is accepted only if
	// it matches, so nobody without the vault password can slip in another
	// value; the unknown salt keeps the hash from revealing a guessable
	// secret.
	Commit string `json:"commit"`
	Added  int64  `json:"added"`
}

const saltLen = 32

// maxWait bounds how long a host waits for an answer (the Worker keeps vault
// requests open for 5 minutes, setup and trust links for 15).
const maxWait = 16 * time.Minute

var (
	NameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	envRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

func dir() string { return filepath.Join(host.ConfigDir, "vault") }

func path(name string) string { return filepath.Join(dir(), name+".json") }

// split checks a released salt||secret against the commitment and returns
// the secret.
func (s *Secret) split(opened []byte) ([]byte, error) {
	if len(opened) <= saltLen {
		return nil, errors.New("released secret is malformed")
	}
	h := sha256.Sum256(opened)
	if b64.EncodeToString(h[:]) != s.Commit {
		return nil, errors.New("released secret does not match the stored one")
	}
	return opened[saltLen:], nil
}

func pinned() (*host.Config, error) {
	cfg, _, _, err := host.LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Vault == nil || cfg.Vault.Key == "" {
		return nil, errors.New("no vault key pinned here; run: request-access vault init (or vault pin)")
	}
	return cfg, nil
}

// PinnedKey returns the vault key this host encrypts to.
func PinnedKey() (string, error) {
	cfg, err := pinned()
	if err != nil {
		return "", err
	}
	return cfg.Vault.Key, nil
}

// Pin stores the vault key in this host's configuration.
func Pin(key string) error {
	if _, err := ParsePublicKey(key); err != nil {
		return err
	}
	cfg, _, _, err := host.LoadConfig()
	if err != nil {
		return err
	}
	cfg.Vault = &host.VaultConfig{Key: key}
	return host.SaveConfig(cfg)
}

// Add seals value to the pinned vault key and stores it.
func Add(name string, users []string, env string, value []byte) (*Secret, error) {
	if !NameRE.MatchString(name) {
		return nil, fmt.Errorf("bad name %q (letters, digits, . _ -)", name)
	}
	if env != "" && !envRE.MatchString(env) {
		return nil, fmt.Errorf("bad variable name %q", env)
	}
	if len(users) == 0 {
		return nil, errors.New("say who may ask for it: --users NAME[,NAME|@GROUP]")
	}
	if len(value) == 0 || len(value) > 16<<10 {
		return nil, errors.New("the secret must be 1 byte to 16 KiB")
	}
	cfg, err := pinned()
	if err != nil {
		return nil, err
	}
	pub, err := ParsePublicKey(cfg.Vault.Key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, saltLen, saltLen+len(value))
	if _, err := rand.Read(plain); err != nil {
		return nil, err
	}
	plain = append(plain, value...)
	box, err := Seal(pub, plain, SecretAAD(cfg.Name, name))
	h := sha256.Sum256(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	s := &Secret{Name: name, Users: users, Env: env, Box: box, Commit: b64.EncodeToString(h[:]), Added: time.Now().Unix()}
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	return s, host.WriteFileAtomic(path(name), append(data, '\n'), 0o600)
}

// Load reads one secret's file.
func Load(name string) (*Secret, error) {
	if !NameRE.MatchString(name) {
		return nil, fmt.Errorf("no secret %q", name)
	}
	data, err := os.ReadFile(path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no secret %q", name)
	}
	if err != nil {
		return nil, err
	}
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path(name), err)
	}
	if s.Name != name || s.Box == nil || s.Commit == "" {
		return nil, fmt.Errorf("%s: incomplete", path(name))
	}
	return &s, nil
}

// List returns all secrets, sorted by name.
func List() ([]*Secret, error) {
	entries, err := os.ReadDir(dir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Secret
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !NameRE.MatchString(n) {
			continue
		}
		if s, err := Load(n); err == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes a secret's file.
func Remove(name string) error {
	if _, err := Load(name); err != nil {
		return err
	}
	return os.Remove(path(name))
}

// Allows reports whether u may ask for the secret.
func (s *Secret) Allows(u *user.User) bool {
	if slices.Contains(s.Users, u.Username) {
		return true
	}
	gids, _ := u.GroupIds()
	for _, entry := range s.Users {
		g, ok := strings.CutPrefix(entry, "@")
		if !ok {
			continue
		}
		if grp, err := user.LookupGroup(g); err == nil && slices.Contains(gids, grp.Gid) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- init / trust / pin

// waitFor polls a host-signed status endpoint until it is no longer pending.
func waitFor(client *proto.Client, path string, expires int64, out any, status func() string) error {
	// The Worker says when the request expires; never wait longer than the
	// longest the protocol allows, whatever it says.
	deadline := time.Unix(expires, 0)
	if limit := time.Now().Add(maxWait); deadline.After(limit) {
		deadline = limit
	}
	deadline = deadline.Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Do("GET", path+"?wait=20", nil, out); err != nil {
			return err
		}
		switch st := status(); st {
		case "pending":
			continue
		case "approved":
			return nil
		default:
			return errors.New(st)
		}
	}
	return errors.New("timed out")
}

func hostFingerprint(key ed25519.PrivateKey) string {
	return proto.Fingerprint(key.Public().(ed25519.PublicKey))
}

// Init asks the server to create the vault: the approver opens the link on
// Telegram, picks the vault password in the browser, and the page creates the
// key, trusting this host. The host then pins the public key.
func Init(out func(string, ...any)) (string, error) {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return "", err
	}
	client := cfg.Client(key)
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	if err := client.Do("POST", "/v1/vault/init", map[string]string{"nonce": proto.Nonce()}, &created); err != nil {
		return "", err
	}
	out("Open the link on Telegram and choose the vault password (save it in your password manager).\n")
	out("The page should show this server's key fingerprint %s.\n", hostFingerprint(key))
	var st struct {
		Status string `json:"status"`
		Key    string `json:"key"`
	}
	if err := waitFor(client, "/v1/vault/init/"+created.ID, created.Expires, &st, func() string { return st.Status }); err != nil {
		return "", fmt.Errorf("vault not created: %w", err)
	}
	if err := Pin(st.Key); err != nil {
		return "", err
	}
	return st.Key, nil
}

// Fetch returns the vault key the server holds, to pin on another host after
// comparing its fingerprint with one already pinned elsewhere.
func Fetch() (string, error) {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return "", err
	}
	var r struct {
		Key string `json:"key"`
	}
	if err := cfg.Client(key).Do("GET", "/v1/vault/key", nil, &r); err != nil {
		return "", err
	}
	if _, err := ParsePublicKey(r.Key); err != nil {
		return "", err
	}
	return r.Key, nil
}

// Trust asks the approver to add this host to the hosts the vault accepts
// requests from. That list lives inside the locked vault key, so only the
// vault password can change it; the page shows this host's key fingerprint.
func Trust(out func(string, ...any)) error {
	cfg, key, _, err := host.LoadConfig()
	if err != nil {
		return err
	}
	client := cfg.Client(key)
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	if err := client.Do("POST", "/v1/vault/trust", map[string]string{"nonce": proto.Nonce()}, &created); err != nil {
		return err
	}
	out("Open the link on Telegram and enter the vault password to trust this server.\n")
	out("The page should show this server's key fingerprint %s.\n", hostFingerprint(key))
	var st struct {
		Status string `json:"status"`
	}
	if err := waitFor(client, "/v1/vault/trust/"+created.ID, created.Expires, &st, func() string { return st.Status }); err != nil {
		return fmt.Errorf("not trusted: %w", err)
	}
	return nil
}
