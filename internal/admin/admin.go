// Package admin is the operator side: one-time setup of the Worker and
// Telegram bot, and day-to-day configuration (every change is confirmed on
// Telegram by the server before it takes effect).
package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asturale/request-access/internal/cloudflare"
	"github.com/asturale/request-access/internal/proto"
	"github.com/asturale/request-access/worker"
)

// Config is the admin's local file (~/.config/request-access/admin.json).
type Config struct {
	URL       string `json:"url"`
	ServerKey string `json:"server_key"`
	KeyID     string `json:"key_id"`
	Key       string `json:"key"` // Ed25519 seed, base64url
	// Kept so `setup --update` can redeploy without asking again.
	WorkerName string `json:"worker_name,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
}

func ConfigPath() string {
	if p := os.Getenv("REQUEST_ACCESS_ADMIN_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "request-access", "admin.json")
}

func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("no admin config (%w); run `request-access setup` first", err)
	}
	var c Config
	return &c, json.Unmarshal(data, &c)
}

func (c *Config) save() error {
	if err := os.MkdirAll(filepath.Dir(ConfigPath()), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(ConfigPath(), append(data, '\n'), 0o600)
}

func (c *Config) client() (*proto.Client, error) {
	key, err := proto.DecodeSeed(c.Key)
	if err != nil {
		return nil, err
	}
	return &proto.Client{BaseURL: c.URL, KeyID: c.KeyID, Key: key}, nil
}

// ---------------------------------------------------------------- setup

type SetupOptions struct {
	CFToken    string
	AccountID  string
	WorkerName string
	BotToken   string
	ApproverID string // Telegram user id; also the chat the bot writes to
	Lang       string
	Update     bool // redeploy the script only, keep keys and secrets
	Replace    bool // set up again over an existing worker (new keys; hosts must re-enroll)
	Out        func(format string, a ...any)
}

func Setup(o SetupOptions) error {
	cf := &cloudflare.Client{Token: o.CFToken, AccountID: o.AccountID}
	if o.Update {
		cfg, err := Load()
		if err != nil {
			return err
		}
		if cf.AccountID == "" {
			cf.AccountID = cfg.AccountID
		}
		if o.WorkerName == "" {
			o.WorkerName = cfg.WorkerName
		}
		if err := cf.ResolveAccount(); err != nil {
			return err
		}
		o.Out("Uploading worker %q...\n", o.WorkerName)
		return cf.Deploy(cloudflare.DeployOptions{Name: o.WorkerName, Script: worker.Script})
	}

	if o.BotToken == "" || o.ApproverID == "" {
		return errors.New("--bot-token and --approver are required")
	}
	if _, err := strconv.ParseInt(o.ApproverID, 10, 64); err != nil {
		return errors.New("--approver must be a numeric Telegram user id")
	}
	if !regexp.MustCompile(`^[a-z0-9-]{1,63}$`).MatchString(o.WorkerName) {
		return errors.New("worker name may only contain lowercase letters, digits and '-'")
	}
	if err := cf.ResolveAccount(); err != nil {
		return err
	}
	exists, err := cf.Exists(o.WorkerName)
	if err != nil {
		return err
	}
	if exists && !o.Replace {
		return fmt.Errorf("a worker named %q already exists; use --update to redeploy it, --replace to set it up again with new keys, or pick another --name", o.WorkerName)
	}

	// The bot must be able to write to the approver first.
	o.Out("Checking the Telegram bot...\n")
	if err := telegram(o.BotToken, "sendMessage", map[string]any{
		"chat_id": o.ApproverID,
		"text":    "Request Access: setting up. You will get approval requests here.",
	}); err != nil {
		return fmt.Errorf("the bot cannot message you (%w). Open the bot in Telegram and press Start first", err)
	}

	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signing)
	if err != nil {
		return err
	}
	adminPub, adminPriv, _ := ed25519.GenerateKey(rand.Reader)
	secret := make([]byte, 32)
	rand.Read(secret)
	webhookSecret := base64.RawURLEncoding.EncodeToString(secret)

	o.Out("Uploading worker %q to Cloudflare...\n", o.WorkerName)
	err = cf.Deploy(cloudflare.DeployOptions{
		Name:   o.WorkerName,
		Script: worker.Script,
		Create: !exists,
		Secrets: map[string]string{
			"SIGNING_KEY":             base64.RawURLEncoding.EncodeToString(pkcs8),
			"TELEGRAM_BOT_TOKEN":      o.BotToken,
			"TELEGRAM_WEBHOOK_SECRET": webhookSecret,
			"TELEGRAM_CHAT_ID":        o.ApproverID,
			"APPROVER_IDS":            o.ApproverID,
			"ADMIN_KEYS":              proto.EncodeKey(adminPub),
		},
	})
	if err != nil {
		return err
	}
	workerURL, err := cf.EnableWorkersDev(o.WorkerName)
	if err != nil {
		return err
	}
	o.Out("Worker URL: %s\n", workerURL)

	// A fresh workers.dev hostname can take a little while to resolve.
	var info struct {
		WorkerKey string `json:"worker_key"`
	}
	unsigned := &proto.Client{BaseURL: workerURL}
	for i := 0; ; i++ {
		if err = unsigned.Do("GET", "/v1/info", nil, &info); err == nil {
			break
		}
		if i == 30 {
			return fmt.Errorf("worker not reachable: %w", err)
		}
		time.Sleep(5 * time.Second)
	}
	if info.WorkerKey != proto.EncodeKey(signing.Public().(ed25519.PublicKey)) {
		return errors.New("the deployed worker reports an unexpected key")
	}

	if err := telegram(o.BotToken, "setWebhook", map[string]any{
		"url":                  workerURL + "/telegram/webhook",
		"secret_token":         webhookSecret,
		"allowed_updates":      []string{"callback_query"},
		"drop_pending_updates": true,
	}); err != nil {
		return fmt.Errorf("setting the Telegram webhook: %w", err)
	}

	cfg := &Config{
		URL: workerURL, ServerKey: info.WorkerKey, KeyID: "admin:0",
		Key: proto.EncodeSeed(adminPriv), WorkerName: o.WorkerName, AccountID: cf.AccountID,
	}
	if err := cfg.save(); err != nil {
		return err
	}
	o.Out("Admin config saved to %s\n", ConfigPath())
	if o.Lang != "" && o.Lang != "en" {
		o.Out("Setting language to %q (confirm on Telegram)...\n", o.Lang)
		if err := SetConfig(map[string]any{"lang": o.Lang}, o.Out); err != nil {
			return err
		}
	}
	o.Out("\nDone. Enroll a server with:\n  sudo request-access enroll --url %s --server-key %s --name <hostname>\n", workerURL, info.WorkerKey)
	return nil
}

func telegram(token, method string, params map[string]any) error {
	body, _ := json.Marshal(params)
	res, err := http.Post("https://api.telegram.org/bot"+url.PathEscape(token)+"/"+method, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	json.Unmarshal(data, &r)
	if !r.OK {
		return errors.New(r.Description)
	}
	return nil
}

// ---------------------------------------------------------------- state & changes

type State struct {
	Version string         `json:"version"`
	Config  map[string]any `json:"config"`
	Hosts   []struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		Added       int64  `json:"added"`
	} `json:"hosts"`
}

func GetState() (*State, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	c, err := cfg.client()
	if err != nil {
		return nil, err
	}
	var st State
	return &st, c.Do("GET", "/v1/admin/state", nil, &st)
}

// SetConfig proposes a config change and waits for it to be confirmed.
func SetConfig(changes map[string]any, out func(string, ...any)) error {
	return action(map[string]any{"action": "set_config", "config": changes}, out)
}

func RemoveHost(name string, out func(string, ...any)) error {
	return action(map[string]any{"action": "remove_host", "name": name}, out)
}

func action(body map[string]any, out func(string, ...any)) error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	c, err := cfg.client()
	if err != nil {
		return err
	}
	body["nonce"] = proto.Nonce()
	var res struct {
		ID string `json:"id"`
	}
	if err := c.Do("POST", "/v1/admin/actions", body, &res); err != nil {
		return err
	}
	out("Confirm the change on Telegram...\n")
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		var st struct {
			Status string `json:"status"`
		}
		if err := c.Do("GET", "/v1/admin/actions/"+res.ID+"?wait=25", nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "approved":
			out("Applied.\n")
			return nil
		case "denied", "expired":
			return errors.New("change " + st.Status)
		}
	}
	return errors.New("timed out")
}

// ParseDuration accepts plain seconds or Go-style durations ("15m", "2h").
func ParseDuration(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil {
			return n * 86400, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return int(d.Seconds()), nil
}

// ParseSettings turns `key=value` arguments into a config change.
// Keys: lang, request_timeout, default_window, max_window, window.<service>,
// window.<host>/<service> (value "default" removes a window override).
func ParseSettings(args []string, current map[string]any) (map[string]any, error) {
	out := map[string]any{}
	windows := map[string]any{}
	if w, ok := current["windows"].(map[string]any); ok {
		for k, v := range w {
			windows[k] = v
		}
	}
	touchedWindows := false
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("expected key=value, got %q", a)
		}
		switch {
		case k == "lang":
			out["lang"] = v
		case k == "request_timeout" || k == "default_window" || k == "max_window":
			n, err := ParseDuration(v)
			if err != nil {
				return nil, err
			}
			out[k] = n
		case strings.HasPrefix(k, "window.") || strings.HasPrefix(k, "windows."):
			wk := k[strings.Index(k, ".")+1:]
			touchedWindows = true
			if v == "default" {
				windows[wk] = nil
				continue
			}
			n, err := ParseDuration(v)
			if err != nil {
				return nil, err
			}
			windows[wk] = n
		default:
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	if touchedWindows {
		out["windows"] = windows
	}
	return out, nil
}
