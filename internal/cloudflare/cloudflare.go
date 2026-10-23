// Package cloudflare deploys the Request Access Worker through the
// Cloudflare API: script upload (with its Durable Object and secrets) and
// the workers.dev route. No wrangler or dashboard steps needed.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

const api = "https://api.cloudflare.com/client/v4"

type Client struct {
	Token     string
	AccountID string
	HTTP      *http.Client
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int
		Message string
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(method, path, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequest(method, api+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("cloudflare %s %s: HTTP %d", method, path, res.StatusCode)
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(msgs, "; "))
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// ResolveAccount fills AccountID when the token can see exactly one account.
func (c *Client) ResolveAccount() error {
	if c.AccountID != "" {
		return nil
	}
	var accts []struct{ ID, Name string }
	if err := c.do("GET", "/accounts", "", nil, &accts); err != nil {
		return err
	}
	if len(accts) != 1 {
		return fmt.Errorf("token can see %d accounts; pass --account-id", len(accts))
	}
	c.AccountID = accts[0].ID
	return nil
}

// Binding is a Worker binding as the upload metadata describes it.
type Binding map[string]string

// DeployOptions describes one Worker upload.
type DeployOptions struct {
	Name    string
	Script  string
	Secrets map[string]string // set (or replace) these secret bindings
	Vars    map[string]string // plain-text bindings
	// First deploy creates the Durable Object class; later deploys must not
	// repeat that migration.
	Create bool
}

// Deploy uploads the script. Secrets not passed are kept as they are.
func (c *Client) Deploy(o DeployOptions) error {
	bindings := []Binding{{"type": "durable_object_namespace", "name": "STATE", "class_name": "State"}}
	for k, v := range o.Secrets {
		bindings = append(bindings, Binding{"type": "secret_text", "name": k, "text": v})
	}
	for k, v := range o.Vars {
		bindings = append(bindings, Binding{"type": "plain_text", "name": k, "text": v})
	}
	meta := map[string]any{
		"main_module":        "index.js",
		"compatibility_date": "2025-09-01",
		"bindings":           bindings,
		"keep_bindings":      []string{"secret_text"},
	}
	if o.Create {
		meta["migrations"] = map[string]any{"new_tag": "v1", "new_sqlite_classes": []string{"State"}}
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mj, _ := json.Marshal(meta)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="metadata"`)
	h.Set("Content-Type", "application/json")
	w, _ := mw.CreatePart(h)
	w.Write(mj)
	h = textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="index.js"; filename="index.js"`)
	h.Set("Content-Type", "application/javascript+module")
	w, _ = mw.CreatePart(h)
	io.WriteString(w, o.Script)
	mw.Close()
	return c.do("PUT", fmt.Sprintf("/accounts/%s/workers/scripts/%s", c.AccountID, o.Name), mw.FormDataContentType(), &buf, nil)
}

// Exists reports whether a Worker script with this name already exists.
func (c *Client) Exists(name string) (bool, error) {
	var scripts []struct {
		ID string `json:"id"`
	}
	if err := c.do("GET", fmt.Sprintf("/accounts/%s/workers/scripts", c.AccountID), "", nil, &scripts); err != nil {
		return false, err
	}
	for _, s := range scripts {
		if s.ID == name {
			return true, nil
		}
	}
	return false, nil
}

// EnableWorkersDev turns on the <name>.<subdomain>.workers.dev route and
// returns its URL.
func (c *Client) EnableWorkersDev(name string) (string, error) {
	var sub struct {
		Subdomain string `json:"subdomain"`
	}
	if err := c.do("GET", fmt.Sprintf("/accounts/%s/workers/subdomain", c.AccountID), "", nil, &sub); err != nil {
		return "", err
	}
	if sub.Subdomain == "" {
		return "", errors.New("this account has no workers.dev subdomain yet; open Workers & Pages once in the dashboard to pick one")
	}
	body := strings.NewReader(`{"enabled":true,"previews_enabled":false}`)
	if err := c.do("POST", fmt.Sprintf("/accounts/%s/workers/scripts/%s/subdomain", c.AccountID, name), "application/json", body, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s.%s.workers.dev", name, sub.Subdomain), nil
}
