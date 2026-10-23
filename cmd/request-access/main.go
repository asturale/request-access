// Command request-access: push-based approval (via Telegram) for SSH logins
// and sudo, backed by a small Cloudflare Worker.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/asturale/request-access/internal/admin"
	"github.com/asturale/request-access/internal/host"
)

var version = "dev"

const usage = `request-access -- approve SSH logins and sudo with a tap on Telegram

Admin (on your own machine):
  setup     --cf-token T --bot-token B --approver ID [--name request-access] [--lang en|nl] [--account-id A]
  setup     --update --cf-token T        redeploy the worker script (after an upgrade)
  setup     --replace ...                set up again over an existing worker (new keys)
  config                                 show server settings
  config    key=value ...                change settings (confirmed on Telegram), e.g.
                                         window.ssh=15m window.sudo=30m window.web1/sudo=5m
                                         request_timeout=60 default_window=15m max_window=1d lang=nl
  hosts                                  list enrolled servers
  hosts     remove NAME                  remove a server (confirmed on Telegram)

Server (as root):
  enroll    --url URL --name NAME [--server-key KEY]   register this server (confirmed on Telegram)
  install   [--ssh] [--sudo] [--exempt USER ...]       add the PAM rules
  uninstall                              remove the PAM rules
  status                                 show configuration and cached grants
  revoke    [--service S] [--user U]     forget cached grants
  pam                                    (called by pam_exec)

  version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "pam":
		os.Exit(runPAM())
	case "setup":
		err = cmdSetup(args)
	case "config":
		err = cmdConfig(args)
	case "hosts":
		err = cmdHosts(args)
	case "enroll":
		err = cmdEnroll(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = host.UninstallPAM([]string{"sshd", "sudo", "sudo-i"})
		if err == nil {
			fmt.Println("PAM rules removed.")
		}
	case "status":
		err = cmdStatus()
	case "revoke":
		err = cmdRevoke(args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printf(format string, a ...any) { fmt.Printf(format, a...) }

// runPAM is the pam_exec entry point. Exit 0 allows, anything else denies.
func runPAM() int {
	if os.Getenv("PAM_TYPE") != "account" {
		return 0 // only the account phase is managed
	}
	r := host.Request{
		PAMService: os.Getenv("PAM_SERVICE"),
		User:       os.Getenv("PAM_USER"),
		RHost:      os.Getenv("PAM_RHOST"),
		TTY:        os.Getenv("PAM_TTY"),
	}
	if r.PAMService == "sudo" || r.PAMService == "sudo-i" {
		r.Detail = parentCommand()
		if ru := os.Getenv("PAM_RUSER"); ru != "" {
			// For sudo, PAM_USER is the target (usually root); the person
			// asking is PAM_RUSER.
			r.User = ru
		}
	}
	d := host.Check(r, func(s string) { fmt.Println(s) })
	logger, _ := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "request-access")
	msg := fmt.Sprintf("service=%s user=%s rhost=%s allowed=%t reason=%q", r.PAMService, r.User, r.RHost, d.Allowed, d.Reason)
	if logger != nil {
		logger.Info(msg)
		logger.Close()
	}
	if !d.Allowed {
		fmt.Println("Request Access: not approved (" + d.Reason + ")")
		return 1
	}
	return 0
}

// parentCommand returns the command line of the process that invoked PAM
// (for sudo: "sudo apt upgrade"), shown in the approval message.
func parentCommand() string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", os.Getppid()))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	token := fs.String("cf-token", os.Getenv("CLOUDFLARE_API_TOKEN"), "Cloudflare API token (Workers Scripts: Edit)")
	account := fs.String("account-id", os.Getenv("CLOUDFLARE_ACCOUNT_ID"), "Cloudflare account id (optional if the token sees one account)")
	name := fs.String("name", "request-access", "worker name")
	bot := fs.String("bot-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token from @BotFather")
	approver := fs.String("approver", os.Getenv("TELEGRAM_APPROVER_ID"), "your numeric Telegram user id")
	lang := fs.String("lang", "en", "message language: en or nl")
	update := fs.Bool("update", false, "redeploy the worker script only")
	replace := fs.Bool("replace", false, "set up again over an existing worker (new keys; servers must re-enroll)")
	fs.Parse(args)
	if *token == "" {
		return fmt.Errorf("--cf-token (or CLOUDFLARE_API_TOKEN) is required")
	}
	n := *name
	if *update && !flagSet(fs, "name") {
		n = ""
	}
	return admin.Setup(admin.SetupOptions{
		CFToken: *token, AccountID: *account, WorkerName: n, BotToken: *bot,
		ApproverID: *approver, Lang: *lang, Update: *update, Replace: *replace, Out: printf,
	})
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func cmdConfig(args []string) error {
	st, err := admin.GetState()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		out, _ := json.MarshalIndent(st.Config, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	changes, err := admin.ParseSettings(args, st.Config)
	if err != nil {
		return err
	}
	return admin.SetConfig(changes, printf)
}

func cmdHosts(args []string) error {
	if len(args) == 2 && args[0] == "remove" {
		return admin.RemoveHost(args[1], printf)
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: hosts [remove NAME]")
	}
	st, err := admin.GetState()
	if err != nil {
		return err
	}
	sort.Slice(st.Hosts, func(i, j int) bool { return st.Hosts[i].Name < st.Hosts[j].Name })
	for _, h := range st.Hosts {
		fmt.Printf("%-24s %s  added %s\n", h.Name, h.Fingerprint, time.Unix(h.Added, 0).Format("2006-01-02"))
	}
	return nil
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	url := fs.String("url", "", "server URL")
	name := fs.String("name", "", "name for this server (default: hostname)")
	key := fs.String("server-key", "", "expected server key (printed by setup)")
	fs.Parse(args)
	if *url == "" {
		return fmt.Errorf("--url is required")
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	if err := requireRoot(); err != nil {
		return err
	}
	return host.Enroll(host.EnrollOptions{URL: *url, Name: *name, ServerKey: *key, Out: printf})
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	ssh := fs.Bool("ssh", false, "require approval for SSH logins")
	sudo := fs.Bool("sudo", false, "require approval for sudo")
	var exempt multi
	fs.Var(&exempt, "exempt", "user that never needs approval (repeatable)")
	fs.Parse(args)
	if !*ssh && !*sudo {
		return fmt.Errorf("pass --ssh and/or --sudo")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, _, _, err := host.LoadConfig()
	if err != nil {
		return fmt.Errorf("enroll first: %w", err)
	}
	for _, u := range exempt {
		if !contains(cfg.ExemptUsers, u) {
			cfg.ExemptUsers = append(cfg.ExemptUsers, u)
		}
	}
	if err := host.SaveConfig(cfg); err != nil {
		return err
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	bin, _ = filepath.EvalSymlinks(bin)
	if st, err := os.Stat(bin); err != nil || st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group/world writable", bin)
	}
	var svcs []string
	if *ssh {
		svcs = append(svcs, "sshd")
	}
	if *sudo {
		svcs = append(svcs, "sudo")
		if _, err := os.Stat(filepath.Join(host.PAMDir, "sudo-i")); err == nil {
			svcs = append(svcs, "sudo-i")
		}
	}
	// Created here, as root, so the PAM check never has to create it (on
	// SELinux systems sshd may not create directories under /var/lib).
	if err := os.MkdirAll(filepath.Join(host.StateDir, "grants"), 0o700); err != nil {
		return err
	}
	if err := host.InstallPAM(svcs, bin); err != nil {
		return err
	}
	fmt.Printf("Installed for: %s\n", strings.Join(svcs, ", "))
	fmt.Println("Keep this root shell open and test from a second terminal before logging out.")
	return nil
}

func cmdStatus() error {
	cfg, _, _, err := host.LoadConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Server:    %s\nHost name: %s\nPAM:       %s\n", cfg.URL, cfg.Name, strings.Join(host.InstalledServices(), ", "))
	if len(cfg.ExemptUsers) > 0 {
		fmt.Printf("Exempt:    %s\n", strings.Join(cfg.ExemptUsers, ", "))
	}
	grants, err := host.ListGrants()
	if err != nil {
		return err
	}
	for _, g := range grants {
		state := "expired"
		if g.Valid {
			state = "valid for " + time.Until(g.Expires).Round(time.Second).String()
		}
		fmt.Printf("Grant:     %s %s (%s)\n", g.Service, g.User, state)
	}
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	svc := fs.String("service", "", "only this service")
	user := fs.String("user", "", "only this user")
	fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	n, err := host.Revoke(*svc, *user)
	fmt.Printf("Removed %d cached grant(s).\n", n)
	return err
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this as root")
	}
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
