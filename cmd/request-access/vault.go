package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/asturale/request-access/internal/host"
	"github.com/asturale/request-access/internal/vault"
)

const vaultUnit = `[Unit]
Description=Request Access secrets vault agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s vault agent
Restart=on-failure
RuntimeDirectory=request-access
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/request-access
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`

func cmdVault(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault init|pin|add|list|remove|agent|install|run|get")
	}
	switch args[0] {
	case "run":
		return vaultRun(args[1:])
	case "get":
		fs := flag.NewFlagSet("vault get", flag.ExitOnError)
		reason := fs.String("r", "", "why you need it (shown to the approver)")
		name, rest := splitName(args[1:])
		fs.Parse(rest)
		if name == "" {
			return errors.New("usage: vault get NAME [-r REASON]")
		}
		value, _, err := vault.Ask(name, *reason)
		if err != nil {
			return err
		}
		os.Stdout.Write(value)
		if isTerminal(os.Stdout.Fd()) {
			fmt.Println()
		}
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}
	switch args[0] {
	case "init":
		key, err := vault.Init(printf)
		if err != nil {
			return err
		}
		fmt.Printf("Vault created and pinned.\nFingerprint: %s\n", vault.Fingerprint(key))
		fmt.Println("Check that the page showed the same fingerprint. On other servers:")
		fmt.Printf("  request-access vault pin --fingerprint %s\n", vault.Fingerprint(key))
		return nil
	case "pin":
		fs := flag.NewFlagSet("vault pin", flag.ExitOnError)
		fp := fs.String("fingerprint", "", "the fingerprint shown on a server that already pinned the vault")
		fs.Parse(args[1:])
		key, err := vault.Fetch()
		if err != nil {
			return err
		}
		if *fp == "" {
			return fmt.Errorf("the server's vault key has fingerprint %s; if that matches, run again with --fingerprint", vault.Fingerprint(key))
		}
		if vault.Fingerprint(key) != *fp {
			return fmt.Errorf("fingerprint mismatch: the server offers %s", vault.Fingerprint(key))
		}
		if err := vault.Trust(printf); err != nil {
			return err
		}
		if err := vault.Pin(key); err != nil {
			return err
		}
		fmt.Println("This server is trusted by the vault and has pinned its key.")
		return nil
	case "add":
		fs := flag.NewFlagSet("vault add", flag.ExitOnError)
		users := fs.String("users", "", "who may ask for it: user names and @groups, comma separated")
		env := fs.String("env", "", "variable name for 'vault run' (default SECRET)")
		name, rest := splitName(args[1:])
		fs.Parse(rest)
		if name == "" {
			return errors.New("usage: vault add NAME --users U[,@GROUP] [--env VAR]  (secret on stdin)")
		}
		value, err := readSecret()
		if err != nil {
			return err
		}
		s, err := vault.Add(name, splitList(*users), *env, value)
		if err != nil {
			return err
		}
		fmt.Printf("Stored %q for %s.\n", s.Name, strings.Join(s.Users, ", "))
		return nil
	case "list":
		secrets, err := vault.List()
		if err != nil {
			return err
		}
		if len(secrets) == 0 {
			fmt.Println("No secrets stored. Add one with: vault add NAME --users USER")
		}
		for _, s := range secrets {
			env := s.Env
			if env == "" {
				env = "SECRET"
			}
			fmt.Printf("%-24s $%-20s %s  (added %s)\n", s.Name, env, strings.Join(s.Users, ","), time.Unix(s.Added, 0).Format("2006-01-02"))
		}
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: vault remove NAME")
		}
		if err := vault.Remove(args[1]); err != nil {
			return err
		}
		fmt.Printf("Removed %q.\n", args[1])
		return nil
	case "agent":
		if _, err := vault.PinnedKey(); err != nil {
			return err
		}
		return (&vault.Agent{}).Serve()
	case "install":
		return vaultInstall()
	}
	return fmt.Errorf("unknown vault command %q", args[0])
}

// vaultRun asks for the secret and replaces itself with COMMAND, which gets
// the secret in its environment only.
func vaultRun(args []string) error {
	fs := flag.NewFlagSet("vault run", flag.ExitOnError)
	reason := fs.String("r", "", "why you need it (shown to the approver)")
	envName := fs.String("env", "", "variable to put the secret in (default: the secret's own, else SECRET)")
	name, rest := splitName(args)
	fs.Parse(rest)
	cmd := fs.Args()
	if name == "" || len(cmd) == 0 {
		return errors.New("usage: vault run NAME [-r REASON] [--env VAR] -- COMMAND...")
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		return err
	}
	value, env, err := vault.Ask(name, *reason)
	if err != nil {
		return err
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return errors.New("this secret contains a NUL byte and cannot go in an environment variable; use vault get")
	}
	v := *envName
	if v == "" {
		v = env
	}
	if v == "" {
		v = "SECRET"
	}
	// Drop any inherited value of the variable, so the command sees only ours.
	var environ []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, v+"=") {
			environ = append(environ, kv)
		}
	}
	return syscall.Exec(bin, cmd, append(environ, v+"="+string(value)))
}

func vaultInstall() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := vault.PinnedKey(); err != nil {
		return err
	}
	unit := "/etc/systemd/system/request-access-vault.service"
	if err := host.WriteFileAtomic(unit, []byte(fmt.Sprintf(vaultUnit, self)), 0o644); err != nil {
		return err
	}
	for _, c := range [][]string{{"daemon-reload"}, {"enable", "--now", "request-access-vault.service"}} {
		if out, err := exec.Command("systemctl", c...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(c, " "), err, out)
		}
	}
	fmt.Println("request-access-vault.service installed and started.")
	return nil
}

// splitName takes the leading NAME argument, so flags may follow it.
func splitName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// readSecret reads the secret from stdin: without echo from a terminal, or
// everything from a pipe (one trailing newline dropped).
func readSecret() ([]byte, error) {
	if isTerminal(os.Stdin.Fd()) {
		fmt.Fprint(os.Stderr, "Secret (not shown): ")
		b, err := readNoEcho(os.Stdin.Fd())
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	const max = 16 << 10
	b, err := io.ReadAll(bufio.NewReader(io.LimitReader(os.Stdin, max+3)))
	if err != nil {
		return nil, err
	}
	if len(b) > max+2 { // more than the secret plus a line ending: refuse, never truncate
		return nil, errors.New("the secret must be at most 16 KiB")
	}
	return []byte(strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")), nil
}

// isTerminal and readNoEcho avoid a dependency on golang.org/x/term (Linux
// only, like the rest of the host side).
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return e == 0
}

func readNoEcho(fd uintptr) ([]byte, error) {
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old))); e != 0 {
		return nil, e
	}
	t := old
	t.Lflag &^= syscall.ECHO
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t))); e != 0 {
		return nil, e
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}
