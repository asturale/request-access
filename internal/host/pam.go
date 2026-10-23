package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	markBegin = "# BEGIN request-access (managed, remove with: request-access uninstall)"
	markEnd   = "# END request-access"
)

var PAMDir = "/etc/pam.d"

// PAMLine is the rule added to a PAM service file. It runs in the account
// phase, which PAM runs for every login and sudo call -- also for SSH
// public-key logins and for NOPASSWD sudo rules, where the auth phase is
// skipped. "requisite" stops the stack immediately on a "no".
func PAMLine(binary string) string {
	return fmt.Sprintf("account requisite pam_exec.so quiet stdout seteuid %s pam", binary)
}

// InstallPAM adds the rule to the given PAM service files ("sshd", "sudo"),
// placed before the first account rule. A backup is kept next to each file.
func InstallPAM(services []string, binary string) error {
	for _, svc := range services {
		path := filepath.Join(PAMDir, svc)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if strings.Contains(text, markBegin) {
			text = removeBlock(text)
		}
		block := markBegin + "\n" + PAMLine(binary) + "\n" + markEnd + "\n"
		lines := strings.SplitAfter(text, "\n")
		idx := -1
		for i, l := range lines {
			f := strings.Fields(l)
			if len(f) > 0 && (f[0] == "account" || (f[0] == "@include" && len(f) > 1 && strings.Contains(f[1], "account"))) {
				idx = i
				break
			}
		}
		var out string
		if idx < 0 {
			out = text + block
		} else {
			out = strings.Join(lines[:idx], "") + block + strings.Join(lines[idx:], "")
		}
		if _, err := os.Stat(path + ".request-access.bak"); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(path+".request-access.bak", data, 0o644); err != nil {
				return err
			}
		}
		if err := writeFileAtomic(path, []byte(out), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// UninstallPAM removes the managed block from the given service files.
func UninstallPAM(services []string) error {
	for _, svc := range services {
		path := filepath.Join(PAMDir, svc)
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if !strings.Contains(string(data), markBegin) {
			continue
		}
		if err := writeFileAtomic(path, []byte(removeBlock(string(data))), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// InstalledServices lists the PAM services that currently carry the rule.
func InstalledServices() []string {
	var out []string
	for _, svc := range []string{"sshd", "sudo", "sudo-i"} {
		if data, err := os.ReadFile(filepath.Join(PAMDir, svc)); err == nil && strings.Contains(string(data), markBegin) {
			out = append(out, svc)
		}
	}
	return out
}

func removeBlock(text string) string {
	start := strings.Index(text, markBegin)
	end := strings.Index(text, markEnd)
	if start < 0 || end < start {
		return text
	}
	end += len(markEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return text[:start] + text[end:]
}
