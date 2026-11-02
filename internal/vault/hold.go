package vault

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A hold lets the agent keep a released secret in memory for a while, so
// the same user in the same session can use it again without another
// approval. The host asks for it (vault run/get --hold), within limits root
// sets in the host config; the terms are signed with the request and shown
// on the page, and only the approver can agree to them: the page then seals
// the secret with HeldReleaseAAD instead of ReleaseAAD, which the Worker
// cannot forge. Every reuse is reported to the approver, who can revoke it.
//
// A hold never touches the disk and ends when the agent stops.

// heldSecret is one secret the agent holds.
type heldSecret struct {
	value    []byte
	env      string
	request  string // the Worker's request id: reuse is reported under it
	idle     time.Duration
	until    time.Time // the hold ends here, however often it is used
	lastUsed time.Time
}

func (h *heldSecret) live(now time.Time) bool {
	return now.Before(h.until) && now.Sub(h.lastUsed) < h.idle
}

// holdKey says who a hold is for: the user, the secret (as stored, so a
// replaced secret is not served from an old hold) and the caller's session.
type holdKey struct {
	uid    uint32
	name   string
	commit string
	scope  string
}

type holds struct {
	mu sync.Mutex
	m  map[holdKey]*heldSecret
}

// get returns a copy of a live held secret and marks it used.
func (hs *holds) get(k holdKey, now time.Time) (value []byte, env, request string, ok bool) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	h := hs.m[k]
	if h == nil {
		return nil, "", "", false
	}
	if !h.live(now) {
		hs.dropLocked(k)
		return nil, "", "", false
	}
	h.lastUsed = now
	return append([]byte{}, h.value...), h.env, h.request, true
}

func (hs *holds) put(k holdKey, h *heldSecret) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.m == nil {
		hs.m = map[holdKey]*heldSecret{}
	}
	hs.dropLocked(k)
	hs.m[k] = h
}

func (hs *holds) drop(k holdKey) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.dropLocked(k)
}

// forget drops every hold of a user, or only those of one secret.
func (hs *holds) forget(uid uint32, name string) int {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	n := 0
	for k := range hs.m {
		if k.uid == uid && (name == "" || k.name == name) {
			hs.dropLocked(k)
			n++
		}
	}
	return n
}

func (hs *holds) dropLocked(k holdKey) {
	if h := hs.m[k]; h != nil {
		clear(h.value)
		delete(hs.m, k)
	}
}

// sweep drops the holds that ended.
func (hs *holds) sweep(now time.Time) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	for k, h := range hs.m {
		if !h.live(now) {
			hs.dropLocked(k)
		}
	}
}

// holdTerms turns what the caller asked for into the terms to request:
// the idle time capped by the host's limit, and the host's total limit.
// No terms ("") when the caller asked for none, or the host allows none.
func holdTerms(asked, maxHold, maxLease int64) (idle, total int64, terms string) {
	if asked <= 0 || maxHold <= 0 {
		return 0, 0, ""
	}
	idle = min(asked, maxHold)
	total = max(maxLease, idle)
	return idle, total, HoldTerms(idle, total)
}

// sessionScope identifies the caller's session for a hold: the process that
// started the caller's session (for an SSH login its sshd, for a tool that
// runs each command in a new session, such as an agent, the tool itself),
// with its start time so a reused pid does not match. Commands started from
// the same shell, or by the same tool, share it; another login does not.
// "" when it cannot be told, and then nothing is held.
//
// This keeps a hold from leaking to other logins and tools of the same
// user; it is no boundary against code that already runs as that user,
// which can read the secret from the process it was given to anyway (see
// docs/VAULT.md). Per-login ids do not fit: services and agents all share
// one audit session, and a tool that starts each command in a new session
// has a new leader every time.
func sessionScope(pid int32) string {
	st, err := procStat(int(pid))
	if err != nil || st.session <= 1 {
		return ""
	}
	leader, err := procStat(st.session)
	if err != nil || leader.ppid <= 1 {
		return ""
	}
	parent, err := procStat(leader.ppid)
	// A service manager (init, systemd --user) adopts every daemonized
	// session of the user: far too wide a scope.
	if err != nil || parent.comm == "systemd" || parent.comm == "init" {
		return ""
	}
	return fmt.Sprintf("%d@%d", leader.ppid, parent.start)
}

type stat struct {
	comm          string
	ppid, session int
	start         uint64
}

// procStat reads the fields we need from /proc/PID/stat; the command name
// (field 2) may contain spaces and parentheses, so parse after the last ")".
func procStat(pid int) (stat, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return stat{}, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	j := strings.IndexByte(s, '(')
	if i < 0 || j < 0 || j > i {
		return stat{}, fmt.Errorf("bad stat for %d", pid)
	}
	f := strings.Fields(s[i+1:]) // f[0] is field 3 (state)
	if len(f) < 20 {
		return stat{}, fmt.Errorf("bad stat for %d", pid)
	}
	ppid, err1 := strconv.Atoi(f[1])                // field 4
	session, err2 := strconv.Atoi(f[3])             // field 6
	start, err3 := strconv.ParseUint(f[19], 10, 64) // field 22
	if err1 != nil || err2 != nil || err3 != nil {
		return stat{}, fmt.Errorf("bad stat for %d", pid)
	}
	return stat{comm: s[j+1 : i], ppid: ppid, session: session, start: start}, nil
}
