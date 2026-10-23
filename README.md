<p align="center"><img src="docs/logo.jpg" width="120" alt=""></p>

# Request Access

Push-based approval for SSH logins and `sudo`. When someone (or something)
logs in or runs `sudo` on a protected server, you get a Telegram message with
**Allow** / **Just this once** / **Deny** buttons. Nothing happens until you
tap. One approval stays valid for a configurable window (say 15 minutes), so
a burst of commands needs one tap, not twenty.

```
🔐 sudo on web1
User: deploy
From: 10.0.0.5
sudo systemctl restart nginx

[✅ Allow 15 min] [☑️ Just this once]
[❌ Deny]
```

It is meant as a second factor for machines that have to keep standing
access to each other (automation, backups, monitoring, an AI agent with a
shell): if one of them is compromised, its keys alone are no longer enough.

## How it works

```
 server (PAM)  ──signed request──▶  Cloudflare Worker  ──message──▶  Telegram
      ▲                                  │   ▲                          │
      └────────── signed grant ──────────┘   └──────── your tap ────────┘
```

- **The Worker is the only party that can approve.** It signs every grant
  with an Ed25519 key that never leaves the Worker. Servers only hold the
  public key, so a compromised server cannot forge an approval for itself or
  for any other server.
- **Each server has its own key** and signs its requests. Requests carry a
  timestamp and a single-use nonce; a grant is bound to that nonce, the
  server, the service and the user.
- **One bot for everything.** Taps arrive at the Worker through a Telegram
  webhook protected by a secret token, and only the configured Telegram user
  can approve.
- **Grants are cached locally** (root-only, signature checked on every use)
  until they expire, which is what makes the time window work for both SSH
  and `sudo`.
- **It fails closed.** No answer, a network error or a bad signature means no
  access.
- **Configuration changes are approved on Telegram too.** The admin key
  alone cannot widen windows, swap a host's key or remove a host.

The Worker keeps its state in a Durable Object (strongly consistent; KV
could serve a stale answer for up to a minute). Everything fits in
Cloudflare's free plan.

## What it protects against, and what not

It protects against someone who gets hold of an SSH key or a user account on
one of your machines and tries to log in elsewhere or become root. It does
**not** protect a machine where the attacker is already root: root can
remove the PAM rule. It also only covers what goes through PAM; a service
that is exploited directly is out of scope.

PAM runs the check in the *account* phase, which runs for every SSH login
(also public-key logins) and every `sudo` call (also `NOPASSWD` rules).

## Setup

You need:

- a Cloudflare account with a `workers.dev` subdomain (open *Workers &
  Pages* once in the dashboard to pick one), and an API token with
  **Account → Workers Scripts → Edit**;
- a Telegram bot from [@BotFather](https://t.me/BotFather) — open it and
  press **Start**, so it is allowed to message you;
- your numeric Telegram user id (ask [@userinfobot](https://t.me/userinfobot)).

Build or download the binary (static, Linux amd64/arm64):

```sh
make build            # or: make dist
```

### 1. Deploy the Worker (once, on your own machine)

```sh
request-access setup --cf-token <TOKEN> --bot-token <BOT_TOKEN> --approver <YOUR_TELEGRAM_ID> [--lang nl]
```

This uploads the Worker with its Durable Object and secrets, enables its
`workers.dev` URL, points the bot's webhook at it, and saves an admin key to
`~/.config/request-access/admin.json`. It prints the command to enroll
servers. After upgrading the binary, `request-access setup --update
--cf-token <TOKEN>` redeploys the script and keeps all keys.

### 2. Add a server

Copy the binary to `/usr/local/sbin/request-access` (root-owned, not
writable by others), then as root (use the full path with `sudo`; some
distributions leave `/usr/local/sbin` out of sudo's `secure_path`):

```sh
request-access enroll --url https://request-access.<you>.workers.dev --server-key <KEY> --name web1
```

Compare the fingerprint it prints with the one in the Telegram message and
tap **Add server**. Then choose what to protect:

```sh
request-access install --ssh --sudo [--exempt backup]
```

Keep a root shell open and test from a second terminal before you log out.
`request-access uninstall` removes the PAM rules again; the original PAM
files are kept as `*.request-access.bak`.

### SELinux

On SELinux systems (Fedora, RHEL and derivatives) the SSH daemon may neither
open outgoing connections nor write under `/var/lib`, so an SSH check fails
closed (`connect: permission denied`) or every login asks again. Load the
module in [`selinux/request-access.te`](selinux/request-access.te); its
header has the four commands. It lets `sshd` connect to web ports and write
only to the grant cache, which gets its own file type.

### Exempting automation

`sudo` started by root (a root shell or a root cron job) never needs
approval: root already has every right `sudo` could grant. Root SSH logins
do. Users listed with `--exempt` never need approval either; use
`--exempt ssh:deploy` to limit that to one service. Passing `--exempt`
replaces the current list. Use this for a dedicated
account whose SSH key is already restricted to one command
(`restrict,command="..."` in `authorized_keys`), not for anything with a
shell.

## Day to day

```sh
request-access config                          # show settings
request-access config window.ssh=30m window.sudo=10m
request-access config window.web1/sudo=5m      # per server
request-access config window.web1/sudo=default # remove an override
request-access config request_timeout=90 max_window=1d lang=en
request-access hosts                           # enrolled servers
request-access hosts remove web1
```

Every change shows up on Telegram and only applies after you confirm it.

### Who approves what

By default every request goes to the approver chosen at setup. Routes send
some requests elsewhere, or require more than one approver:

```sh
request-access route set web1 --approvers 111111111            # this server: someone else
request-access route set user:deploy --approvers 111,222 --chat -100123456 --required 2
request-access route set web1/user:root --approvers 333 --required 1
request-access route                                            # list
request-access route remove web1
```

The most specific route wins (`HOST/user:USER`, then `user:USER`, then
`HOST`). With several approvers, pass a group chat that contains them and
the bot; each approver taps once, and any "Just this once" makes the grant a
one-off. Approvers must have started the bot (or be in the group) so it can
reach them. Enrolling servers and configuration changes always go to the
default approver.

On a server:

```sh
request-access status    # PAM services, exempt users, cached grants
request-access revoke    # forget cached grants (all, or --service/--user)
```

Each decision is logged to syslog (`authpriv`, tag `request-access`).

## Break-glass

If Telegram or Cloudflare is unreachable, protected logins and `sudo` are
refused. Keep a way in that does not go through the protected PAM services:
your provider's web console (a local `login` is not affected), or a root
shell you keep open while making changes.

## Development

```sh
make test   # Go vet + tests
make e2e    # Worker tests and end-to-end tests in Miniflare (Node 20+, glibc)
```

The wire protocol is described in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## License

MIT
