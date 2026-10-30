# Secrets vault

Keep API tokens and passwords on a server without the server being able to
read them: not the user who needs one, not a process running as that user,
not even root. Each use needs the approver's vault password, entered on a
page that opens from Telegram, and the secret goes only to that one request.

```sh
request-access vault run cloudflare -r "update DNS" -- ./update-dns.sh   # gets $CF_TOKEN
request-access vault get github -r "push release" | gh auth login --with-token
```

## How it works

```
 user ──socket──▶ vault agent (root) ──request──▶ Worker ──link──▶ Telegram
   ▲                    │   ▲                        │  ▲               │
   │                    │   └── sealed secret ───────┘  └── sealed ── vault page
   └──── the secret ────┘                                  (vault password)
```

- **The vault key.** `vault init` asks you to create the vault: the page
  generates a P-256 key pair in your browser and encrypts the private key,
  together with the list of **trusted servers** (their Ed25519 host keys),
  with your vault password (PBKDF2-SHA256, 600 000 rounds, AES-256-GCM).
  The Worker stores the public key and that *locked* blob; the server pins
  the public key. Nobody but the page ever holds the private key in the
  clear, and only while it is open. `vault pin` on another server adds it to
  the trusted servers, which again needs the vault password.
- **Storing a secret.** `vault add` encrypts the secret to the pinned public
  key (ECIES: ephemeral P-256 ECDH, HKDF-SHA256, AES-256-GCM, bound to the
  server's and the secret's name) and writes it to
  `/etc/request-access/vault/NAME.json`, together with who may ask for it and
  a commitment: SHA-256 over a random 32-byte salt and the secret, where the
  salt is sealed inside the box. No password is needed to add a secret, and
  the file is useless without the vault password.
- **Using a secret.** `vault run` / `vault get` ask the local agent (a root
  service on a Unix socket). The agent checks the caller's real user id
  against the secret's list, creates a key pair for this request only and
  sends the sealed secret plus that fresh public key to the Worker, signed
  with the server's host key. You get a Telegram message with the secret's
  name, the user, the reason and the command line. On the page, your
  password manager fills in the vault password; the page unlocks the vault
  key, checks the request's signature against the trusted servers inside it
  (so the Worker cannot change the receiving key or what you are shown),
  opens that one secret and seals it to the request's fresh key. The Worker
  hands the sealed result to the agent once and forgets it; the agent opens
  it, checks it against the commitment (so nobody without the vault
  password can slip in another value) and passes the secret to the caller,
  which puts it in the command's environment.

## Setup

On each server (as root, after `enroll`):

```sh
request-access vault init         # first server: create the vault (link on Telegram)
request-access vault pin --fingerprint SHA256:...   # other servers: pin the same vault
request-access vault install      # install and start request-access-vault.service
```

On the page, let your password manager generate a long password (at least
16 characters; more is better) and save it for the Worker's address. The
page fills in a fixed user name, `secrets-vault`, so the password manager
offers it again on the release page.

**Keep a copy of the password somewhere safe.** Without it, the vault key
cannot be unlocked and every stored secret is lost. There is no recovery.

Then add secrets (the value is read from stdin, without echo on a terminal):

```sh
request-access vault add cloudflare --users alice,@deploy --env CF_TOKEN
request-access vault list
request-access vault remove cloudflare
```

## Threat model

What it protects:

- **Secrets at rest**, against anyone on the server, root included: the
  files hold only ciphertext, and the key to open them exists only on the
  page, unlocked by a password that is never sent anywhere.
- **Use without you knowing**: every release needs your password on the
  page, for that request; there is no cache and no time window.
- **The Worker** cannot read a secret, redirect a release to itself, or
  substitute a value: it only sees sealed data, the request is signed by a
  server the vault trusts, and the result must match the commitment.
- **One server's secret** cannot be released as another's: boxes are bound
  to the server's name.

What it does not protect:

- **The page comes from the Worker.** Whoever can replace the Worker script
  can serve a page that captures the vault password, and with it every
  secret. Keep every credential that can deploy to the Worker (a Cloudflare
  token with *Workers Scripts: Edit*, including the one `setup --update`
  uses) off your servers, or in the vault itself. Protect your Cloudflare
  account with a passkey or security key.
- **A released secret** goes to the requesting process. Root on that server
  at that moment, or another process of the same user, can read it from the
  process's memory or environment. The vault limits *when* and *how often* a
  secret is exposed, not what happens to it after you release it.
- **The command line in the message** is supplied by the caller and is only
  informative; the user name is checked by the agent.
- **Adding a server is trust on first use**: the setup and trust pages show
  the server's key fingerprint; compare it with what `vault init` or
  `vault pin` printed.
- **Unattended jobs** cannot use the vault: someone has to type the
  password. Give those their own narrowly scoped credentials.

## Protocol

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/v1/vault/init` | host | `{nonce}` → `{id, expires}`; setup link on Telegram |
| POST | `/v1/vault/trust` | host | `{nonce}` → `{id, expires}`; link to trust this host |
| GET | `/v1/vault/init/<id>?wait=N`, `/v1/vault/trust/<id>?wait=N` | host | `{status, key?}` |
| GET | `/v1/vault/key` | host | `{key, fingerprint}`, for `vault pin` |
| POST | `/v1/vault/request` | host | `{name, user, reason, detail, box, reply_key, vault_key, nonce, sig}` → `{id, expires}` |
| GET | `/v1/vault/request/<id>?wait=N` | host | `{status, sealed?}`; `sealed` is delivered once |
| GET | `/vault/(setup\|trust\|release)/<id>` | none | the vault page |
| GET | `/v1/vault/page/(setup\|trust\|release)/<id>` | none | data for the page |
| POST | `/v1/vault/page/setup/<id>` | none | `{key, locked, auth: {salt, hash}}` |
| POST | `/v1/vault/page/trust/<id>` | none | `{locked, proof, base}`; `base` is the `iv` of the lock it was made from, refused if the lock changed meanwhile; earlier locks are kept |
| POST | `/v1/vault/page/release/<id>` | none | `{sealed, proof}` |

A box is `{v: 1, epk, iv, ct}` (base64url): `epk` is an ephemeral P-256
public key; the AES-256-GCM key is HKDF-SHA256 over the ECDH secret with salt
`epk || recipient public key` and info `secrets-vault v1`. Authenticated
data: `secrets-vault secret v1\n<host>\n<name>` for a stored secret (whose
plaintext is a 32-byte salt followed by the secret) and
`secrets-vault release v1\n<nonce>\n<name>` for a released one.

The request signature (Ed25519, host key) covers length-prefixed lines
(`<byte length>:<value>\n`) of `secrets-vault request v1`, host, user,
name, reason, detail, reply key, nonce and base64url(SHA-256(`epk.iv.ct`)).

The locked vault key is `{kdf: "pbkdf2-sha256", iter, salt, iv, ct}`: AES-256-GCM
over the JSON `{"key": <PKCS#8 private key>, "hosts": {<name>: <Ed25519 key>}}`,
with authenticated data `secrets-vault key v1\n<vault public key>`.

Releasing a secret and changing the lock (trusting another server) need
proof of the vault password: at setup the page derives a second PBKDF2 value from it with its
own salt and the Worker keeps only its SHA-256 (`auth`); a trust post must
include that value (`proof`). A leaked link therefore cannot close a
request or overwrite the vault key, and the last 20 locks are kept in any
case. The page data carries the locked key only while a request is open.
