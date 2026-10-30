# Passkey approval

Without passkeys, a server accepts any grant signed by the Worker. That
makes the Worker the thing to attack: anyone who can deploy a different
script under its name (a Cloudflare API token with *Workers Scripts: Edit*
on that account is enough) can approve every login and every `sudo`. If
such a token is stored on one of the servers you protect, a break-in there
undoes the protection on all of them.

With passkeys pinned on a server, an approval also has to carry a passkey
signature, which the **server** checks against public keys in its own
root-owned configuration. The Worker never sees a private key, so it can
relay a signature but cannot make one.

## How it works

```
 server (PAM)  ──request + 2 challenges──▶  Worker  ──link──▶  Telegram
      ▲                                       │  ▲                  │
      │                                       │  └── signature ── approve page
      └──── grant + passkey signature ────────┘          (Face ID on your phone)
```

1. For each access request the server picks a fresh nonce and computes two
   challenges: SHA-256 over its own name, the service, the user, the nonce
   and the choice (`window` or `once`).
2. The Telegram message gets a **🔑 Approve with passkey** link. The page
   shows the request and asks your phone to sign the challenge for the
   button you press (WebAuthn, user verification required).
3. The Worker passes the signature (`clientDataJSON`, `authenticatorData`,
   signature) to the server along with its usual grant.
4. The server checks: a pinned credential, its own challenge (so the
   signature cannot be reused for another request, server, user or choice),
   the site (`rp_id`) and origin, the user-verified flag, and the signature.
   "Just this once" is part of what was signed. How long an approval is
   cached is the server's own setting (`passkey.window`, default 15 min),
   not the Worker's.

**Deny** stays an ordinary Telegram button: refusing needs no proof.

## Setup

On each server, as root:

```sh
request-access passkey add --label phone
```

Open the link on Telegram on your phone, tap **Create passkey** and confirm.
The phone shows a fingerprint, and so does the server; they must match. The
server prints a line to pin the same passkey on other servers without
registering again:

```sh
request-access passkey add --import ra-passkey:...
```

Register a second passkey as a spare (another phone, a password manager that
syncs passkeys, or a security key), so losing one device does not lock you
out.

At first a passkey **or** a Telegram tap approves (the message has both).
Once a passkey approval has worked:

```sh
request-access passkey require on
```

From then on the message has only the passkey link and **Deny**; taps on an
old message are refused, and cached grants that were not approved with a
passkey stop counting.

```sh
request-access passkey               # list, with fingerprints
request-access passkey export        # lines to copy to other servers
request-access passkey remove phone
request-access passkey require off
```

## Limits

- **Registration is trust on first use.** There is no attestation, so
  register while you trust the Worker (and the server), and compare the
  fingerprints. Copying with `--import` avoids registering on every server.
- **The page comes from the Worker.** A replaced Worker cannot approve on
  its own, but it can show a misleading page: if you are about to approve
  something of your own, it could present its own request instead. Only
  approve right after you started something yourself, and check the details
  on the page.
- **Passkeys are bound to the Worker's host name.** Moving the Worker to
  another URL means registering new passkeys.
- **One signature approves.** Routes that require several approvers still
  decide where the message goes, but a passkey request is approved by one
  signature from any passkey pinned on that server.
- **Browsers inside apps.** Open the link in the system browser or Telegram's
  in-app Safari/Chrome tab; embedded web views often cannot use passkeys.
- It does not change what root on a server can do: root can edit the
  configuration or remove the PAM rule.
