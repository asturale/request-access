# Protocol

All bodies are JSON. Keys are raw Ed25519 keys, encoded base64url without
padding.

## Signed requests

Hosts and admins sign their requests with three headers:

| Header         | Value                                          |
|----------------|------------------------------------------------|
| `RA-Key-Id`    | `host:<name>` or `admin:<index>`               |
| `RA-Timestamp` | Unix seconds; must be within 60 s of the server |
| `RA-Signature` | Ed25519 signature, base64url                   |

The signature covers:

```
"RA1\n" METHOD "\n" PATH_AND_QUERY "\n" TIMESTAMP "\n" base64url(SHA-256(body))
```

State-changing requests also carry a `nonce` (16–64 base64url characters),
remembered for 10 minutes; a reused nonce is rejected with 409.

## Endpoints

| Method | Path                       | Auth   | Purpose |
|--------|----------------------------|--------|---------|
| GET    | `/v1/info`                 | none   | `{name, version, worker_key}` |
| POST   | `/v1/enroll`               | none   | `{name, key, nonce}` → `{id, fingerprint, expires}`; approved on Telegram |
| GET    | `/v1/enroll/<id>?wait=N`   | none   | `{status}`: `pending`, `approved`, `denied`, `expired` |
| POST   | `/v1/access`               | host   | `{service, user, rhost?, tty?, detail?, nonce}` → `{id, expires, window}` |
| GET    | `/v1/access/<id>?wait=N`   | host   | `{status, grant?}`; only the requesting host can read it |
| GET    | `/v1/admin/state`          | admin  | `{version, config, hosts}` |
| POST   | `/v1/admin/actions`        | admin  | `{action: "set_config", config, nonce}` or `{action: "remove_host", name, nonce}` → `{id}` |
| GET    | `/v1/admin/actions/<id>`   | admin  | `{status}` |
| POST   | `/telegram/webhook`        | secret | Telegram updates (`X-Telegram-Bot-Api-Secret-Token`) |

`wait` long-polls for up to 25 seconds.

Enrollment is unauthenticated because a new host has no registered key yet;
it is limited to three pending enrollments and always needs approval, with
the key fingerprint shown on both sides.

## Grants

An approved access request returns:

```json
{"payload": "<base64url JSON>", "sig": "<base64url Ed25519 over the payload bytes>"}
```

with payload

```json
{"v":1,"kind":"grant","id":"…","host":"web1","service":"ssh","user":"alice",
 "nonce":"<the request's nonce>","once":false,"iat":1700000000,"exp":1700000900}
```

A host accepts a fresh grant only if the signature verifies with the
server key it pinned at enrollment, and `id`, `nonce`, `host`, `service` and
`user` match its request. It may cache the grant (unless `once`) and reuse
it for the same service and user until `exp`.

## Configuration

```json
{"lang":"en","request_timeout":60,"default_window":900,"max_window":86400,
 "windows":{"ssh":900,"sudo":900,"web1/sudo":300}}
```

Window lookup: `<host>/<service>`, then `<service>`, then `default_window`;
always capped at `max_window`.

`routes` (optional) maps `<host>`, `user:<user>` or `<host>/user:<user>` to
`{"chat": "<chat id>", "approvers": ["<user id>", …], "required": N}`.
An access request uses the most specific match, else the default approver;
only that route's approvers can decide it, and it is approved once
`required` distinct approvers tapped Allow (any Deny denies).
