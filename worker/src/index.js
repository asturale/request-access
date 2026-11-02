// Request Access -- Cloudflare Worker.
//
// The Worker is the only party that can approve anything: it receives access
// requests from enrolled hosts, asks the approver on Telegram, and returns a
// grant signed with a key that never leaves the Worker. Hosts only hold the
// matching public key, so a compromised host cannot mint its own approvals.
//
// Hosts can additionally pin passkeys (see docs/PASSKEYS.md). Their requests
// are approved on a page where the approver signs the host's challenge with
// the passkey; the Worker only relays that signature and the host verifies
// it, so even a replaced Worker cannot approve anything for such a host.
//
// All state lives in a single Durable Object (strongly consistent, unlike KV,
// whose cross-location reads can lag by up to a minute).

const VERSION = '0.4.1';
const MAX_SKEW = 60; // seconds between a signed request's timestamp and now
const NONCE_TTL = 600; // seconds a request nonce is remembered (replay protection)
const MAX_PENDING_ENROLLMENTS = 3;
const VAULT_TIMEOUT = 300; // seconds a vault request stays open (unlocking a password manager takes a moment)
const MAX_PENDING_VAULT = 10; // open vault requests per host

const DEFAULT_CONFIG = {
  lang: 'en',
  request_timeout: 60, // seconds an approval request stays open
  windows: { ssh: 900, sudo: 900 }, // seconds a grant stays valid, per service or "host/service"
  default_window: 900,
  max_window: 86400,
  // Who approves what. Keys: "<host>", "user:<user>" or "<host>/user:<user>"
  // (most specific wins). Values: { chat, approvers: [telegram user ids],
  // required }. Anything without a route goes to the default approver set
  // at setup (TELEGRAM_CHAT_ID / APPROVER_IDS), one tap needed.
  routes: {},
};

export default {
  async fetch(request, env) {
    const stub = env.STATE.get(env.STATE.idFromName('main'));
    return stub.fetch(request);
  },
};

export class State {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.storage = ctx.storage;
    this.env = env;
  }

  async fetch(request) {
    try {
      return await this.route(request);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e && e.stack ? e.stack : e);
      return json({ error: 'internal error' }, 500);
    }
  }

  async route(request) {
    const url = new URL(request.url);
    const p = url.pathname;
    const m = request.method;
    await this.sweep();

    if (m === 'GET' && p === '/v1/info') {
      return json({ name: 'request-access', version: VERSION, worker_key: await this.publicKey() });
    }
    if (m === 'POST' && p === '/telegram/webhook') return this.telegramWebhook(request);
    if (m === 'POST' && p === '/v1/enroll') return this.enroll(request);
    let mm;
    if (m === 'GET' && (mm = p.match(/^\/v1\/enroll\/([0-9a-f]{32})$/))) return this.enrollStatus(mm[1], url);

    // Passkey pages and what they post. Unauthenticated: the 128-bit id in
    // the link (sent only to the approver's chat) finds the request, and the
    // host verifies the passkey signature itself, so nothing posted here can
    // approve anything on its own.
    if (m === 'GET' && (mm = p.match(/^\/(approve|register)\/([0-9a-f]{32})$/))) return this.passkeyPage(mm[1], mm[2]);
    if (m === 'GET' && (mm = p.match(/^\/v1\/approve\/([0-9a-f]{32})$/))) return this.approveInfo(mm[1]);
    if (m === 'POST' && (mm = p.match(/^\/v1\/approve\/([0-9a-f]{32})$/))) return this.approveWithPasskey(mm[1], await request.text());
    if (m === 'GET' && (mm = p.match(/^\/v1\/register\/([0-9a-f]{32})$/))) return this.registerInfo(mm[1]);
    if (m === 'POST' && (mm = p.match(/^\/v1\/register\/([0-9a-f]{32})$/))) return this.registerPasskey(mm[1], await request.text());

    // Secrets vault pages (docs/VAULT.md). Unauthenticated like the passkey
    // pages: releasing a secret needs the vault password, which only the
    // approver has, and the result is sealed to the requesting host.
    if (m === 'GET' && (mm = p.match(/^\/vault\/(setup|trust|release)\/([0-9a-f]{32})$/))) return this.vaultPage(mm[1], mm[2]);
    if (m === 'GET' && (mm = p.match(/^\/v1\/vault\/page\/(setup|trust|release)\/([0-9a-f]{32})$/))) return this.vaultInfo(mm[1], mm[2]);
    if (m === 'POST' && (mm = p.match(/^\/v1\/vault\/page\/(setup|trust|release)\/([0-9a-f]{32})$/))) return this.vaultSubmit(mm[1], mm[2], await request.text());

    // Everything below requires a signed request.
    const body = m === 'GET' ? '' : await request.text();
    const caller = await this.authenticate(request, url, body);

    if (m === 'POST' && p === '/v1/access') return this.createAccess(caller, body, url);
    if (m === 'GET' && (mm = p.match(/^\/v1\/access\/([0-9a-f]{32})$/))) return this.accessStatus(caller, mm[1], url);
    if (m === 'POST' && p === '/v1/passkey/register') return this.createRegistration(caller, body, url);
    if (m === 'GET' && (mm = p.match(/^\/v1\/passkey\/register\/([0-9a-f]{32})$/))) return this.registrationStatus(caller, mm[1], url);
    if (m === 'POST' && p === '/v1/vault/init') return this.vaultLink(caller, body, url, 'setup');
    if (m === 'POST' && p === '/v1/vault/trust') return this.vaultLink(caller, body, url, 'trust');
    if (m === 'GET' && (mm = p.match(/^\/v1\/vault\/(init|trust)\/([0-9a-f]{32})$/))) return this.vaultLinkStatus(caller, mm[2], url);
    if (m === 'GET' && p === '/v1/vault/key') return this.vaultKey(caller);
    if (m === 'POST' && p === '/v1/vault/request') return this.vaultRequest(caller, body, url);
    if (m === 'GET' && (mm = p.match(/^\/v1\/vault\/request\/([0-9a-f]{32})$/))) return this.vaultRequestStatus(caller, mm[1], url);
    if (m === 'POST' && (mm = p.match(/^\/v1\/vault\/held\/([0-9a-f]{32})$/))) return this.vaultHeld(caller, mm[1], body);
    if (m === 'GET' && p === '/v1/admin/state') return this.adminState(caller);
    if (m === 'POST' && p === '/v1/admin/actions') return this.createAdminAction(caller, body);
    if (m === 'GET' && (mm = p.match(/^\/v1\/admin\/actions\/([0-9a-f]{32})$/))) return this.adminActionStatus(caller, mm[1], url);
    throw new HttpError(404, 'not found');
  }

  // ---------------------------------------------------------------- auth

  // Signed requests carry RA-Key-Id ("host:<name>" or "admin:<n>"),
  // RA-Timestamp (unix seconds) and RA-Signature (Ed25519, base64url) over:
  //   "RA1\n" METHOD "\n" PATH+QUERY "\n" TIMESTAMP "\n" base64url(sha256(body))
  async authenticate(request, url, body) {
    const keyId = request.headers.get('RA-Key-Id') || '';
    const ts = request.headers.get('RA-Timestamp') || '';
    const sig = request.headers.get('RA-Signature') || '';
    if (!keyId || !/^\d+$/.test(ts) || !sig) throw new HttpError(401, 'unsigned request');
    if (Math.abs(now() - Number(ts)) > MAX_SKEW) throw new HttpError(401, 'timestamp out of range');

    let pub, caller;
    if (keyId.startsWith('host:')) {
      const name = keyId.slice(5);
      const host = await this.storage.get('host:' + name);
      if (!host) throw new HttpError(401, 'unknown host');
      pub = host.key;
      caller = { kind: 'host', name };
    } else if (keyId.startsWith('admin:')) {
      const idx = Number(keyId.slice(6));
      const keys = adminKeys(this.env);
      if (!Number.isInteger(idx) || !keys[idx]) throw new HttpError(401, 'unknown admin key');
      pub = keys[idx];
      caller = { kind: 'admin', name: keyId };
    } else {
      throw new HttpError(401, 'bad key id');
    }
    const msg = `RA1\n${request.method}\n${url.pathname}${url.search}\n${ts}\n${b64u(await sha256(body))}`;
    if (!(await verifyEd25519(pub, sig, msg))) throw new HttpError(401, 'bad signature');
    return caller;
  }

  async useNonce(scope, nonce) {
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new HttpError(400, 'bad nonce');
    const k = `nonce:${scope}:${nonce}`;
    if (await this.storage.get(k)) throw new HttpError(409, 'nonce reused');
    await this.storage.put(k, { exp: now() + NONCE_TTL });
  }

  // ---------------------------------------------------------------- access

  async createAccess(caller, body, url) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const r = parseJson(body);
    await this.useNonce(caller.name, r.nonce);
    const service = str(r.service, 32);
    const user = str(r.user, 64);
    if (!service || !user) throw new HttpError(400, 'service and user required');
    const cfg = await this.config();
    const id = randomHex(16);
    const req = {
      id,
      host: caller.name,
      service,
      user,
      rhost: str(r.rhost, 128),
      tty: str(r.tty, 64),
      detail: str(r.detail, 256),
      nonce: r.nonce,
      created: now(),
      expires: now() + cfg.request_timeout,
      window: windowFor(cfg, caller.name, service),
      status: 'pending',
      ...routeFor(cfg, this.env, caller.name, user),
      approvals: [],
      passkey: parsePasskeyRequest(r.passkey, url),
    };
    // A passkey approval is one signature. Where a route asks for several
    // approvers, keep the taps unless the host itself insists on a passkey.
    if (req.passkey && req.required > 1 && !req.passkey.required) req.passkey = null;
    const t = texts(cfg.lang);
    const lines = [
      `🔐 <b>${esc(t.title[service] || service)}</b> ${esc(t.on)} <b>${esc(req.host)}</b>`,
      `${esc(t.user)}: <code>${esc(user)}</code>`,
    ];
    if (req.rhost) lines.push(`${esc(t.from)}: <code>${esc(req.rhost)}</code>`);
    if (req.tty) lines.push(`TTY: <code>${esc(req.tty)}</code>`);
    if (req.detail) lines.push(`<code>${esc(req.detail)}</code>`);
    if (req.required > 1 && !req.passkey) lines.push(`👥 ${esc(t.needs)} ${req.required}`);
    // With a passkey the approval happens on a page (the host checks the
    // signature); hosts that require one get no tap-to-allow buttons.
    const keyboard = [];
    if (req.passkey) keyboard.push([{ text: `🔑 ${t.approve_passkey}`, url: `${url.origin}/approve/${id}` }]);
    if (!req.passkey || !req.passkey.required) {
      keyboard.push([
        { text: `✅ ${t.allow} ${fmtDuration(req.window, cfg.lang)}`, callback_data: `r:${id}:a` },
        { text: `☑️ ${t.once}`, callback_data: `r:${id}:o` },
      ]);
    }
    keyboard.push([{ text: `❌ ${t.deny}`, callback_data: `r:${id}:d` }]);
    const sent = await this.telegram('sendMessage', {
      chat_id: req.chat,
      text: lines.join('\n'),
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: keyboard },
    });
    req.message_id = sent && sent.message_id;
    req.text = lines.join('\n');
    req.keyboard = keyboard;
    await this.storage.put('req:' + id, req);
    await this.scheduleAlarm(req.expires);
    return json({ id, expires: req.expires, window: req.window });
  }

  async accessStatus(caller, id, url) {
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const req = await this.storage.get('req:' + id);
      if (!req || caller.kind !== 'host' || req.host !== caller.name) throw new HttpError(404, 'not found');
      if (req.status === 'pending' && now() >= req.expires) await this.expire(req);
      if (req.status !== 'pending' || Date.now() >= deadline) {
        const out = { status: req.status };
        if (req.status === 'approved') out.grant = req.grant;
        if (req.status === 'approved' && req.assertion) out.passkey = req.assertion;
        return json(out);
      }
      await sleep(1000);
    }
  }

  // choice: 'a' (allow for the window), 'o' (just this once) or 'd' (deny).
  // assertion: set when the approver signed with a passkey on the approve
  // page; it is handed to the host, which verifies it.
  async decideAccess(req, choice, from, assertion = null) {
    if (req.status !== 'pending') return req.status;
    if (choice !== 'd' && !assertion && req.passkey && req.passkey.required) return 'passkey_required';
    if (now() >= req.expires) {
      await this.expire(req);
      return 'expired';
    }
    const cfg = await this.config();
    const t = texts(cfg.lang);
    if (choice === 'd') {
      req.status = 'denied';
      await this.editDecision(req, `❌ ${t.denied_by} ${who(from)}`);
    } else {
      // With several approvers required, collect distinct approvals first.
      // "Just this once" from any of them makes the grant a one-off.
      const id = String(from && from.id);
      if (!req.approvals.some((a) => a.id === id)) req.approvals.push({ id, who: who(from), once: choice === 'o' });
      if (assertion) req.assertion = assertion;
      // A passkey approval is complete on its own: the host checks one
      // signature and does not count Telegram taps.
      if (!assertion && req.approvals.length < (req.required || 1)) {
        await this.editDecision(req, `⏳ ${req.approvals.length}/${req.required}: ${req.approvals.map((a) => a.who).join(', ')}`, true);
        await this.storage.put('req:' + req.id, req);
        return 'pending';
      }
      const once = assertion ? choice === 'o' : req.approvals.some((a) => a.once);
      const window = once ? 30 : req.window;
      const payload = {
        v: 1,
        kind: 'grant',
        id: req.id,
        host: req.host,
        service: req.service,
        user: req.user,
        nonce: req.nonce,
        once,
        iat: now(),
        exp: now() + window,
      };
      req.grant = await this.sign(payload);
      req.status = 'approved';
      const label = once ? t.once_note : `${t.valid_for} ${fmtDuration(window, cfg.lang)}`;
      await this.editDecision(req, `✅ ${t.approved_by} ${req.approvals.map((a) => a.who).join(', ')} (${label})`);
    }
    req.decided = now();
    await this.storage.put('req:' + req.id, req);
    return req.status;
  }

  async expire(req) {
    req.status = 'expired';
    await this.storage.put('req:' + req.id, req);
    const t = texts((await this.config()).lang);
    await this.editDecision(req, `⌛ ${t.expired}`);
  }

  // keepButtons: an intermediate state (some approvals still missing).
  async editDecision(req, line, keepButtons = false) {
    if (!req.message_id) return;
    const params = {
      chat_id: req.chat || this.env.TELEGRAM_CHAT_ID,
      message_id: req.message_id,
      text: `${req.text}\n\n${esc(line)}`,
      parse_mode: 'HTML',
    };
    if (keepButtons && req.keyboard) params.reply_markup = { inline_keyboard: req.keyboard };
    await this.telegram('editMessageText', params);
  }

  // ---------------------------------------------------------------- passkeys

  // Data for the approve page; only for passkey requests.
  async approveInfo(id) {
    const req = await this.storage.get('req:' + id);
    if (!req || !req.passkey) throw new HttpError(404, 'not found');
    const cfg = await this.config();
    return json({
      lang: cfg.lang,
      status: req.status === 'pending' && now() >= req.expires ? 'expired' : req.status,
      host: req.host, service: req.service, user: req.user,
      rhost: req.rhost, tty: req.tty, detail: req.detail,
      window: req.window, expires: req.expires,
      rp_id: req.passkey.rp_id,
      challenges: req.passkey.challenges,
      credentials: req.passkey.credentials,
    });
  }

  async approveWithPasskey(id, body) {
    const req = await this.storage.get('req:' + id);
    if (!req || !req.passkey) throw new HttpError(404, 'not found');
    const r = parseJson(body);
    const choice = { window: 'a', once: 'o' }[r.choice];
    if (!choice) throw new HttpError(400, 'bad choice');
    const a = parseAssertion(r.assertion);
    // A sanity check so a stray post cannot close the request; the real
    // verification (signature, key, site, user verification) is the host's.
    const cd = clientDataOf(a.client_data_json);
    if (cd.type !== 'webauthn.get' || cd.challenge !== req.passkey.challenges[r.choice]) throw new HttpError(400, 'challenge does not match');
    if (!req.passkey.credentials.includes(a.id)) throw new HttpError(400, 'unknown passkey');
    const status = await this.decideAccess(req, choice, { id: 'passkey', first_name: 'passkey' }, a);
    return json({ status });
  }

  // A host (as root) asks to register a passkey. The approver opens the link
  // and creates the passkey on their phone; the host picks up the public key
  // and pins it.
  async createRegistration(caller, body, url) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const r = parseJson(body);
    await this.useNonce(caller.name, r.nonce);
    const label = str(r.label, 64);
    if (!label) throw new HttpError(400, 'label required');
    if (!isB64u(r.challenge, 43, 86)) throw new HttpError(400, 'bad challenge');
    if (r.rp_id !== url.hostname) throw new HttpError(400, "rp_id must be this server's host name");
    const exclude = credentialIds(r.exclude);
    const t = texts((await this.config()).lang);
    const id = randomHex(16);
    const text = [
      `🔑 <b>${esc(t.register_title)}</b>`,
      `${esc(t.server)}: <b>${esc(caller.name)}</b>`,
      `${esc(t.label)}: <code>${esc(label)}</code>`,
      esc(t.register_hint),
    ].join('\n');
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: `🔑 ${t.register_button}`, url: `${url.origin}/register/${id}` }],
          [{ text: `❌ ${t.deny}`, callback_data: `p:${id}:d` }],
        ],
      },
    });
    const reg = {
      id, host: caller.name, label, challenge: r.challenge, rp_id: r.rp_id, exclude,
      status: 'pending', created: now(), expires: now() + 600, message_id: sent && sent.message_id, text,
    };
    await this.storage.put('reg:' + id, reg);
    await this.scheduleAlarm(reg.expires);
    return json({ id, expires: reg.expires });
  }

  async registerInfo(id) {
    const reg = await this.storage.get('reg:' + id);
    if (!reg) throw new HttpError(404, 'not found');
    return json({
      lang: (await this.config()).lang,
      status: reg.status === 'pending' && now() >= reg.expires ? 'expired' : reg.status,
      host: reg.host, label: reg.label, rp_id: reg.rp_id, challenge: reg.challenge, exclude: reg.exclude,
      expires: reg.expires,
    });
  }

  async registerPasskey(id, body) {
    const reg = await this.storage.get('reg:' + id);
    if (!reg) throw new HttpError(404, 'not found');
    if (reg.status !== 'pending') return json({ status: reg.status });
    if (now() >= reg.expires) return json({ status: 'expired' });
    const r = parseJson(body).registration || {};
    if (!isB64u(r.id, 1, 1400) || !isB64u(r.public_key, 32, 2048) || !isB64u(r.client_data_json, 1, 4096) || ![-7, -8, -257].includes(r.alg)) {
      throw new HttpError(400, 'bad registration');
    }
    const cd = clientDataOf(r.client_data_json);
    if (cd.type !== 'webauthn.create' || cd.challenge !== reg.challenge) throw new HttpError(400, 'challenge does not match');
    reg.registration = { id: r.id, alg: r.alg, public_key: r.public_key, client_data_json: r.client_data_json };
    reg.status = 'approved';
    await this.storage.put('reg:' + id, reg);
    const t = texts((await this.config()).lang);
    await this.editMsg(reg, `✅ ${t.registered}\n${await fingerprint(r.public_key)}`);
    return json({ status: reg.status });
  }

  async registrationStatus(caller, id, url) {
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const reg = await this.storage.get('reg:' + id);
      if (!reg || caller.kind !== 'host' || reg.host !== caller.name) throw new HttpError(404, 'not found');
      if (reg.status === 'pending' && now() >= reg.expires) reg.status = 'expired';
      if (reg.status !== 'pending' || Date.now() >= deadline) {
        const out = { status: reg.status };
        if (reg.status === 'approved') out.registration = reg.registration;
        return json(out);
      }
      await sleep(1000);
    }
  }

  async passkeyPage(kind, id) {
    const obj = await this.storage.get((kind === 'approve' ? 'req:' : 'reg:') + id);
    if (!obj || (kind === 'approve' && !obj.passkey)) return new Response('Not found', { status: 404 });
    const nonce = b64u(crypto.getRandomValues(new Uint8Array(16)));
    return new Response(PAGE.replace(/__NONCE__/g, nonce).replace('__KIND__', kind), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  // ---------------------------------------------------------------- vault

  // A host (as root) asks to create the vault ("setup") or to be trusted by
  // the existing one ("trust"). The approver opens the link and enters the
  // vault password; the page creates the key pair, or adds the host's key to
  // the trusted hosts inside the locked vault key. Only the public key and the
  // password-encrypted private key ever come back here.
  async vaultLink(caller, body, url, kind) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const r = parseJson(body);
    await this.useNonce(caller.name, r.nonce);
    const vault = await this.storage.get('vault');
    if (kind === 'setup' && vault) throw new HttpError(409, 'a vault already exists; pin its key with: vault pin');
    if (kind === 'trust' && !vault) throw new HttpError(404, 'no vault yet; create one with: vault init');
    const host = await this.storage.get('host:' + caller.name);
    const t = texts((await this.config()).lang);
    const id = randomHex(16);
    const text = [
      `🗝️ <b>${esc(kind === 'setup' ? t.vault_setup_title : t.vault_trust_title)}</b>`,
      `${esc(t.server)}: <b>${esc(caller.name)}</b>`,
      `${esc(t.fingerprint)}: <code>${esc(host.fp)}</code>`,
      esc(t.register_hint),
    ].join('\n');
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: `🗝️ ${kind === 'setup' ? t.vault_setup_button : t.vault_trust_button}`, url: `${url.origin}/vault/${kind}/${id}` }],
          [{ text: `❌ ${t.deny}`, callback_data: `s:${id}:d` }],
        ],
      },
    });
    const set = {
      id, kind, host: caller.name, host_key: host.key, host_fp: host.fp,
      status: 'pending', created: now(), expires: now() + 900, message_id: sent && sent.message_id, text,
    };
    await this.storage.put('vset:' + id, set);
    await this.scheduleAlarm(set.expires);
    return json({ id, expires: set.expires });
  }

  async vaultLinkStatus(caller, id, url) {
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const set = await this.storage.get('vset:' + id);
      if (!set || caller.kind !== 'host' || set.host !== caller.name) throw new HttpError(404, 'not found');
      if (set.status === 'pending' && now() >= set.expires) set.status = 'expired';
      if (set.status !== 'pending' || Date.now() >= deadline) {
        const out = { status: set.status };
        if (set.status === 'approved') out.key = set.key;
        return json(out);
      }
      await sleep(1000);
    }
  }

  async vaultKey(caller) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const vault = await this.storage.get('vault');
    if (!vault) throw new HttpError(404, 'no vault yet; create one with: vault init');
    return json({ key: vault.key, fingerprint: vault.fp });
  }

  // A host asks to release one secret to one of its users. The request is
  // signed with the host key and carries the secret sealed to the vault key
  // and a fresh key to seal the released secret to; the Worker can read
  // neither, and the page checks the signature against the trusted hosts
  // inside the locked vault key, so the Worker cannot change any of it.
  async vaultRequest(caller, body, url) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const r = parseJson(body);
    await this.useNonce(caller.name, r.nonce);
    const vault = await this.storage.get('vault');
    if (!vault) throw new HttpError(404, 'no vault yet');
    if (r.vault_key !== vault.key) throw new HttpError(409, 'this host pinned a different vault key');
    const name = typeof r.name === 'string' ? r.name : '';
    const user = typeof r.user === 'string' ? r.user : '';
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name) || !user || user.length > 64) throw new HttpError(400, 'name and user required');
    // Signed fields are kept exactly as sent (no truncation), or refused.
    const reason = r.reason === undefined ? '' : r.reason;
    const detail = r.detail === undefined ? '' : r.detail;
    if (typeof reason !== 'string' || typeof detail !== 'string' || reason.length > 600 || detail.length > 800) throw new HttpError(400, 'bad reason or detail');
    const box = boxOf(r.box);
    if (!isB64u(r.reply_key, 87, 87)) throw new HttpError(400, 'bad reply key');
    if (!isB64u(r.sig, 86, 86)) throw new HttpError(400, 'bad signature');
    const hold = r.hold === undefined ? '' : holdOf(r.hold);
    const open = (await this.list('vreq:')).filter((v) => v.host === caller.name && v.status === 'pending');
    if (open.length >= MAX_PENDING_VAULT) throw new HttpError(429, 'too many open vault requests');
    const t = texts((await this.config()).lang);
    const id = randomHex(16);
    const req = {
      id, host: caller.name, user, name, reason, detail, box,
      reply_key: r.reply_key, nonce: r.nonce, sig: r.sig, hold,
      status: 'pending', created: now(), expires: now() + VAULT_TIMEOUT,
    };
    const lines = [
      `🗝️ <b>${esc(t.vault_title)}</b> <code>${esc(name)}</code> ${esc(t.on)} <b>${esc(req.host)}</b>`,
      `${esc(t.user)}: <code>${esc(user)}</code>`,
    ];
    if (reason) lines.push(`${esc(t.reason)}: ${esc(reason)}`);
    if (detail) lines.push(`<code>${esc(detail)}</code>`);
    if (hold) lines.push(`⏳ ${esc(t.hold_ask)}: ${esc(holdText(hold, t))}`);
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text: lines.join('\n'),
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: `🔓 ${t.vault_release}`, url: `${url.origin}/vault/release/${id}` }],
          [{ text: `❌ ${t.deny}`, callback_data: `v:${id}:d` }],
        ],
      },
    });
    req.message_id = sent && sent.message_id;
    req.text = lines.join('\n');
    await this.storage.put('vreq:' + id, req);
    await this.scheduleAlarm(req.expires);
    return json({ id, expires: req.expires });
  }

  // The sealed secret is handed out once, then forgotten.
  async vaultRequestStatus(caller, id, url) {
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const req = await this.storage.get('vreq:' + id);
      if (!req || caller.kind !== 'host' || req.host !== caller.name) throw new HttpError(404, 'not found');
      if (req.status === 'pending' && now() >= req.expires) req.status = 'expired';
      if (req.status !== 'pending' || Date.now() >= deadline) {
        const out = { status: req.status };
        if (req.status === 'approved') {
          if (!req.sealed) throw new HttpError(410, 'already delivered');
          out.sealed = req.sealed;
          delete req.sealed;
          req.delivered = now();
          await this.storage.put('vreq:' + id, req);
        }
        return json(out);
      }
      await sleep(1000);
    }
  }

  // A host reports that it served a held secret again: the approver gets a
  // silent message with Revoke. Once revoked (or past its terms) the host is
  // told, drops the secret and asks again.
  async vaultHeld(caller, id, body) {
    if (caller.kind !== 'host') throw new HttpError(403, 'hosts only');
    const r = parseJson(body);
    await this.useNonce(caller.name, r.nonce);
    const req = await this.storage.get('vreq:' + id);
    if (!req || req.host !== caller.name || !req.held) throw new HttpError(404, 'not found');
    if (req.revoked) return json({ status: 'revoked' });
    const terms = parseHold(req.hold);
    if (!terms || now() >= req.decided + terms.max) return json({ status: 'expired' });
    const t = texts((await this.config()).lang);
    const reason = str(r.reason, 600) || '';
    const detail = str(r.detail, 800) || '';
    const lines = [
      `🗝️ <code>${esc(req.name)}</code> ${esc(t.on)} <b>${esc(req.host)}</b>: ${esc(t.vault_reused)}`,
      `${esc(t.user)}: <code>${esc(req.user)}</code>`,
    ];
    if (reason) lines.push(`${esc(t.reason)}: ${esc(reason)}`);
    if (detail) lines.push(`<code>${esc(detail)}</code>`);
    await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text: lines.join('\n'),
      parse_mode: 'HTML',
      disable_notification: true,
      reply_markup: revokeButton(id, t),
    });
    req.reuses = (req.reuses || 0) + 1;
    await this.storage.put('vreq:' + id, req);
    return json({ status: 'held' });
  }

  // Data for the vault page.
  async vaultInfo(kind, id) {
    const lang = (await this.config()).lang;
    const vault = await this.storage.get('vault');
    const vaultOut = vault ? { key: vault.key, locked: vault.locked, fingerprint: vault.fp, auth_salt: vault.auth.salt } : null;
    if (kind === 'setup' || kind === 'trust') {
      const set = await this.storage.get('vset:' + id);
      if (!set || set.kind !== kind) throw new HttpError(404, 'not found');
      if (kind === 'trust' && !vault) throw new HttpError(404, 'no vault');
      return json({
        lang, status: set.status === 'pending' && now() >= set.expires ? 'expired' : set.status,
        host: set.host, host_key: set.host_key, host_fp: set.host_fp, expires: set.expires,
        vault: kind === 'trust' ? vaultOut : null,
      });
    }
    const req = await this.storage.get('vreq:' + id);
    if (!req || !vault) throw new HttpError(404, 'not found');
    const status = req.status === 'pending' && now() >= req.expires ? 'expired' : req.status;
    return json({
      lang,
      status,
      host: req.host, user: req.user, name: req.name, reason: req.reason, detail: req.detail, expires: req.expires,
      hold: req.hold || '', box: req.box, reply_key: req.reply_key, nonce: req.nonce, sig: req.sig,
      // The locked key only while the request is open.
      vault: status === 'pending' ? vaultOut : { fingerprint: vault.fp },
    });
  }

  // What the page posts: the new vault (setup), the re-locked vault key with
  // one more trusted host (trust), or the sealed secret (release).
  async vaultSubmit(kind, id, body) {
    const r = parseJson(body);
    const t = texts((await this.config()).lang);
    if (kind === 'release') {
      const req = await this.storage.get('vreq:' + id);
      if (!req) throw new HttpError(404, 'not found');
      if (req.status !== 'pending') return json({ status: req.status });
      if (now() >= req.expires) return json({ status: 'expired' });
      // Only someone with the vault password can close the request.
      if (!(await this.vaultProof(r.proof))) throw new HttpError(403, 'wrong vault password');
      req.sealed = boxOf(r.sealed);
      req.status = 'approved';
      req.decided = now();
      // What the page says it chose; the host only holds the secret if the
      // page sealed it for a hold, which needs the vault password. This
      // only decides whether the message offers Revoke.
      req.held = !!(req.hold && r.held === true);
      await this.storage.put('vreq:' + id, req);
      if (req.held) await this.editMsg(req, `✅ ${t.vault_released}, ${t.hold} ${holdText(req.hold, t)}`, revokeButton(id, t));
      else await this.editMsg(req, `✅ ${t.vault_released}`);
      return json({ status: req.status });
    }
    const set = await this.storage.get('vset:' + id);
    if (!set || set.kind !== kind) throw new HttpError(404, 'not found');
    if (set.status !== 'pending') return json({ status: set.status });
    if (now() >= set.expires) return json({ status: 'expired' });
    let vault = await this.storage.get('vault');
    if (kind === 'setup') {
      if (vault) throw new HttpError(409, 'a vault already exists');
      const a = r.auth || {};
      if (!isB64u(a.salt, 22, 43) || !isB64u(a.hash, 43, 43)) throw new HttpError(400, 'bad auth');
      vault = { key: vaultKeyOf(r.key), locked: lockedOf(r.locked), auth: { salt: a.salt, hash: a.hash }, created: now() };
      vault.fp = await fingerprint(vault.key);
    } else {
      if (!vault) throw new HttpError(404, 'no vault');
      // Changing the lock needs proof of the vault password (a second,
      // separately salted derivation of it), so a leaked link alone cannot
      // overwrite the vault key. Earlier locks are kept as well.
      if (!(await this.vaultProof(r.proof))) throw new HttpError(403, 'wrong vault password');
      // Two trust pages open at once must not undo each other: a change is
      // only accepted on top of the lock it was made from.
      if (r.base !== vault.locked.iv) throw new HttpError(409, 'the vault changed meanwhile; reload this page and try again');
      const hist = (await this.storage.get('vault_hist')) || [];
      hist.push({ locked: vault.locked, until: now() });
      await this.storage.put('vault_hist', hist.slice(-20));
      vault = { ...vault, locked: lockedOf(r.locked), updated: now() };
    }
    await this.storage.put('vault', vault);
    set.status = 'approved';
    set.key = vault.key;
    await this.storage.put('vset:' + id, set);
    await this.editMsg(set, kind === 'setup' ? `✅ ${t.vault_created}\n${vault.fp}` : `✅ ${t.vault_trusted}`);
    return json({ status: set.status, fingerprint: vault.fp });
  }

  // Checks a proof of the vault password (see passwordProof on the page).
  async vaultProof(proof) {
    const vault = await this.storage.get('vault');
    return !!vault && isB64u(proof, 43, 43) && timingSafeEqual(b64u(await sha256(b64uDecode(proof))), vault.auth.hash);
  }

  async vaultPage(kind, id) {
    const obj = await this.storage.get((kind === 'release' ? 'vreq:' : 'vset:') + id);
    if (!obj || (kind !== 'release' && obj.kind !== kind)) return new Response('Not found', { status: 404 });
    const nonce = b64u(crypto.getRandomValues(new Uint8Array(16)));
    return new Response(VAULT_PAGE.replace(/__NONCE__/g, nonce).replace('__KIND__', kind), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  // ---------------------------------------------------------------- enrollment

  // A new host asks to be enrolled. Unauthenticated by necessity (the host has
  // no registered key yet), so it is rate limited and always needs approval
  // on Telegram, where the key fingerprint the host printed can be compared.
  async enroll(request) {
    const r = parseJson(await request.text());
    const name = str(r.name, 64);
    if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) throw new HttpError(400, 'bad host name');
    if (typeof r.key !== 'string' || b64uDecode(r.key).length !== 32) throw new HttpError(400, 'bad key');
    await this.useNonce('enroll', r.nonce);
    const pending = (await this.list('enr:')).filter((e) => e.status === 'pending');
    if (pending.length >= MAX_PENDING_ENROLLMENTS) throw new HttpError(429, 'too many pending enrollments');
    const cfg = await this.config();
    const t = texts(cfg.lang);
    const id = randomHex(16);
    const existing = await this.storage.get('host:' + name);
    const fp = await fingerprint(r.key);
    const text = [
      `🖥️ <b>${esc(existing ? t.reenroll : t.enroll)}</b>`,
      `${esc(t.server)}: <b>${esc(name)}</b>`,
      `${esc(t.fingerprint)}: <code>${esc(fp)}</code>`,
      esc(t.compare),
    ].join('\n');
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [[
          { text: `✅ ${t.add}`, callback_data: `e:${id}:a` },
          { text: `❌ ${t.deny}`, callback_data: `e:${id}:d` },
        ]],
      },
    });
    const enr = {
      id, name, key: r.key, fp, status: 'pending', created: now(),
      expires: now() + 600, message_id: sent && sent.message_id, text,
    };
    await this.storage.put('enr:' + id, enr);
    await this.scheduleAlarm(enr.expires);
    return json({ id, fingerprint: fp, expires: enr.expires });
  }

  async enrollStatus(id, url) {
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const enr = await this.storage.get('enr:' + id);
      if (!enr) throw new HttpError(404, 'not found');
      if (enr.status !== 'pending' || Date.now() >= deadline) return json({ status: enr.status });
      await sleep(1000);
    }
  }

  async decideEnroll(enr, choice, from) {
    if (enr.status !== 'pending') return enr.status;
    const t = texts((await this.config()).lang);
    if (choice === 'a') {
      await this.storage.put('host:' + enr.name, { name: enr.name, key: enr.key, fp: enr.fp, added: now() });
      enr.status = 'approved';
      await this.editMsg(enr, `✅ ${t.added_by} ${who(from)}`);
    } else {
      enr.status = 'denied';
      await this.editMsg(enr, `❌ ${t.denied_by} ${who(from)}`);
    }
    await this.storage.put('enr:' + enr.id, enr);
    return enr.status;
  }

  // ---------------------------------------------------------------- admin

  async adminState(caller) {
    if (caller.kind !== 'admin') throw new HttpError(403, 'admin only');
    const hosts = (await this.list('host:')).map((h) => ({ name: h.name, fingerprint: h.fp, added: h.added }));
    return json({ version: VERSION, config: await this.config(), hosts });
  }

  // Every change goes through Telegram as well: an admin key on its own
  // (say, on a compromised machine) cannot silently widen grant windows or
  // swap a host's key.
  async createAdminAction(caller, body) {
    if (caller.kind !== 'admin') throw new HttpError(403, 'admin only');
    const r = parseJson(body);
    await this.useNonce('admin', r.nonce);
    const cfg = await this.config();
    const t = texts(cfg.lang);
    let summary;
    if (r.action === 'remove_host') {
      if (!(await this.storage.get('host:' + str(r.name, 64)))) throw new HttpError(404, 'unknown host');
      summary = `${t.remove_host}: ${r.name}`;
    } else if (r.action === 'set_config') {
      const next = validateConfig({ ...cfg, ...(r.config || {}) });
      summary = `${t.set_config}:\n${diffConfig(cfg, next)}`;
      r.config = next;
    } else {
      throw new HttpError(400, 'unknown action');
    }
    const id = randomHex(16);
    const text = `⚙️ <b>${esc(t.admin_change)}</b>\n<code>${esc(summary)}</code>`;
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [[
          { text: `✅ ${t.confirm}`, callback_data: `x:${id}:a` },
          { text: `❌ ${t.deny}`, callback_data: `x:${id}:d` },
        ]],
      },
    });
    const act = {
      id, action: r.action, name: r.name, config: r.config, status: 'pending',
      created: now(), expires: now() + 600, message_id: sent && sent.message_id, text,
    };
    await this.storage.put('act:' + id, act);
    await this.scheduleAlarm(act.expires);
    return json({ id, expires: act.expires });
  }

  async adminActionStatus(caller, id, url) {
    if (caller.kind !== 'admin') throw new HttpError(403, 'admin only');
    const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25);
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const act = await this.storage.get('act:' + id);
      if (!act) throw new HttpError(404, 'not found');
      if (act.status !== 'pending' || Date.now() >= deadline) return json({ status: act.status });
      await sleep(1000);
    }
  }

  async decideAdmin(act, choice, from) {
    if (act.status !== 'pending') return act.status;
    const t = texts((await this.config()).lang);
    if (choice === 'a') {
      if (act.action === 'remove_host') await this.storage.delete('host:' + act.name);
      if (act.action === 'set_config') await this.storage.put('config', act.config);
      act.status = 'approved';
      await this.editMsg(act, `✅ ${t.approved_by} ${who(from)}`);
    } else {
      act.status = 'denied';
      await this.editMsg(act, `❌ ${t.denied_by} ${who(from)}`);
    }
    await this.storage.put('act:' + act.id, act);
    return act.status;
  }

  // ---------------------------------------------------------------- telegram

  async telegramWebhook(request) {
    const secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token') || '';
    if (!this.env.TELEGRAM_WEBHOOK_SECRET || !timingSafeEqual(secret, this.env.TELEGRAM_WEBHOOK_SECRET)) {
      throw new HttpError(401, 'bad webhook secret');
    }
    const update = await request.json();
    const cq = update.callback_query;
    if (!cq) return json({ ok: true });
    const t = texts((await this.config()).lang);
    const fromId = String(cq.from && cq.from.id);
    const denyTap = async () => {
      await this.telegram('answerCallbackQuery', { callback_query_id: cq.id, text: t.not_allowed });
      return json({ ok: true });
    };
    const m = /^([rexpvsh]):([0-9a-f]{32}):([aod])$/.exec(cq.data || '');
    let result = 'unknown';
    if (m) {
      const [, kind, id, choice] = m;
      // Access requests are approved by their route's approvers; enrolling
      // hosts and admin changes only by the default approvers.
      if (kind === 'r') {
        const req = await this.storage.get('req:' + id);
        const allowed = req ? req.approvers || defaultApprovers(this.env) : [];
        if (!allowed.includes(fromId)) return denyTap();
        result = await this.decideAccess(req, choice, cq.from);
      } else if (!defaultApprovers(this.env).includes(fromId)) {
        return denyTap();
      } else if (kind === 'p') {
        const reg = await this.storage.get('reg:' + id);
        if (reg && reg.status === 'pending' && choice === 'd') {
          reg.status = 'denied';
          await this.storage.put('reg:' + id, reg);
          await this.editMsg(reg, `❌ ${t.denied_by} ${who(cq.from)}`);
        }
        result = reg ? reg.status : 'unknown';
      } else if (kind === 'v' || kind === 's') {
        // Vault messages only carry Deny; releasing needs the page.
        const k = (kind === 'v' ? 'vreq:' : 'vset:') + id;
        const v = await this.storage.get(k);
        if (v && v.status === 'pending' && choice === 'd') {
          v.status = 'denied';
          await this.storage.put(k, v);
          await this.editMsg(v, `❌ ${t.denied_by} ${who(cq.from)}`);
        }
        result = v ? v.status : 'unknown';
      } else if (kind === 'h') {
        // Revoke a hold: the host drops the secret at its next use.
        const v = await this.storage.get('vreq:' + id);
        if (v && v.held && choice === 'd') {
          if (!v.revoked) {
            v.revoked = now();
            await this.storage.put('vreq:' + id, v);
            await this.editMsg(v, `🚫 ${t.hold_revoked_by} ${who(cq.from)}`);
          }
          result = 'revoked';
        }
      } else if (kind === 'e') {
        const enr = await this.storage.get('enr:' + id);
        if (enr) result = await this.decideEnroll(enr, choice === 'o' ? 'a' : choice, cq.from);
      } else {
        const act = await this.storage.get('act:' + id);
        if (act) result = await this.decideAdmin(act, choice === 'o' ? 'a' : choice, cq.from);
      }
    }
    await this.telegram('answerCallbackQuery', { callback_query_id: cq.id, text: t.status[result] || result });
    return json({ ok: true });
  }

  async telegram(method, params) {
    const base = this.env.TELEGRAM_API || 'https://api.telegram.org';
    const res = await fetch(`${base}/bot${this.env.TELEGRAM_BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    const data = await res.json().catch(() => ({}));
    if (!data.ok) {
      console.error(`telegram ${method} failed: ${res.status} ${data.description || ''}`);
      if (method === 'sendMessage') throw new HttpError(502, 'could not reach the approver');
      return null;
    }
    return data.result;
  }

  async editMsg(obj, line, markup) {
    if (!obj.message_id) return;
    const params = {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      message_id: obj.message_id,
      text: `${obj.text}\n\n${esc(line)}`,
      parse_mode: 'HTML',
    };
    if (markup) params.reply_markup = markup;
    await this.telegram('editMessageText', params);
  }

  // ---------------------------------------------------------------- housekeeping

  async alarm() {
    await this.sweep();
  }

  async scheduleAlarm(at) {
    const cur = await this.storage.getAlarm();
    const when = (at + 1) * 1000;
    if (!cur || cur > when) await this.storage.setAlarm(when);
  }

  // Expire stale requests (editing their Telegram message), forget old
  // nonces and drop finished records after a day.
  async sweep() {
    const t = now();
    let next = null;
    for (const [k, v] of await this.storage.list({ prefix: 'nonce:' })) if (v.exp < t) await this.storage.delete(k);
    for (const prefix of ['req:', 'enr:', 'act:', 'reg:', 'vreq:', 'vset:']) {
      for (const [k, v] of await this.storage.list({ prefix })) {
        if (v.status === 'pending' && t >= v.expires) {
          if (prefix === 'req:') await this.expire(v);
          else {
            v.status = 'expired';
            await this.storage.put(k, v);
            await this.editMsg(v, `⌛ ${texts((await this.config()).lang).expired}`);
          }
        } else if (v.status === 'pending') {
          next = next === null ? v.expires : Math.min(next, v.expires);
        } else if (t - v.created > 86400) {
          await this.storage.delete(k);
        }
      }
    }
    if (next !== null) await this.scheduleAlarm(next);
  }

  async list(prefix) {
    return [...(await this.storage.list({ prefix })).values()];
  }

  async config() {
    return { ...DEFAULT_CONFIG, ...((await this.storage.get('config')) || {}) };
  }

  // ---------------------------------------------------------------- signing

  async signingKey() {
    if (!this._sk) {
      this._sk = await crypto.subtle.importKey('pkcs8', b64uDecode(this.env.SIGNING_KEY), { name: 'Ed25519' }, true, ['sign']);
    }
    return this._sk;
  }

  async publicKey() {
    if (!this._pk) {
      const jwk = await crypto.subtle.exportKey('jwk', await this.signingKey());
      this._pk = jwk.x; // raw public key, base64url
    }
    return this._pk;
  }

  async sign(payload) {
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, await this.signingKey(), bytes);
    return { payload: b64u(bytes), sig: b64u(new Uint8Array(sig)) };
  }
}

// ------------------------------------------------------------------ helpers

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function parseJson(s) {
  try {
    const v = JSON.parse(s);
    if (v && typeof v === 'object') return v;
  } catch {}
  throw new HttpError(400, 'bad json');
}

function str(v, max) {
  if (v === undefined || v === null) return '';
  return String(v).slice(0, max);
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function who(from) {
  if (!from) return '?';
  return from.username ? '@' + from.username : from.first_name || String(from.id);
}

function adminKeys(env) {
  return String(env.ADMIN_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function windowFor(cfg, host, service) {
  const w = cfg.windows || {};
  const v = w[`${host}/${service}`] ?? w[service] ?? cfg.default_window;
  return Math.max(30, Math.min(Number(v) || cfg.default_window, cfg.max_window));
}

function validateConfig(c) {
  const out = { ...DEFAULT_CONFIG, ...c };
  if (!['en', 'nl'].includes(out.lang)) throw new HttpError(400, 'lang must be en or nl');
  const num = (v, lo, hi, name) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < lo || n > hi) throw new HttpError(400, `${name} must be an integer between ${lo} and ${hi}`);
    return n;
  };
  out.request_timeout = num(out.request_timeout, 15, 600, 'request_timeout');
  out.max_window = num(out.max_window, 30, 7 * 86400, 'max_window');
  out.default_window = num(out.default_window, 30, out.max_window, 'default_window');
  const windows = {};
  for (const [k, v] of Object.entries(out.windows || {})) {
    if (!/^([A-Za-z0-9._-]+\/)?[a-z0-9_-]+$/.test(k)) throw new HttpError(400, `bad window key ${k}`);
    if (v === null) continue; // null removes an entry
    windows[k] = num(v, 30, out.max_window, `window ${k}`);
  }
  out.windows = windows;
  const routes = {};
  for (const [k, v] of Object.entries(out.routes || {})) {
    if (!/^([A-Za-z0-9._-]+|user:[A-Za-z0-9._@-]+|[A-Za-z0-9._-]+\/user:[A-Za-z0-9._@-]+)$/.test(k)) throw new HttpError(400, `bad route key ${k}`);
    if (v === null) continue;
    const approvers = (Array.isArray(v.approvers) ? v.approvers : String(v.approvers || '').split(','))
      .map((x) => String(x).trim()).filter(Boolean);
    if (!approvers.length || !approvers.every((x) => /^\d+$/.test(x))) throw new HttpError(400, `route ${k}: approvers must be numeric Telegram user ids`);
    const chat = String(v.chat || (approvers.length === 1 ? approvers[0] : ''));
    if (!/^-?\d+$/.test(chat)) throw new HttpError(400, `route ${k}: chat must be a numeric Telegram chat id`);
    const required = num(v.required ?? 1, 1, approvers.length, `route ${k}: required`);
    routes[k] = { chat, approvers, required };
  }
  out.routes = routes;
  return out;
}

function isB64u(v, min, max) {
  return typeof v === 'string' && v.length >= min && v.length <= max && /^[A-Za-z0-9_-]+$/.test(v);
}

function credentialIds(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > 20 || !v.every((x) => isB64u(x, 1, 1400))) throw new HttpError(400, 'bad credential ids');
  return v;
}

// The passkey part of an access request: the two challenges the host will
// accept (approve for the window, or just this once) and the credentials
// it has pinned.
function parsePasskeyRequest(p, url) {
  if (p === undefined || p === null) return null;
  if (typeof p !== 'object') throw new HttpError(400, 'bad passkey');
  if (p.rp_id !== url.hostname) throw new HttpError(400, "passkey rp_id must be this server's host name");
  const c = p.challenges || {};
  if (!isB64u(c.window, 43, 86) || !isB64u(c.once, 43, 86) || c.window === c.once) throw new HttpError(400, 'bad passkey challenges');
  const credentials = credentialIds(p.credentials);
  if (!credentials.length) throw new HttpError(400, 'no passkeys');
  return { rp_id: p.rp_id, challenges: { window: c.window, once: c.once }, credentials, required: p.required === true };
}

// Vault shapes: a raw P-256 public key (65 bytes), the password-locked
// private key, and an ECIES box (see internal/vault/crypto.go).
function vaultKeyOf(k) {
  if (!isB64u(k, 87, 87)) throw new HttpError(400, 'bad vault key');
  return k;
}

function lockedOf(l) {
  if (!l || typeof l !== 'object' || l.kdf !== 'pbkdf2-sha256' || !Number.isInteger(l.iter) || l.iter < 100000 || l.iter > 10000000 ||
      !isB64u(l.salt, 22, 43) || !isB64u(l.iv, 16, 16) || !isB64u(l.ct, 32, 16384)) {
    throw new HttpError(400, 'bad locked key');
  }
  return { kdf: l.kdf, iter: l.iter, salt: l.salt, iv: l.iv, ct: l.ct };
}

function boxOf(b) {
  if (!b || typeof b !== 'object' || b.v !== 1 || !isB64u(b.epk, 87, 87) || !isB64u(b.iv, 16, 16) || !isB64u(b.ct, 22, 22000)) {
    throw new HttpError(400, 'bad box');
  }
  return { v: 1, epk: b.epk, iv: b.iv, ct: b.ct };
}

function parseAssertion(a) {
  if (!a || typeof a !== 'object' || !isB64u(a.id, 1, 1400) || !isB64u(a.client_data_json, 1, 4096) ||
      !isB64u(a.authenticator_data, 37, 4096) || !isB64u(a.signature, 1, 1024)) {
    throw new HttpError(400, 'bad assertion');
  }
  return { id: a.id, client_data_json: a.client_data_json, authenticator_data: a.authenticator_data, signature: a.signature };
}

function clientDataOf(s) {
  try {
    const v = JSON.parse(new TextDecoder().decode(b64uDecode(s)));
    if (v && typeof v === 'object') return v;
  } catch {}
  throw new HttpError(400, 'bad client data');
}

function defaultApprovers(env) {
  return String(env.APPROVER_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function routeFor(cfg, env, host, user) {
  const r = cfg.routes || {};
  const hit = r[`${host}/user:${user}`] || r[`user:${user}`] || r[host];
  if (hit) return { chat: hit.chat, approvers: hit.approvers, required: hit.required };
  return { chat: String(env.TELEGRAM_CHAT_ID), approvers: defaultApprovers(env), required: 1 };
}

function diffConfig(a, b) {
  const flat = (c) => {
    const o = { lang: c.lang, request_timeout: c.request_timeout, default_window: c.default_window, max_window: c.max_window };
    for (const [k, v] of Object.entries(c.windows || {})) o[`windows.${k}`] = v;
    for (const [k, v] of Object.entries(c.routes || {})) o[`routes.${k}`] = `chat ${v.chat}, approvers ${v.approvers.join('+')}, required ${v.required}`;
    return o;
  };
  const fa = flat(a), fb = flat(b);
  const keys = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].sort();
  const lines = keys.filter((k) => fa[k] !== fb[k]).map((k) => `${k}: ${fa[k] ?? '-'} → ${fb[k] ?? '-'}`);
  return lines.length ? lines.join('\n') : '(no changes)';
}

// Hold terms as the host signs them (HoldTerms in internal/vault/crypto.go):
// seconds between uses, and in total. At most 12 hours, because the record
// that lets the approver revoke a hold is dropped a day after the request.
function parseHold(h) {
  const m = /^idle=([1-9][0-9]{0,4}),max=([1-9][0-9]{0,4})$/.exec(typeof h === 'string' ? h : '');
  if (!m) return null;
  const idle = Number(m[1]), max = Number(m[2]);
  return idle <= max && max <= 43200 ? { idle, max } : null;
}

function holdOf(h) {
  if (!parseHold(h)) throw new HttpError(400, 'bad hold');
  return h;
}

function holdText(h, t) {
  const p = parseHold(h);
  return p ? `${fmtDuration(p.idle, t.lang)} ${t.hold_idle}, max ${fmtDuration(p.max, t.lang)}` : '';
}

function revokeButton(id, t) {
  return { inline_keyboard: [[{ text: `🚫 ${t.hold_revoke}`, callback_data: `h:${id}:d` }]] };
}

function fmtDuration(s, lang) {
  const nl = lang === 'nl';
  if (s % 86400 === 0) return `${s / 86400} ${nl ? (s === 86400 ? 'dag' : 'dagen') : s === 86400 ? 'day' : 'days'}`;
  if (s % 3600 === 0) return `${s / 3600} ${nl ? 'uur' : 'h'}`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

function texts(lang) {
  const en = {
    title: { ssh: 'SSH login', sudo: 'sudo' },
    on: 'on', user: 'User', from: 'From', server: 'Server', needs: 'Approvals needed:',
    allow: 'Allow', once: 'Just this once', deny: 'Deny',
    approved_by: 'Approved by', denied_by: 'Denied by', valid_for: 'valid for', once_note: 'this once',
    expired: 'Expired, no answer in time', not_allowed: 'You are not an approver.',
    enroll: 'New server wants to enroll', reenroll: 'Server wants to replace its key', fingerprint: 'Key fingerprint',
    compare: 'Compare this with the fingerprint shown on the server.', add: 'Add server', added_by: 'Added by',
    admin_change: 'Configuration change', remove_host: 'Remove server', set_config: 'Change settings', confirm: 'Confirm',
    approve_passkey: 'Approve with passkey', register_title: 'Register a passkey', label: 'Name',
    register_hint: 'Only continue if you just started this on the server.', register_button: 'Create passkey',
    registered: 'Passkey created; compare the fingerprint with the server:',
    vault_setup_title: 'Create the secrets vault', vault_setup_button: 'Create vault', vault_created: 'Vault created; compare the fingerprint with the server:',
    vault_trust_title: 'Trust a server for the vault', vault_trust_button: 'Trust server', vault_trusted: 'Server trusted',
    vault_title: 'Secret', reason: 'Reason', vault_release: 'Open to release', vault_released: 'Released',
    lang: 'en', hold_ask: 'Asks to hold it', hold: 'held', hold_idle: 'between uses', hold_revoke: 'Revoke hold', hold_revoked_by: 'Hold revoked by',
    vault_reused: 'held secret used again',
    status: { revoked: 'Hold revoked', approved: 'Approved', denied: 'Denied', expired: 'Already expired', pending: 'Noted, waiting for more approvals', unknown: 'Unknown request', passkey_required: 'This server needs your passkey: use the 🔑 button' },
  };
  if (lang !== 'nl') return en;
  return {
    title: { ssh: 'SSH-login', sudo: 'sudo' },
    on: 'op', user: 'Gebruiker', from: 'Vanaf', server: 'Server', needs: 'Akkoorden nodig:',
    allow: 'Toestaan', once: 'Alleen deze keer', deny: 'Weigeren',
    approved_by: 'Goedgekeurd door', denied_by: 'Geweigerd door', valid_for: 'geldig', once_note: 'alleen deze keer',
    expired: 'Verlopen, niet op tijd beantwoord', not_allowed: 'Je mag dit niet goedkeuren.',
    enroll: 'Nieuwe server wil zich aanmelden', reenroll: 'Server wil een nieuwe sleutel', fingerprint: 'Vingerafdruk sleutel',
    compare: 'Vergelijk dit met de vingerafdruk op de server.', add: 'Server toevoegen', added_by: 'Toegevoegd door',
    admin_change: 'Configuratiewijziging', remove_host: 'Server verwijderen', set_config: 'Instellingen wijzigen', confirm: 'Bevestigen',
    approve_passkey: 'Goedkeuren met passkey', register_title: 'Passkey registreren', label: 'Naam',
    register_hint: 'Ga alleen verder als je dit net zelf op de server hebt gestart.', register_button: 'Passkey aanmaken',
    registered: 'Passkey aangemaakt; vergelijk de vingerafdruk met de server:',
    vault_setup_title: 'Kluis voor geheimen aanmaken', vault_setup_button: 'Kluis aanmaken', vault_created: 'Kluis aangemaakt; vergelijk de vingerafdruk met de server:',
    vault_trust_title: 'Server toevoegen aan de kluis', vault_trust_button: 'Server vertrouwen', vault_trusted: 'Server vertrouwd',
    vault_title: 'Geheim', reason: 'Reden', vault_release: 'Openen om vrij te geven', vault_released: 'Vrijgegeven',
    lang: 'nl', hold_ask: 'Vraagt om vast te houden', hold: 'vastgehouden', hold_idle: 'tussen gebruik', hold_revoke: 'Intrekken', hold_revoked_by: 'Ingetrokken door',
    vault_reused: 'vastgehouden geheim opnieuw gebruikt',
    status: { revoked: 'Ingetrokken', approved: 'Goedgekeurd', denied: 'Geweigerd', expired: 'Al verlopen', pending: 'Genoteerd, wacht op meer akkoorden', unknown: 'Onbekend verzoek', passkey_required: 'Deze server vraagt je passkey: gebruik de 🔑-knop' },
  };
}

function randomHex(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof s === 'string' ? new TextEncoder().encode(s) : s));
}

async function fingerprint(keyB64u) {
  return 'SHA256:' + b64u(await sha256(b64uDecode(keyB64u))).slice(0, 43);
}

async function verifyEd25519(pubB64u, sigB64u, msg) {
  try {
    const key = await crypto.subtle.importKey('raw', b64uDecode(pubB64u), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, b64uDecode(sigB64u), new TextEncoder().encode(msg));
  } catch {
    return false;
  }
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s) {
  const b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

// ------------------------------------------------------------------ page

// The approve and register page. Everything it shows comes from the API and
// the host verifies what it signs, so the page holds no secrets. No
// backticks or dollar-brace below: this is one template literal.
const PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Request Access</title>
<style nonce="__NONCE__">
  :root { color-scheme: light dark; --fg: #1b1f24; --muted: #5d6670; --bg: #f6f7f9; --card: #fff; --line: #dde1e6; --ok: #1a7f37; --bad: #b42318; --accent: #1f5fbf; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e8eaed; --muted: #9aa3ad; --bg: #111418; --card: #1a1e24; --line: #2c323a; --ok: #4ac26b; --bad: #f1707a; --accent: #3d7be0; } }
  * { box-sizing: border-box; }
  body { margin: 0; font: 16px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
  main { max-width: 26rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  dl { margin: 0 0 1.25rem; padding: 1rem; background: var(--card); border: 1px solid var(--line); border-radius: 10px; display: grid; grid-template-columns: auto 1fr; gap: .35rem .9rem; }
  dl:empty { display: none; }
  dt { color: var(--muted); }
  dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .92rem; overflow-wrap: anywhere; }
  button { display: block; width: 100%; padding: .85rem 1rem; margin: 0 0 .6rem; font: inherit; font-weight: 600; border-radius: 10px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button:disabled { opacity: .5; cursor: default; }
  #msg { min-height: 1.5rem; margin: .5rem 0 0; }
  .ok { color: var(--ok); } .bad { color: var(--bad); } .muted { color: var(--muted); font-size: .9rem; }
  code.fp { display: block; margin-top: .4rem; font-size: .85rem; overflow-wrap: anywhere; color: var(--fg); }
</style>
</head>
<body>
<main>
  <h1 id="title">Request Access</h1>
  <dl id="facts"></dl>
  <div id="actions"></div>
  <p id="msg" role="status"></p>
  <p class="muted" id="hint"></p>
</main>
<script nonce="__NONCE__">
(function () {
  var KIND = '__KIND__';
  var id = location.pathname.split('/').pop();
  var T = {
    en: {
      approve: 'Approve access', register: 'Register a passkey', server: 'Server', service: 'Service', user: 'User', from: 'From',
      command: 'Command', name: 'Name', allow: 'Allow for ', once: 'Just this once', create: 'Create passkey',
      approved: 'Approved. You can close this page.', registered: 'Passkey created. Check that the server shows the same fingerprint:',
      denied: 'This request was denied.', expired: 'This request has expired.', done: 'This request was already answered.',
      cancelled: 'Cancelled or not allowed. Try again.', unsupported: 'This browser cannot use passkeys. Open the link in Safari or Chrome.',
      failed: 'Failed: ', hint_approve: 'Only approve what you started yourself just now.',
      hint_register: 'Only continue if you just ran "passkey add" on this server yourself.', s: ' s', min: ' min', h: ' h', d: ' days'
    },
    nl: {
      approve: 'Toegang goedkeuren', register: 'Passkey registreren', server: 'Server', service: 'Dienst', user: 'Gebruiker', from: 'Vanaf',
      command: 'Opdracht', name: 'Naam', allow: 'Toestaan voor ', once: 'Alleen deze keer', create: 'Passkey aanmaken',
      approved: 'Goedgekeurd. Je kunt deze pagina sluiten.', registered: 'Passkey aangemaakt. Controleer of de server dezelfde vingerafdruk toont:',
      denied: 'Dit verzoek is geweigerd.', expired: 'Dit verzoek is verlopen.', done: 'Dit verzoek is al beantwoord.',
      cancelled: 'Geannuleerd of niet toegestaan. Probeer opnieuw.', unsupported: 'Deze browser kan geen passkeys gebruiken. Open de link in Safari of Chrome.',
      failed: 'Mislukt: ', hint_approve: 'Keur alleen goed wat je zelf net hebt gestart.',
      hint_register: 'Ga alleen verder als je net zelf "passkey add" op deze server hebt gedraaid.', s: ' s', min: ' min', h: ' uur', d: ' dagen'
    }
  };
  var t = T.en;
  var $ = function (s) { return document.getElementById(s); };

  function b64u(buf) {
    var s = '', b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  function unb64u(s) {
    var b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(b, function (c) { return c.charCodeAt(0); });
  }
  function msg(text, cls) { var m = $('msg'); m.textContent = text; m.className = cls || ''; }
  function fact(k, v) {
    if (!v) return;
    var dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = k; dd.textContent = v;
    $('facts').append(dt, dd);
  }
  function button(text, primary, onclick) {
    var b = document.createElement('button');
    b.textContent = text; if (primary) b.className = 'primary';
    b.addEventListener('click', onclick);
    $('actions').append(b);
  }
  function busy(on) { document.querySelectorAll('button').forEach(function (b) { b.disabled = on; }); }
  function duration(s) {
    if (s % 86400 === 0) return s / 86400 + t.d;
    if (s % 3600 === 0) return s / 3600 + t.h;
    if (s % 60 === 0) return s / 60 + t.min;
    return s + t.s;
  }
  function closed(status) {
    $('actions').textContent = '';
    msg(t[status] || t.done, status === 'approved' ? 'ok' : 'bad');
  }
  function failed(e) {
    busy(false);
    msg(e && e.name === 'NotAllowedError' ? t.cancelled : t.failed + ((e && e.message) || e), 'bad');
  }
  async function post(path, body) {
    var res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || res.status);
    return data;
  }

  async function approve(info, choice) {
    busy(true); msg('');
    try {
      var cred = await navigator.credentials.get({ publicKey: {
        challenge: unb64u(info.challenges[choice]),
        rpId: info.rp_id,
        allowCredentials: info.credentials.map(function (c) { return { type: 'public-key', id: unb64u(c) }; }),
        userVerification: 'required',
        timeout: 120000
      } });
      var r = await post('/v1/approve/' + id, { choice: choice, assertion: {
        id: b64u(cred.rawId),
        client_data_json: b64u(cred.response.clientDataJSON),
        authenticator_data: b64u(cred.response.authenticatorData),
        signature: b64u(cred.response.signature)
      } });
      closed(r.status);
    } catch (e) { failed(e); }
  }

  async function register(info) {
    busy(true); msg('');
    try {
      var user = new Uint8Array(16); crypto.getRandomValues(user);
      var cred = await navigator.credentials.create({ publicKey: {
        rp: { id: info.rp_id, name: 'Request Access' },
        user: { id: user, name: 'request-access ' + info.label, displayName: 'Request Access (' + info.label + ')' },
        challenge: unb64u(info.challenge),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        excludeCredentials: (info.exclude || []).map(function (c) { return { type: 'public-key', id: unb64u(c) }; }),
        attestation: 'none',
        timeout: 120000
      } });
      if (typeof cred.response.getPublicKey !== 'function') throw new Error(t.unsupported);
      var spki = cred.response.getPublicKey();
      var r = await post('/v1/register/' + id, { registration: {
        id: b64u(cred.rawId),
        alg: cred.response.getPublicKeyAlgorithm(),
        public_key: b64u(spki),
        client_data_json: b64u(cred.response.clientDataJSON)
      } });
      if (r.status !== 'approved') return closed(r.status);
      var fp = 'SHA256:' + b64u(await crypto.subtle.digest('SHA-256', spki));
      $('actions').textContent = '';
      msg(t.registered, 'ok');
      var c = document.createElement('code'); c.className = 'fp'; c.textContent = fp;
      $('msg').append(c);
    } catch (e) { failed(e); }
  }

  async function main() {
    var res = await fetch('/v1/' + KIND + '/' + id);
    if (!res.ok) { msg(t.expired, 'bad'); return; }
    var info = await res.json();
    t = T[info.lang] || T.en;
    document.documentElement.lang = info.lang === 'nl' ? 'nl' : 'en';
    $('title').textContent = KIND === 'approve' ? t.approve : t.register;
    $('hint').textContent = KIND === 'approve' ? t.hint_approve : t.hint_register;
    fact(t.server, info.host);
    if (KIND === 'approve') {
      fact(t.service, info.service); fact(t.user, info.user); fact(t.from, info.rhost); fact('TTY', info.tty); fact(t.command, info.detail);
    } else {
      fact(t.name, info.label);
    }
    if (info.status !== 'pending') return closed(info.status);
    if (!window.PublicKeyCredential || !navigator.credentials) { msg(t.unsupported, 'bad'); return; }
    if (KIND === 'approve') {
      button(t.allow + duration(info.window), true, function () { approve(info, 'window'); });
      button(t.once, false, function () { approve(info, 'once'); });
    } else {
      button(t.create, true, function () { register(info); });
    }
  }
  main().catch(failed);
})();
</script>
</body>
</html>
`;

// ------------------------------------------------------------------ vault page

// The vault setup and release page. The vault password never leaves this
// page: it unlocks the vault's private key here, which opens the one
// requested secret, which is sealed to the requesting host's fresh key.
// The block between CRYPTO-BEGIN and CRYPTO-END is also run by the tests.
// No backticks, dollar-brace or backslashes below: this is a template literal.
const VAULT_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Secrets vault</title>
<style nonce="__NONCE__">
  :root { color-scheme: light dark; --fg: #1b1f24; --muted: #5d6670; --bg: #f6f7f9; --card: #fff; --line: #dde1e6; --ok: #1a7f37; --bad: #b42318; --accent: #1f5fbf; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e8eaed; --muted: #9aa3ad; --bg: #111418; --card: #1a1e24; --line: #2c323a; --ok: #4ac26b; --bad: #f1707a; --accent: #3d7be0; } }
  * { box-sizing: border-box; }
  body { margin: 0; font: 16px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
  main { max-width: 26rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  dl { margin: 0 0 1.25rem; padding: 1rem; background: var(--card); border: 1px solid var(--line); border-radius: 10px; display: grid; grid-template-columns: auto 1fr; gap: .35rem .9rem; }
  dl:empty { display: none; }
  dt { color: var(--muted); }
  dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .92rem; overflow-wrap: anywhere; }
  form { display: none; }
  label { display: block; margin: 0 0 .3rem; color: var(--muted); font-size: .9rem; }
  input { display: block; width: 100%; padding: .75rem .85rem; margin: 0 0 .8rem; font: inherit; border-radius: 10px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }
  input.user { display: none; }
  #holdbox { display: none; margin: 0 0 1rem; }
  label.check { display: flex; gap: .6rem; align-items: flex-start; color: var(--fg); font-size: .95rem; }
  label.check input { display: inline-block; width: auto; margin: .2rem 0 0; flex: none; }
  button { display: block; width: 100%; padding: .85rem 1rem; margin: 0 0 .6rem; font: inherit; font-weight: 600; border-radius: 10px; border: 1px solid var(--accent); background: var(--accent); color: #fff; cursor: pointer; }
  button:disabled { opacity: .5; cursor: default; }
  #msg { min-height: 1.5rem; margin: .5rem 0 0; }
  .ok { color: var(--ok); } .bad { color: var(--bad); } .muted { color: var(--muted); font-size: .9rem; }
  code.fp { display: block; margin-top: .4rem; font-size: .85rem; overflow-wrap: anywhere; color: var(--fg); }
</style>
</head>
<body>
<main>
  <h1 id="title">Secrets vault</h1>
  <dl id="facts"></dl>
  <form id="form" autocomplete="on">
    <input class="user" type="text" name="username" autocomplete="username" value="secrets-vault" readonly>
    <label for="pw" id="pwlabel">Vault password</label>
    <input id="pw" type="password" name="password" autocomplete="current-password" required>
    <div id="pw2box"><label for="pw2" id="pw2label">Repeat</label><input id="pw2" type="password" name="password2" autocomplete="new-password"></div>
    <div id="holdbox"><label class="check"><input id="hold" type="checkbox"> <span id="holdlabel"></span></label></div>
    <button id="go" type="submit">OK</button>
  </form>
  <p id="msg" role="status"></p>
  <p class="muted" id="hint"></p>
</main>
<script nonce="__NONCE__">
// CRYPTO-BEGIN
var NL = String.fromCharCode(10);
var ITER = 600000;
var enc = new TextEncoder();
function b64u(buf) {
  var s = '', b = new Uint8Array(buf);
  for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).split('+').join('-').split('/').join('_').split('=').join('');
}
function unb64u(s) {
  var t = String(s).split('-').join('+').split('_').join('/');
  while (t.length % 4) t += '=';
  return Uint8Array.from(atob(t), function (c) { return c.charCodeAt(0); });
}
function cat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
var P256 = { name: 'ECDH', namedCurve: 'P-256' };
async function boxKey(shared, epk, recipient) {
  var ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: cat(epk, recipient), info: enc.encode('secrets-vault v1') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(recipientRaw, plaintext, aad) {
  var recip = await crypto.subtle.importKey('raw', recipientRaw, P256, false, []);
  var eph = await crypto.subtle.generateKey(P256, true, ['deriveBits']);
  var shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: recip }, eph.privateKey, 256));
  var epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  var key = await boxKey(shared, epk, recipientRaw);
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, key, plaintext));
  return { v: 1, epk: b64u(epk), iv: b64u(iv), ct: b64u(ct) };
}
async function openBox(priv, privPubRaw, box, aad) {
  if (!box || box.v !== 1) throw new Error('unsupported box');
  var epk = unb64u(box.epk);
  var pub = await crypto.subtle.importKey('raw', epk, P256, false, []);
  var shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
  var key = await boxKey(shared, epk, privPubRaw);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(box.iv), additionalData: aad }, key, unb64u(box.ct)));
}
async function passwordKey(password, salt, iter) {
  var base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iter }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function lockAAD(pub) { return enc.encode('secrets-vault key v1' + NL + pub); }
async function fingerprintOf(key) { return 'SHA256:' + b64u(await crypto.subtle.digest('SHA-256', unb64u(key))); }
// The locked vault key: the PKCS#8 private key and the trusted hosts
// ({name: Ed25519 public key}), encrypted with the vault password.
async function lock(pub, content, password) {
  var salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  var k = await passwordKey(password, salt, ITER);
  var plain = enc.encode(JSON.stringify(content));
  var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: lockAAD(pub) }, k, plain));
  plain.fill(0);
  return { kdf: 'pbkdf2-sha256', iter: ITER, salt: b64u(salt), iv: b64u(iv), ct: b64u(ct) };
}
async function unlock(vault, password) {
  var l = vault.locked;
  if (!l || l.kdf !== 'pbkdf2-sha256' || !(l.iter >= 100000)) throw new Error('unsupported vault');
  var k = await passwordKey(password, unb64u(l.salt), l.iter);
  var plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(l.iv), additionalData: lockAAD(vault.key) }, k, unb64u(l.ct)));
  } catch (e) { var err = new Error('wrong password'); err.wrongPassword = true; throw err; }
  var content = JSON.parse(new TextDecoder().decode(plain));
  plain.fill(0);
  if (!content || typeof content.key !== 'string' || !content.hosts || typeof content.hosts !== 'object') throw new Error('unsupported vault');
  return content;
}
// A second derivation of the password, with its own salt: the Worker keeps
// only its hash, and asks for it before it accepts a changed lock.
async function passwordProof(password, salt) {
  var base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITER }, base, 256));
}
async function createVault(password, host, hostKey) {
  var kp = await crypto.subtle.generateKey(P256, true, ['deriveBits']);
  var pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
  var hosts = {}; hosts[host] = hostKey;
  var content = { key: b64u(await crypto.subtle.exportKey('pkcs8', kp.privateKey)), hosts: hosts };
  var authSalt = crypto.getRandomValues(new Uint8Array(16));
  var proof = await passwordProof(password, authSalt);
  return { key: pub, locked: await lock(pub, content, password),
    auth: { salt: b64u(authSalt), hash: b64u(await crypto.subtle.digest('SHA-256', proof)) } };
}
async function trustHost(vault, password, host, hostKey) {
  var content = await unlock(vault, password);
  content.hosts[host] = hostKey;
  return { locked: await lock(vault.key, content, password), proof: b64u(await passwordProof(password, unb64u(vault.auth_salt))), base: vault.locked.iv };
}
// What the host signed (see RequestMessage in internal/vault/crypto.go):
// length-prefixed lines, the box as a SHA-256 hash.
async function requestMessage(info) {
  var h = b64u(await crypto.subtle.digest('SHA-256', enc.encode(info.box.epk + '.' + info.box.iv + '.' + info.box.ct)));
  var fields = ['secrets-vault request v1', info.host, info.user, info.name, info.reason || '', info.detail || '', info.reply_key, info.nonce, h];
  // A request that asks for a hold is v2, with the hold terms last.
  if (info.hold) { fields[0] = 'secrets-vault request v2'; fields.push(info.hold); }
  var out = new Uint8Array(0);
  for (var i = 0; i < fields.length; i++) {
    var f = enc.encode(fields[i]);
    out = cat(cat(cat(out, enc.encode(f.length + ':')), f), enc.encode(NL));
  }
  return out;
}
// hold: the approver agrees to let the host hold the secret on the signed
// terms (info.hold). The seal then says so, and the Worker cannot change it.
async function releaseSecret(vault, password, info, hold) {
  var content = await unlock(vault, password);
  var hostKey = content.hosts[info.host];
  if (!hostKey) { var e1 = new Error('this server is not trusted by the vault'); e1.untrusted = true; throw e1; }
  var pk = await crypto.subtle.importKey('raw', unb64u(hostKey), { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, pk, unb64u(info.sig), await requestMessage(info)))) {
    var e2 = new Error('the request is not signed by this server'); e2.badSignature = true; throw e2;
  }
  var pkcs8 = unb64u(content.key);
  var priv = await crypto.subtle.importKey('pkcs8', pkcs8, P256, false, ['deriveBits']);
  pkcs8.fill(0);
  var secret = await openBox(priv, unb64u(vault.key), info.box, enc.encode('secrets-vault secret v1' + NL + info.host + NL + info.name));
  var held = !!(hold && info.hold);
  var aad = held ? 'secrets-vault release v2' + NL + info.nonce + NL + info.name + NL + info.hold
    : 'secrets-vault release v1' + NL + info.nonce + NL + info.name;
  var sealed = await seal(unb64u(info.reply_key), secret, enc.encode(aad));
  secret.fill(0);
  return { sealed: sealed, held: held, proof: b64u(await passwordProof(password, unb64u(vault.auth_salt))) };
}
// CRYPTO-END
(function () {
  var KIND = '__KIND__';
  var id = location.pathname.split('/').pop();
  var T = {
    en: {
      setup: 'Create the secrets vault', trust: 'Trust a server for the vault', release: 'Release a secret',
      server: 'Server', server_key: 'Server key', user: 'User', secret: 'Secret',
      reason: 'Reason', command: 'Command', vault: 'Vault', pw: 'Vault password', pw2: 'Repeat the password',
      create: 'Create vault', trust_btn: 'Trust server', release_btn: 'Release',
      created: 'Vault created. Check that the server shows the same fingerprint:', trusted: 'Server trusted. You can close this page.',
      approved: 'Released. You can close this page.', denied: 'This request was denied.', expired: 'This request has expired.',
      done: 'This request was already answered.', wrong: 'Wrong password.', mismatch: 'The passwords differ.',
      untrusted: 'This server is not trusted by the vault. Run "vault pin" on it first.',
      badsig: 'This request was not signed by the server it claims to come from. Do not release it.',
      short: 'Use at least 16 characters; let your password manager generate one.', busy: 'Working...', failed: 'Failed: ',
      hint_setup: 'Save this password in your password manager. Without it, the secrets cannot be recovered. Check that the server key matches what the server printed.',
      hint_trust: 'Only continue if you just ran "vault pin" on this server, and the server key matches what it printed.',
      hint_release: 'Only release what you started yourself just now. The secret goes only to this request.',
      hold: 'Hold', hold_label: 'Let the server hold it for this session: no new approval while it is used at least every {idle}, for at most {max}. Every reuse is reported to you, with Revoke.',
      approved_held: 'Released and held. Each reuse is reported on Telegram. You can close this page.'
    },
    nl: {
      setup: 'Kluis voor geheimen aanmaken', trust: 'Server toevoegen aan de kluis', release: 'Geheim vrijgeven',
      server: 'Server', server_key: 'Serversleutel', user: 'Gebruiker', secret: 'Geheim',
      reason: 'Reden', command: 'Opdracht', vault: 'Kluis', pw: 'Kluiswachtwoord', pw2: 'Herhaal het wachtwoord',
      create: 'Kluis aanmaken', trust_btn: 'Server vertrouwen', release_btn: 'Vrijgeven',
      created: 'Kluis aangemaakt. Controleer of de server dezelfde vingerafdruk toont:', trusted: 'Server vertrouwd. Je kunt deze pagina sluiten.',
      approved: 'Vrijgegeven. Je kunt deze pagina sluiten.', denied: 'Dit verzoek is geweigerd.', expired: 'Dit verzoek is verlopen.',
      done: 'Dit verzoek is al beantwoord.', wrong: 'Onjuist wachtwoord.', mismatch: 'De wachtwoorden verschillen.',
      untrusted: 'Deze server wordt niet door de kluis vertrouwd. Draai daar eerst "vault pin".',
      badsig: 'Dit verzoek is niet ondertekend door de server waar het van zegt te komen. Niet vrijgeven.',
      short: 'Gebruik minstens 16 tekens; laat je wachtwoordmanager er een maken.', busy: 'Bezig...', failed: 'Mislukt: ',
      hint_setup: 'Bewaar dit wachtwoord in je wachtwoordmanager. Zonder dit wachtwoord zijn de geheimen niet terug te halen. Controleer of de serversleutel klopt met wat de server toonde.',
      hint_trust: 'Ga alleen verder als je net zelf "vault pin" op deze server draaide en de serversleutel klopt met wat de server toonde.',
      hint_release: 'Geef alleen vrij wat je zelf net hebt gestart. Het geheim gaat alleen naar dit verzoek.',
      hold: 'Vasthouden', hold_label: 'Laat de server het vasthouden voor deze sessie: geen nieuwe goedkeuring zolang het minstens elke {idle} wordt gebruikt, hooguit {max}. Elk hergebruik meldt zich bij jou, met Intrekken.',
      approved_held: 'Vrijgegeven en vastgehouden. Elk hergebruik krijg je op Telegram. Je kunt deze pagina sluiten.'
    }
  };
  var t = T.en;
  var $ = function (s) { return document.getElementById(s); };
  function msg(text, cls) { var m = $('msg'); m.textContent = text; m.className = cls || ''; }
  function fact(k, v) {
    if (!v) return;
    var dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = k; dd.textContent = v;
    $('facts').append(dt, dd);
  }
  function closed(status) { $('form').style.display = 'none'; msg(t[status] || t.done, status === 'approved' || status === 'approved_held' ? 'ok' : 'bad'); }
  function dur(s, nl) {
    if (s % 3600 === 0) return (s / 3600) + (nl ? ' uur' : ' h');
    if (s % 60 === 0) return (s / 60) + ' min';
    return s + ' s';
  }
  function holdTerms(h) {
    var m = /^idle=([1-9][0-9]{0,4}),max=([1-9][0-9]{0,4})$/.exec(h || '');
    return m ? { idle: Number(m[1]), max: Number(m[2]) } : null;
  }
  async function post(body) {
    var res = await fetch('/v1/vault/page/' + KIND + '/' + id, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || res.status);
    return data;
  }
  function problem(text) { var e = new Error(text); e.shown = true; return e; }
  async function submit(info) {
    var pw = $('pw').value;
    $('go').disabled = true; msg(t.busy);
    try {
      if (KIND === 'setup') {
        if (pw.length < 16) throw problem(t.short);
        if (pw !== $('pw2').value) throw problem(t.mismatch);
        var v = await createVault(pw, info.host, info.host_key);
        var r = await post(v);
        if (r.status !== 'approved') return closed(r.status);
        $('form').style.display = 'none';
        msg(t.created, 'ok');
        var c = document.createElement('code'); c.className = 'fp'; c.textContent = await fingerprintOf(v.key);
        $('msg').append(c);
      } else if (KIND === 'trust') {
        var r1 = await post(await trustHost(info.vault, pw, info.host, info.host_key));
        if (r1.status === 'approved') { $('form').style.display = 'none'; msg(t.trusted, 'ok'); } else closed(r1.status);
      } else {
        var rel = await releaseSecret(info.vault, pw, info, $('hold').checked);
        var st = (await post(rel)).status;
        closed(st === 'approved' && rel.held ? 'approved_held' : st);
      }
    } catch (e) {
      $('go').disabled = false;
      msg(e && e.wrongPassword ? t.wrong : e && e.untrusted ? t.untrusted : e && e.badSignature ? t.badsig :
        e && e.shown ? e.message : t.failed + ((e && e.message) || e), 'bad');
    }
  }
  async function main() {
    var res = await fetch('/v1/vault/page/' + KIND + '/' + id);
    if (!res.ok) { msg(t.expired, 'bad'); return; }
    var info = await res.json();
    t = T[info.lang] || T.en;
    document.documentElement.lang = info.lang === 'nl' ? 'nl' : 'en';
    $('title').textContent = t[KIND];
    $('hint').textContent = t['hint_' + KIND];
    $('pwlabel').textContent = t.pw; $('pw2label').textContent = t.pw2;
    fact(t.server, info.host);
    if (KIND === 'release') {
      fact(t.secret, info.name); fact(t.user, info.user); fact(t.reason, info.reason); fact(t.command, info.detail);
      fact(t.vault, info.vault.fingerprint);
      var terms = holdTerms(info.hold);
      if (terms) {
        var nl = info.lang === 'nl';
        fact(t.hold, dur(terms.idle, nl) + ' / max ' + dur(terms.max, nl));
        $('holdlabel').textContent = t.hold_label.replace('{idle}', dur(terms.idle, nl)).replace('{max}', dur(terms.max, nl));
        $('hold').checked = true;
        $('holdbox').style.display = 'block';
      }
    } else {
      fact(t.server_key, info.host_fp);
      if (info.vault) fact(t.vault, info.vault.fingerprint);
    }
    if (KIND === 'setup') {
      $('pw').setAttribute('autocomplete', 'new-password');
      $('pw').setAttribute('minlength', '16');
      $('go').textContent = t.create;
    } else {
      // Remove, not just hide, the repeat field: a "new-password" field in
      // the form makes Android autofill offer to save the password again.
      $('pw2box').remove();
      $('go').textContent = KIND === 'trust' ? t.trust_btn : t.release_btn;
    }
    if (info.status !== 'pending') return closed(info.status);
    $('form').style.display = 'block';
    $('form').addEventListener('submit', function (ev) { ev.preventDefault(); submit(info); });
    $('pw').focus();
  }
  main().catch(function (e) { msg(t.failed + ((e && e.message) || e), 'bad'); });
})();
</script>
</body>
</html>
`;
