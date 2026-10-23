// Request Access -- Cloudflare Worker.
//
// The Worker is the only party that can approve anything: it receives access
// requests from enrolled hosts, asks the approver on Telegram, and returns a
// grant signed with a key that never leaves the Worker. Hosts only hold the
// matching public key, so a compromised host cannot mint its own approvals.
//
// All state lives in a single Durable Object (strongly consistent, unlike KV,
// whose cross-location reads can lag by up to a minute).

const VERSION = '0.1.0';
const MAX_SKEW = 60; // seconds between a signed request's timestamp and now
const NONCE_TTL = 600; // seconds a request nonce is remembered (replay protection)
const MAX_PENDING_ENROLLMENTS = 3;

const DEFAULT_CONFIG = {
  lang: 'en',
  request_timeout: 60, // seconds an approval request stays open
  windows: { ssh: 900, sudo: 900 }, // seconds a grant stays valid, per service or "host/service"
  default_window: 900,
  max_window: 86400,
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

    // Everything below requires a signed request.
    const body = m === 'GET' ? '' : await request.text();
    const caller = await this.authenticate(request, url, body);

    if (m === 'POST' && p === '/v1/access') return this.createAccess(caller, body);
    if (m === 'GET' && (mm = p.match(/^\/v1\/access\/([0-9a-f]{32})$/))) return this.accessStatus(caller, mm[1], url);
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

  async createAccess(caller, body) {
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
    };
    const t = texts(cfg.lang);
    const lines = [
      `🔐 <b>${esc(t.title[service] || service)}</b> ${esc(t.on)} <b>${esc(req.host)}</b>`,
      `${esc(t.user)}: <code>${esc(user)}</code>`,
    ];
    if (req.rhost) lines.push(`${esc(t.from)}: <code>${esc(req.rhost)}</code>`);
    if (req.tty) lines.push(`TTY: <code>${esc(req.tty)}</code>`);
    if (req.detail) lines.push(`<code>${esc(req.detail)}</code>`);
    const sent = await this.telegram('sendMessage', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      text: lines.join('\n'),
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            { text: `✅ ${t.allow} ${fmtDuration(req.window, cfg.lang)}`, callback_data: `r:${id}:a` },
            { text: `☑️ ${t.once}`, callback_data: `r:${id}:o` },
          ],
          [{ text: `❌ ${t.deny}`, callback_data: `r:${id}:d` }],
        ],
      },
    });
    req.message_id = sent && sent.message_id;
    req.text = lines.join('\n');
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
        return json(out);
      }
      await sleep(1000);
    }
  }

  async decideAccess(req, choice, from) {
    if (req.status !== 'pending') return req.status;
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
      const window = choice === 'o' ? 30 : req.window;
      const payload = {
        v: 1,
        kind: 'grant',
        id: req.id,
        host: req.host,
        service: req.service,
        user: req.user,
        nonce: req.nonce,
        once: choice === 'o',
        iat: now(),
        exp: now() + window,
      };
      req.grant = await this.sign(payload);
      req.status = 'approved';
      const label = choice === 'o' ? t.once_note : `${t.valid_for} ${fmtDuration(window, cfg.lang)}`;
      await this.editDecision(req, `✅ ${t.approved_by} ${who(from)} (${label})`);
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

  async editDecision(req, line) {
    if (!req.message_id) return;
    await this.telegram('editMessageText', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      message_id: req.message_id,
      text: `${req.text}\n\n${esc(line)}`,
      parse_mode: 'HTML',
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
    const approvers = String(this.env.APPROVER_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
    const t = texts((await this.config()).lang);
    if (!approvers.includes(String(cq.from && cq.from.id))) {
      await this.telegram('answerCallbackQuery', { callback_query_id: cq.id, text: t.not_allowed });
      return json({ ok: true });
    }
    const m = /^([rex]):([0-9a-f]{32}):([aod])$/.exec(cq.data || '');
    let result = 'unknown';
    if (m) {
      const [, kind, id, choice] = m;
      if (kind === 'r') {
        const req = await this.storage.get('req:' + id);
        if (req) result = await this.decideAccess(req, choice, cq.from);
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

  async editMsg(obj, line) {
    if (!obj.message_id) return;
    await this.telegram('editMessageText', {
      chat_id: this.env.TELEGRAM_CHAT_ID,
      message_id: obj.message_id,
      text: `${obj.text}\n\n${esc(line)}`,
      parse_mode: 'HTML',
    });
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
    for (const prefix of ['req:', 'enr:', 'act:']) {
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
  return out;
}

function diffConfig(a, b) {
  const flat = (c) => {
    const o = { lang: c.lang, request_timeout: c.request_timeout, default_window: c.default_window, max_window: c.max_window };
    for (const [k, v] of Object.entries(c.windows || {})) o[`windows.${k}`] = v;
    return o;
  };
  const fa = flat(a), fb = flat(b);
  const keys = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].sort();
  const lines = keys.filter((k) => fa[k] !== fb[k]).map((k) => `${k}: ${fa[k] ?? '-'} → ${fb[k] ?? '-'}`);
  return lines.length ? lines.join('\n') : '(no changes)';
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
    on: 'on', user: 'User', from: 'From', server: 'Server',
    allow: 'Allow', once: 'Just this once', deny: 'Deny',
    approved_by: 'Approved by', denied_by: 'Denied by', valid_for: 'valid for', once_note: 'this once',
    expired: 'Expired, no answer in time', not_allowed: 'You are not an approver.',
    enroll: 'New server wants to enroll', reenroll: 'Server wants to replace its key', fingerprint: 'Key fingerprint',
    compare: 'Compare this with the fingerprint shown on the server.', add: 'Add server', added_by: 'Added by',
    admin_change: 'Configuration change', remove_host: 'Remove server', set_config: 'Change settings', confirm: 'Confirm',
    status: { approved: 'Approved', denied: 'Denied', expired: 'Already expired', unknown: 'Unknown request' },
  };
  if (lang !== 'nl') return en;
  return {
    title: { ssh: 'SSH-login', sudo: 'sudo' },
    on: 'op', user: 'Gebruiker', from: 'Vanaf', server: 'Server',
    allow: 'Toestaan', once: 'Alleen deze keer', deny: 'Weigeren',
    approved_by: 'Goedgekeurd door', denied_by: 'Geweigerd door', valid_for: 'geldig', once_note: 'alleen deze keer',
    expired: 'Verlopen, niet op tijd beantwoord', not_allowed: 'Je mag dit niet goedkeuren.',
    enroll: 'Nieuwe server wil zich aanmelden', reenroll: 'Server wil een nieuwe sleutel', fingerprint: 'Vingerafdruk sleutel',
    compare: 'Vergelijk dit met de vingerafdruk op de server.', add: 'Server toevoegen', added_by: 'Toegevoegd door',
    admin_change: 'Configuratiewijziging', remove_host: 'Server verwijderen', set_config: 'Instellingen wijzigen', confirm: 'Bevestigen',
    status: { approved: 'Goedgekeurd', denied: 'Geweigerd', expired: 'Al verlopen', unknown: 'Onbekend verzoek' },
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
