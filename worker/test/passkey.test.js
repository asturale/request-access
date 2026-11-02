// End-to-end passkey approval: the real Go binary against the Worker in
// Miniflare, with a software passkey playing the approver's phone. It opens
// the links the fake Telegram receives, just like a person would.
//
// Needs the binary at test/bin/request-access (see Makefile `e2e`).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { Miniflare } from 'miniflare';

const BIN = new URL('./bin/request-access', import.meta.url).pathname;
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const APPROVER = 4242;
const SECRET = 'e2e-webhook-secret';

let mf, tg, workerURL;
let nextTap = null; // callback button the fake approver taps, if any
let onLink = null; // what the "phone" does with a link button
const messages = [];
const answers = [];
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ra-passkey-'));
const env = {
  ...process.env,
  REQUEST_ACCESS_CONFIG_DIR: path.join(tmp, 'etc'),
  REQUEST_ACCESS_STATE_DIR: path.join(tmp, 'var'),
};
const signing = crypto.generateKeyPairSync('ed25519');

// A software passkey.
class Phone {
  constructor() {
    this.id = b64u(crypto.randomBytes(16));
    this.key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  }
  clientData(type, challenge) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: workerURL, crossOrigin: false }));
  }
  async register(link) {
    const id = link.split('/').pop();
    const info = await (await fetch(`${workerURL}/v1/register/${id}`)).json();
    const res = await fetch(`${workerURL}/v1/register/${id}`, {
      method: 'POST',
      body: JSON.stringify({ registration: {
        id: this.id, alg: -7,
        public_key: b64u(this.key.publicKey.export({ type: 'spki', format: 'der' })),
        client_data_json: b64u(this.clientData('webauthn.create', info.challenge)),
      } }),
    });
    return res.json();
  }
  // signer: a different key, to play a forged approval.
  async approve(link, choice, { signer = this.key.privateKey, flags = 0x05 } = {}) {
    const id = link.split('/').pop();
    const info = await (await fetch(`${workerURL}/v1/approve/${id}`)).json();
    const authData = Buffer.concat([sha256(info.rp_id), Buffer.from([flags, 0, 0, 0, 0])]);
    const cd = this.clientData('webauthn.get', info.challenges[choice]);
    const sig = crypto.sign('sha256', Buffer.concat([authData, sha256(cd)]), signer);
    const res = await fetch(`${workerURL}/v1/approve/${id}`, {
      method: 'POST',
      body: JSON.stringify({ choice, assertion: {
        id: this.id, client_data_json: b64u(cd), authenticator_data: b64u(authData), signature: b64u(sig),
      } }),
    });
    return { info, status: res.status, body: await res.json() };
  }
}
const phone = new Phone();

before(async () => {
  tg = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const method = req.url.split('/').pop();
      const params = JSON.parse(body || '{}');
      res.setHeader('Content-Type', 'application/json');
      if (method === 'sendMessage') {
        const kb = (params.reply_markup && params.reply_markup.inline_keyboard || []).flat();
        messages.push({ text: params.text, buttons: kb });
        const link = kb.find((b) => b.url);
        if (link && onLink) setTimeout(() => onLink(link.url), 300);
        // Reports of a window used again (only Revoke) are left alone.
        if (kb.length && kb.every((b) => (b.callback_data || '').startsWith('g:'))) {
          return res.end(JSON.stringify({ ok: true, result: { message_id: messages.length } }));
        }
        const cb = nextTap && kb.find((b) => b.callback_data && b.callback_data.endsWith(':' + nextTap));
        const data = cb ? cb.callback_data : nextTap && kb.find((b) => b.callback_data) &&
          kb.find((b) => b.callback_data).callback_data.replace(/:[aod]$/, ':' + nextTap);
        if (data) setTimeout(() => tap(data), 300);
        return res.end(JSON.stringify({ ok: true, result: { message_id: messages.length } }));
      }
      if (method === 'answerCallbackQuery') answers.push(params.text);
      res.end(JSON.stringify({ ok: true, result: true }));
    });
  });
  await new Promise((r) => tg.listen(0, '127.0.0.1', r));
  mf = new Miniflare({
    modules: true,
    scriptPath: new URL('../src/index.js', import.meta.url).pathname,
    compatibilityDate: '2025-09-01',
    durableObjects: { STATE: 'State' },
    host: '127.0.0.1',
    port: 0,
    bindings: {
      TELEGRAM_API: `http://127.0.0.1:${tg.address().port}`,
      TELEGRAM_BOT_TOKEN: 'x',
      TELEGRAM_CHAT_ID: String(APPROVER),
      TELEGRAM_WEBHOOK_SECRET: SECRET,
      APPROVER_IDS: String(APPROVER),
      SIGNING_KEY: b64u(signing.privateKey.export({ format: 'der', type: 'pkcs8' })),
      ADMIN_KEYS: '',
    },
  });
  // Passkeys need https or http://localhost; Miniflare listens on 127.0.0.1.
  workerURL = `http://localhost:${new URL((await mf.ready).toString()).port}`;
});

after(async () => {
  await mf.dispose();
  tg.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function tap(data) {
  await fetch(workerURL + '/telegram/webhook', {
    method: 'POST',
    headers: { 'X-Telegram-Bot-Api-Secret-Token': SECRET, 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query: { id: 'cq', from: { id: APPROVER, username: 'tester' }, data } }),
  });
}

function run(args, extraEnv = {}) {
  return new Promise((resolve) => {
    execFile(BIN, args, { env: { ...env, ...extraEnv }, timeout: 120000 }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code ?? 1 : 0, stdout, stderr });
    });
  });
}

const sudo = (user) => run(['pam'], { PAM_TYPE: 'account', PAM_SERVICE: 'sudo', PAM_USER: 'root', PAM_RUSER: user });
const ssh = (user) => run(['pam'], { PAM_TYPE: 'account', PAM_SERVICE: 'sshd', PAM_USER: user, PAM_RHOST: '10.9.9.9' });
const config = () => JSON.parse(fs.readFileSync(path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'config.json')));

test('enroll', async () => {
  nextTap = 'a';
  const r = await run(['enroll', '--url', workerURL, '--name', 'web1']);
  assert.equal(r.code, 0, r.stderr);
  nextTap = null;
});

test('passkey add: link on Telegram, phone creates it, host pins the key', async () => {
  let reg;
  onLink = async (url) => (reg = await phone.register(url));
  const r = await run(['passkey', 'add', '--label', 'phone']);
  onLink = null;
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.equal(reg.status, 'approved');
  const msg = messages.at(-1);
  assert.match(msg.text, /web1/);
  assert.match(msg.buttons[0].url, /\/register\/[0-9a-f]{32}$/);
  const cfg = config();
  assert.equal(cfg.passkey.rp_id, 'localhost');
  assert.equal(cfg.passkey.required, false);
  assert.equal(cfg.passkey.credentials[0].id, phone.id);
  const fp = 'SHA256:' + b64u(sha256(phone.key.publicKey.export({ type: 'spki', format: 'der' })));
  assert.ok(r.stdout.includes(fp), 'fingerprint printed');
  assert.match(r.stdout, /--import ra-passkey:/);

  const page = await fetch(msg.buttons[0].url);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /script-src 'nonce-/);
});

test('approve with the passkey, then served from the cache', async () => {
  let res;
  onLink = async (url) => (res = await phone.approve(url, 'window'));
  let r = await sudo('alice');
  onLink = null;
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.equal(res.body.status, 'approved');
  assert.equal(res.info.user, 'alice');
  const kb = messages.at(-1).buttons;
  assert.ok(kb.some((b) => b.url) && kb.some((b) => /:a$/.test(b.callback_data || '')), 'passkey and tap buttons while optional');
  const before = messages.length;
  r = await sudo('alice');
  assert.equal(r.code, 0);
  assert.equal(messages.length, before + 1, 'cached, with one silent report');
  assert.ok(messages.at(-1).buttons.every((b) => b.callback_data.startsWith('g:')), 'the report only offers Revoke');
  r = await run(['status']);
  assert.match(r.stdout, /sudo alice \(valid for .*passkey\)/);
});

test('"just this once" is signed and not cached', async () => {
  onLink = async (url) => phone.approve(url, 'once');
  let r = await sudo('bob');
  assert.equal(r.code, 0, r.stdout);
  const before = messages.length;
  onLink = null;
  nextTap = 'd';
  r = await sudo('bob');
  nextTap = null;
  assert.notEqual(r.code, 0);
  assert.equal(messages.length, before + 1, 'asked again');
});

test('optional mode: a Telegram tap still works', async () => {
  nextTap = 'a';
  const r = await sudo('carol');
  nextTap = null;
  assert.equal(r.code, 0, r.stdout);
});

test('require on: taps no longer approve, old tap grants stop counting', async () => {
  let r = await run(['passkey', 'require', 'on']);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(config().passkey.required, true);

  // carol's cached grant came from a tap; she must ask again. The approver
  // taps Allow (refused by the Worker), then Deny.
  nextTap = 'a';
  const p = sudo('carol');
  await new Promise((res) => setTimeout(res, 1500));
  const kb = messages.at(-1).buttons;
  assert.ok(!kb.some((b) => /:[ao]$/.test(b.callback_data || '')), 'no tap-to-allow buttons');
  await tap(`r:${kb.find((b) => b.url).url.split('/').pop()}:a`);
  assert.match(answers.at(-1), /passkey/);
  await tap(`r:${kb.find((b) => b.url).url.split('/').pop()}:d`);
  nextTap = null;
  r = await p;
  assert.notEqual(r.code, 0);
  assert.match(r.stdout, /denied/);

  // alice's passkey grant still counts.
  r = await sudo('alice');
  assert.equal(r.code, 0);
});

test('a forged signature is refused by the host', async () => {
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  let res;
  onLink = async (url) => (res = await phone.approve(url, 'window', { signer: other.privateKey }));
  const r = await sudo('mallory');
  onLink = null;
  // The Worker cannot tell (it has no keys) and reports approved...
  assert.equal(res.body.status, 'approved');
  // ...but the host checks the signature itself.
  assert.notEqual(r.code, 0);
  assert.match(r.stdout, /signature does not verify/);
});

test('without user verification the host refuses', async () => {
  onLink = async (url) => phone.approve(url, 'window', { flags: 0x01 });
  const r = await sudo('dave');
  onLink = null;
  assert.notEqual(r.code, 0);
  assert.match(r.stdout, /not verified/);
});

test('the Worker rejects a signature for the wrong challenge', async () => {
  let res;
  onLink = async (url) => {
    const id = url.split('/').pop();
    const info = await (await fetch(`${workerURL}/v1/approve/${id}`)).json();
    const cd = phone.clientData('webauthn.get', info.challenges.once);
    const r = await fetch(`${workerURL}/v1/approve/${id}`, {
      method: 'POST',
      body: JSON.stringify({ choice: 'window', assertion: { id: phone.id, client_data_json: b64u(cd), authenticator_data: b64u(Buffer.alloc(37)), signature: 'AA' } }),
    });
    res = r.status;
    await tap(`r:${id}:d`);
  };
  const r = await sudo('erin');
  onLink = null;
  assert.equal(res, 400);
  assert.notEqual(r.code, 0);
});

test('SSH + sudo with the passkey: one signature, both windows', async () => {
  let res;
  onLink = async (url) => (res = await phone.approve(url, 'both'));
  let r = await ssh('frank');
  onLink = null;
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.ok(res.info.challenges.both && res.info.window_sudo > 0, 'the page offers it for SSH');
  const before = messages.length;
  r = await sudo('frank');
  assert.equal(r.code, 0, 'sudo came with the SSH approval');
  assert.ok(!messages.slice(before).some((m) => m.buttons.some((b) => b.url)), 'no new approval link');
  r = await run(['status']);
  assert.match(r.stdout, /sudo frank \(valid for .*passkey\)/);
});

test('a passkey approval of SSH alone does not cover sudo', async () => {
  onLink = async (url) => phone.approve(url, 'window');
  let r = await ssh('gina');
  assert.equal(r.code, 0, r.stdout);
  // The Worker will not take the plain signature as "both" either.
  let bad;
  onLink = async (url) => {
    const id = url.split('/').pop();
    const info = await (await fetch(`${workerURL}/v1/approve/${id}`)).json();
    const cd = phone.clientData('webauthn.get', info.challenges.window);
    bad = (await fetch(`${workerURL}/v1/approve/${id}`, {
      method: 'POST',
      body: JSON.stringify({ choice: 'both', assertion: { id: phone.id, client_data_json: b64u(cd), authenticator_data: b64u(Buffer.alloc(37)), signature: 'AA' } }),
    })).status;
    await tap(`r:${id}:d`);
  };
  r = await sudo('gina');
  onLink = null;
  assert.equal(bad, 400, 'no "both" challenge for a sudo request, nor a mismatched one');
  assert.notEqual(r.code, 0, 'sudo still needs its own approval');
});

test('the last passkey cannot be removed while required; export round-trips', async () => {
  let r = await run(['passkey', 'remove', 'phone']);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /last passkey/);
  r = await run(['passkey', 'export']);
  assert.match(r.stdout, /^ra-passkey:/);
  const line = r.stdout.trim();
  r = await run(['passkey', 'add', '--import', line]);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /already registered/);
  r = await run(['passkey', 'require', 'off']);
  assert.equal(r.code, 0);
  r = await run(['passkey', 'remove', 'phone']);
  assert.equal(r.code, 0, r.stderr);
  // alice's grant came from the removed passkey: it no longer counts.
  const before = messages.length;
  nextTap = 'd';
  r = await sudo('alice');
  nextTap = null;
  assert.notEqual(r.code, 0);
  assert.equal(messages.length, before + 1, 'asked again');
  r = await run(['passkey', 'add', '--import', line]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(config().passkey.credentials[0].id, phone.id);
});

test('a host without passkeys keeps the plain flow', async () => {
  const cfg = config();
  delete cfg.passkey;
  fs.writeFileSync(path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'config.json'), JSON.stringify(cfg));
  nextTap = 'a';
  const r = await sudo('frank');
  nextTap = null;
  assert.equal(r.code, 0);
  assert.ok(!messages.at(-1).buttons.some((b) => b.url));
});
