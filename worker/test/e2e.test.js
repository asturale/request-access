// End-to-end: the real Go binary (enroll, PAM check, grant cache, admin
// config) against the Worker in Miniflare, with a fake Telegram that
// "taps" a button on every message it receives.
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
const APPROVER = 4242;
const SECRET = 'e2e-webhook-secret';

let mf, tg, workerURL;
let nextTap = 'a'; // what the fake approver taps next
const messages = [];
const sent = []; // every sendMessage, with its parameters
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ra-e2e-'));
const env = {
  ...process.env,
  REQUEST_ACCESS_CONFIG_DIR: path.join(tmp, 'etc'),
  REQUEST_ACCESS_STATE_DIR: path.join(tmp, 'var'),
  REQUEST_ACCESS_ADMIN_CONFIG: path.join(tmp, 'admin.json'),
};
const signing = crypto.generateKeyPairSync('ed25519');
const admin = crypto.generateKeyPairSync('ed25519');

before(async () => {
  tg = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const method = req.url.split('/').pop();
      const params = JSON.parse(body || '{}');
      res.setHeader('Content-Type', 'application/json');
      if (method === 'sendMessage') {
        const kb = params.reply_markup && params.reply_markup.inline_keyboard;
        messages.push(params.text + (kb ? '\n[' + kb.flat().map((b) => b.text).join('] [') + ']' : ''));
        sent.push(params);
        // Reports of a window being used again only offer Revoke; the fake
        // approver leaves those alone (the tests tap them on purpose).
        const report = kb && kb.flat().every((b) => (b.callback_data || '').startsWith('g:'));
        if (kb && nextTap && !report) {
          const data = kb.flat().map((b) => b.callback_data).find((d) => d.endsWith(':' + nextTap)) ||
            kb.flat()[0].callback_data.replace(/:[aod]$/, ':' + nextTap);
          setTimeout(() => tap(data), 300);
        }
        return res.end(JSON.stringify({ ok: true, result: { message_id: messages.length } }));
      }
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
      ADMIN_KEYS: admin.publicKey.export({ format: 'jwk' }).x,
    },
  });
  workerURL = (await mf.ready).toString().replace(/\/$/, '');
  fs.writeFileSync(env.REQUEST_ACCESS_ADMIN_CONFIG, JSON.stringify({
    url: workerURL,
    server_key: signing.publicKey.export({ format: 'jwk' }).x,
    key_id: 'admin:0',
    key: admin.privateKey.export({ format: 'jwk' }).d,
  }));
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

const pam = (service, user, extra = {}) =>
  run(['pam'], { PAM_TYPE: 'account', PAM_SERVICE: service, PAM_USER: user, PAM_RHOST: '10.1.2.3', ...extra });

test('enroll waits for approval and writes the host config', async () => {
  nextTap = 'a';
  const r = await run(['enroll', '--url', workerURL, '--name', 'web1']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /Enrolled as "web1"/);
  const cfg = JSON.parse(fs.readFileSync(path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'config.json')));
  assert.equal(cfg.name, 'web1');
  assert.match(messages.at(-1), /web1/);
});

const grantFile = (service, user) => path.join(env.REQUEST_ACCESS_STATE_DIR, 'grants', `${service}__${user}.json`);
const grantId = (service, user) => JSON.parse(Buffer.from(JSON.parse(fs.readFileSync(grantFile(service, user))).payload, 'base64url')).id;

test('ssh login: approved, then served from the cache with a silent report', async () => {
  nextTap = 'a';
  const before = messages.length;
  let r = await pam('sshd', 'alice');
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.equal(messages.length, before + 1);
  assert.match(messages.at(-1), /alice/);
  r = await pam('sshd', 'alice');
  assert.equal(r.code, 0);
  assert.equal(messages.length, before + 2, 'second login used the cached grant and reported it');
  const report = sent.at(-1);
  assert.equal(report.disable_notification, true, 'the report is silent');
  assert.match(report.text, /approved window used again/);
  assert.match(report.text, /10\.1\.2\.3/);
  assert.deepEqual(report.reply_markup.inline_keyboard.flat().map((b) => b.callback_data), [`g:${grantId('ssh', 'alice')}:d`]);
  // Within the minute: no new message, the use is counted.
  r = await pam('sshd', 'alice');
  assert.equal(r.code, 0);
  assert.equal(messages.length, before + 2, 'at most one report a minute');
});

test('a revoked window is dropped and asked for again', async () => {
  const id = grantId('ssh', 'alice');
  await tap(`g:${id}:d`);
  nextTap = 'd';
  const before = messages.length;
  const r = await pam('sshd', 'alice');
  assert.notEqual(r.code, 0, 'revoked: asked again, and denied');
  assert.equal(messages.length, before + 1);
  assert.match(messages.at(-1), /alice/);
  assert.ok(!fs.existsSync(grantFile('ssh', 'alice')), 'the window was dropped');
  // Approve again, for the tests below.
  nextTap = 'a';
  assert.equal((await pam('sshd', 'alice')).code, 0);
});

test('only an approver can revoke a window', async () => {
  const id = grantId('ssh', 'alice');
  await fetch(workerURL + '/telegram/webhook', {
    method: 'POST',
    headers: { 'X-Telegram-Bot-Api-Secret-Token': SECRET, 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query: { id: 'cq', from: { id: 999, username: 'stranger' }, data: `g:${id}:d` } }),
  });
  const before = messages.length;
  assert.equal((await pam('sshd', 'alice')).code, 0, 'the window still counts');
  assert.ok(messages.length <= before + 1, 'no new approval asked');
  assert.ok(!messages.slice(before).some((m) => /Allow/.test(m)));
});

test('server unreachable: a cached window still counts', async () => {
  const etc = path.join(tmp, 'etc-offline');
  fs.cpSync(env.REQUEST_ACCESS_CONFIG_DIR, etc, { recursive: true });
  const f = path.join(etc, 'config.json');
  fs.writeFileSync(f, JSON.stringify({ ...JSON.parse(fs.readFileSync(f)), url: 'http://127.0.0.1:9' }));
  const r = await pam('sshd', 'alice', { REQUEST_ACCESS_CONFIG_DIR: etc });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  const n = await pam('sshd', 'nobody-cached', { REQUEST_ACCESS_CONFIG_DIR: etc });
  assert.notEqual(n.code, 0, 'without a window it still fails closed');
});

test('a grant for one user or service does not cover another', async () => {
  nextTap = 'd';
  const before = messages.length;
  let r = await pam('sshd', 'bob');
  assert.notEqual(r.code, 0);
  r = await pam('sudo', 'carol', { PAM_RUSER: 'alice' });
  assert.notEqual(r.code, 0, 'sudo needs its own approval');
  assert.equal(messages.length, before + 2);
});

test('sudo: the asking user (PAM_RUSER) is shown and "just this once" is not cached', async () => {
  nextTap = 'o';
  const before = messages.length;
  let r = await pam('sudo', 'root', { PAM_RUSER: 'alice' });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(messages.at(-1), /alice/);
  nextTap = 'd';
  r = await pam('sudo', 'root', { PAM_RUSER: 'alice' });
  assert.notEqual(r.code, 0);
  assert.equal(messages.length, before + 2);
});

test('a tampered cached grant is ignored', async () => {
  const dir = path.join(env.REQUEST_ACCESS_STATE_DIR, 'grants');
  const f = path.join(dir, 'ssh__alice.json');
  const g = JSON.parse(fs.readFileSync(f));
  const payload = JSON.parse(Buffer.from(g.payload, 'base64url'));
  payload.user = 'mallory';
  fs.writeFileSync(path.join(dir, 'ssh__mallory.json'), JSON.stringify({ payload: b64u(Buffer.from(JSON.stringify(payload))), sig: g.sig }));
  nextTap = 'd';
  const r = await pam('sshd', 'mallory');
  assert.notEqual(r.code, 0);
});

test('admin: config change goes through Telegram and changes the window', async () => {
  nextTap = 'a';
  let r = await run(['config', 'window.ssh=20m', 'lang=nl']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(messages.at(-1), /windows\.ssh: 900 → 1200/);
  r = await run(['config']);
  assert.match(r.stdout, /"ssh": 1200/);
  r = await pam('sshd', 'dave');
  assert.equal(r.code, 0);
  assert.match(messages.at(-1), /Toestaan 20 min/);
});

test('admin: denied change is not applied', async () => {
  nextTap = 'd';
  const r = await run(['config', 'window.ssh=1d']);
  assert.notEqual(r.code, 0);
  const s = await run(['config']);
  assert.match(s.stdout, /"ssh": 1200/);
});

test('exempt users: global and per service', async () => {
  const f = path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'config.json');
  const cfg = JSON.parse(fs.readFileSync(f));
  cfg.exempt_users = ['backup', 'ssh:deploy'];
  fs.writeFileSync(f, JSON.stringify(cfg));
  nextTap = 'd';
  const before = messages.length;
  assert.equal((await pam('sshd', 'backup')).code, 0);
  assert.equal((await pam('sshd', 'deploy')).code, 0);
  assert.equal((await pam('sudo', 'root', { PAM_RUSER: 'root' })).code, 0, 'sudo by root is always exempt');
  assert.equal(messages.length, before, 'exempt users send no request');
  assert.notEqual((await pam('sudo', 'root', { PAM_RUSER: 'deploy' })).code, 0, 'ssh:deploy does not cover sudo');
  assert.notEqual((await pam('sshd', 'root')).code, 0, 'root ssh logins still need approval');
  assert.equal(messages.length, before + 2);
});

test('unconfigured host fails closed', async () => {
  const r = await run(['pam'], { PAM_TYPE: 'account', PAM_SERVICE: 'sshd', PAM_USER: 'x', REQUEST_ACCESS_CONFIG_DIR: path.join(tmp, 'nope') });
  assert.notEqual(r.code, 0);
});
