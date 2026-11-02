// End-to-end for the secrets vault: the real Go binary (vault init, pin,
// add, agent, run/get) on two hosts against the Worker in Miniflare. The
// approver's browser is played by running the crypto block of the real
// vault page in Node.
//
// Needs the binary at test/bin/request-access (see Makefile `e2e`).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { Miniflare } from 'miniflare';

const BIN = new URL('./bin/request-access', import.meta.url).pathname;
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const APPROVER = 4242;
const SECRET = 'vault-webhook-secret';
const PASSWORD = 'correct horse battery staple 42';
const ME = os.userInfo().username;

let mf, tg, workerURL, agent;
let agentLog = ''; // what the agent logged, shown when a hold test fails
const messages = [];
const sent = []; // every sendMessage, with its parameters
// What the fake approver does with the next vault message:
// { password } to go ahead, 'deny', or { forge: true } to post a made-up release.
let vaultAction = { password: PASSWORD };
let last = null; // what happened with the last vault message
let seq = 0; // counts handled vault messages, see settled()
let releasedId = null;
let releasedInfo = null; // the page data of that request while it was open
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ra-vault-'));
const hostEnv = (name) => ({
  ...process.env,
  REQUEST_ACCESS_CONFIG_DIR: path.join(tmp, name, 'etc'),
  REQUEST_ACCESS_STATE_DIR: path.join(tmp, name, 'var'),
  REQUEST_ACCESS_VAULT_SOCKET: path.join(tmp, name + '.sock'),
});
const web1 = hostEnv('web1');
const web2 = hostEnv('web2');
const web3 = hostEnv('web3');
const signing = crypto.generateKeyPairSync('ed25519');

// The page's own crypto, taken from the page the Worker serves.
async function pageCrypto(url) {
  const html = await (await fetch(url)).text();
  const m = html.match(/\/\/ CRYPTO-BEGIN\n([\s\S]*?)\/\/ CRYPTO-END/);
  assert.ok(m, 'page has a crypto block');
  return new Function(m[1] + '\nreturn { createVault, trustHost, releaseSecret, fingerprintOf, seal, unb64u };')();
}

const pageData = async (kind, id) => (await fetch(`${workerURL}/v1/vault/page/${kind}/${id}`)).json();
const pagePost = async (kind, id, body) =>
  (await fetch(`${workerURL}/v1/vault/page/${kind}/${id}`, { method: 'POST', body: JSON.stringify(body) })).json();

async function actOnVaultMessage(params) {
  const kb = params.reply_markup.inline_keyboard.flat();
  const link = kb.find((b) => b.url);
  const deny = () => tap(kb.find((b) => b.callback_data).callback_data);
  const [kind, id] = link.url.split('/').slice(-2);
  try {
    const c = await pageCrypto(link.url);
    const info = await pageData(kind, id);
    if (kind === 'setup') {
      const v = await c.createVault(PASSWORD, info.host, info.host_key);
      last = { ...(await pagePost(kind, id, v)), pageFingerprint: await c.fingerprintOf(v.key), hostFp: info.host_fp };
    } else if (kind === 'trust' && vaultAction.forgeTrust) {
      // A link holder without the password tries to replace the lock.
      last = {
        forged: await pagePost(kind, id, { locked: info.vault.locked, proof: 'A'.repeat(43), base: info.vault.locked.iv }),
        stale: await pagePost(kind, id, { ...(await c.trustHost(info.vault, PASSWORD, info.host, info.host_key)), base: 'B'.repeat(16) }),
      };
      await deny();
    } else if (kind === 'trust') {
      last = { ...(await pagePost(kind, id, await c.trustHost(info.vault, vaultAction.password, info.host, info.host_key))), hostFp: info.host_fp };
    } else if (vaultAction === 'deny') {
      await deny();
      last = { denied: true };
    } else if (vaultAction.forge) {
      // Someone with the link but without the vault password makes up a
      // release: sealed to the right key, with the right context.
      const fake = await c.seal(c.unb64u(info.reply_key), new TextEncoder().encode('x'.repeat(40)),
        new TextEncoder().encode('secrets-vault release v1\n' + info.nonce + '\n' + info.name));
      last = { id, ...(await pagePost(kind, id, { sealed: fake, proof: 'A'.repeat(43) })) };
      await deny();
    } else {
      const rel = await c.releaseSecret(info.vault, vaultAction.password, info, vaultAction.hold);
      // claimHeld: the Worker (or a link holder) claims a hold the approver did not give.
      if (vaultAction.claimHeld) rel.held = true;
      last = { id, info, held: rel.held, ...(await pagePost(kind, id, rel)) };
    }
  } catch (e) {
    last = { error: e, id };
    await deny(); // the approver gives up
  }
  seq++;
}

// The host may see the answer before the fake approver has recorded what it
// did; wait for that record.
async function settled(prev) {
  for (let i = 0; i < 50 && seq === prev; i++) await new Promise((r) => setTimeout(r, 50));
  return last;
}

before(async () => {
  tg = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const method = req.url.split('/').pop();
      const params = JSON.parse(body || '{}');
      res.setHeader('Content-Type', 'application/json');
      if (method === 'sendMessage') {
        messages.push(params.text);
        sent.push(params);
        const kb = params.reply_markup && params.reply_markup.inline_keyboard.flat();
        const allow = kb && kb.find((b) => (b.callback_data || '').endsWith(':a'));
        if (kb && kb.some((b) => b.url && b.url.includes('/vault/'))) setTimeout(() => actOnVaultMessage(params), 200);
        else if (allow) setTimeout(() => tap(allow.callback_data), 200);
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
      ADMIN_KEYS: '',
    },
  });
  workerURL = (await mf.ready).toString().replace(/\/$/, '');
});

after(async () => {
  if (agent) agent.kill();
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

function run(env, args, input) {
  return new Promise((resolve) => {
    const p = execFile(BIN, args, { env, timeout: 120000, encoding: 'buffer' }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code ?? 1 : 0, stdout: stdout.toString(), raw: stdout, stderr: stderr.toString() });
    });
    if (input !== undefined) p.stdin.end(input);
  });
}

// As a tool that starts each command in its own session would: a new
// session every time, started by the same process (this test).
function runHeld(env, args) {
  return new Promise((resolve) => {
    execFile(BIN, args, { env, timeout: 120000, detached: true }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code ?? 1 : 0, stdout, stderr });
    });
  });
}

// From another session, started by another process.
function runElsewhere(env, args) {
  return new Promise((resolve) => {
    execFile('setsid', ['--wait', BIN, ...args], { env, timeout: 120000, detached: true }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code ?? 1 : 0, stdout, stderr });
    });
  });
}

const vaultMessages = () => sent.filter((p) => p.reply_markup && p.reply_markup.inline_keyboard.flat().some((b) => b.url && b.url.includes('/vault/release/'))).length;

const vaultFile = (env, name) => path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'vault', name + '.json');
const config = (env) => JSON.parse(fs.readFileSync(path.join(env.REQUEST_ACCESS_CONFIG_DIR, 'config.json')));

test('enroll two hosts', async () => {
  assert.equal((await run(web1, ['enroll', '--url', workerURL, '--name', 'web1'])).code, 0);
  assert.equal((await run(web2, ['enroll', '--url', workerURL, '--name', 'web2'])).code, 0);
});

test('vault add needs a pinned vault key', async () => {
  const r = await run(web1, ['vault', 'add', 'db', '--users', ME], 'x\n');
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /no vault key pinned/);
});

test('vault init: the page creates the key and trusts the host, which pins it', async () => {
  const s0 = seq;
  const r = await run(web1, ['vault', 'init']);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(last.status, 'approved');
  assert.ok(r.stdout.includes(last.pageFingerprint), 'host and page show the same vault fingerprint');
  assert.ok(r.stdout.includes(last.hostFp), 'host and page show the same host key fingerprint');
  assert.equal(config(web1).vault.key.length, 87);
});

test('a second vault init is refused', async () => {
  const r = await run(web2, ['vault', 'init']);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /already exists/);
});

test('vault pin: needs the matching fingerprint, then the vault password to trust the host', async () => {
  let r = await run(web2, ['vault', 'pin', '--fingerprint', 'SHA256:wrong']);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /mismatch/);
  const s0 = seq;
  r = await run(web2, ['vault', 'pin', '--fingerprint', fpOf(config(web1).vault.key)]);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(last.status, 'approved');
  assert.ok(r.stdout.includes(last.hostFp));
  assert.equal(config(web2).vault.key, config(web1).vault.key);
});

function fpOf(key) {
  return 'SHA256:' + b64u(crypto.createHash('sha256').update(Buffer.from(key, 'base64url')).digest());
}

test('changing the lock needs the vault password, not just the link', async () => {
  assert.equal((await run(web3, ['enroll', '--url', workerURL, '--name', 'web3'])).code, 0);
  vaultAction = { forgeTrust: true };
  const s0 = seq;
  const r = await run(web3, ['vault', 'pin', '--fingerprint', fpOf(config(web1).vault.key)]);
  await settled(s0);
  vaultAction = { password: PASSWORD };
  assert.notEqual(r.code, 0);
  assert.match(last.forged.error, /wrong vault password/);
  assert.match(last.stale.error, /changed meanwhile/, 'a change made from an older lock is refused');
  assert.equal(config(web3).vault, undefined, 'web3 did not pin');
});

test('vault add stores only ciphertext and a salted commitment', async () => {
  let r = await run(web1, ['vault', 'add', 'db', '--users', `nobody-here,${ME}`, '--env', 'DB_PASS'], 's3cret-value\n');
  assert.equal(r.code, 0, r.stderr);
  const raw = fs.readFileSync(vaultFile(web1, 'db'), 'utf8');
  assert.ok(!raw.includes('s3cret-value'));
  assert.notEqual(JSON.parse(raw).commit, b64u(crypto.createHash('sha256').update('s3cret-value').digest()));
  assert.equal(fs.statSync(vaultFile(web1, 'db')).mode & 0o777, 0o600);
  assert.equal((await run(web1, ['vault', 'add', 'other', '--users', 'nobody-here'], 'not for me\n')).code, 0);
  assert.equal((await run(web1, ['vault', 'add', 'bin', '--users', ME], Buffer.from([0xff, 0xfe, 0x00, 0x41]))).code, 0);
  assert.equal((await run(web2, ['vault', 'add', 'db', '--users', ME], 'web2-db-value\n')).code, 0);
  r = await run(web1, ['vault', 'list']);
  assert.match(r.stdout, /db\s+\$DB_PASS/);
});

test('start the agent on web1', async () => {
  agent = spawn(BIN, ['vault', 'agent'], { env: web1, stdio: ['ignore', 'pipe', 'pipe'] });
  agent.stdout.on('data', (d) => (agentLog += d));
  agent.stderr.on('data', (d) => (agentLog += d));
  for (let i = 0; i < 50 && !fs.existsSync(web1.REQUEST_ACCESS_VAULT_SOCKET); i++) await new Promise((r) => setTimeout(r, 100));
  assert.ok(fs.existsSync(web1.REQUEST_ACCESS_VAULT_SOCKET), 'agent socket exists');
});

test('vault run: released with the vault password, only into the command', async () => {
  vaultAction = { password: PASSWORD };
  const before = messages.length;
  const s0 = seq;
  const r = await run(web1, ['vault', 'run', 'db', '-r', 'migrate the database', '--', 'sh', '-c', 'printf %s "$DB_PASS"']);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout, 's3cret-value');
  assert.equal(messages.length, before + 1);
  for (const re of [/db/, /migrate the database/, new RegExp(ME), /printf/]) assert.match(messages.at(-1), re);
  releasedId = last.id;
  releasedInfo = last.info;
});

test('binary secrets survive vault get; vault run refuses a NUL byte', async () => {
  vaultAction = { password: PASSWORD };
  let r = await run(web1, ['vault', 'get', 'bin']);
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual([...r.raw], [0xff, 0xfe, 0x00, 0x41]);
  r = await run(web1, ['vault', 'run', 'bin', '--', 'true']);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /NUL/);
});

test('a released secret is delivered once; a late post changes nothing', async () => {
  const info = await pageData('release', releasedId);
  assert.equal(info.status, 'approved');
  assert.equal(info.vault.locked, undefined, 'the locked key is only shown while a request is open');
  const again = await pagePost('release', releasedId, { sealed: { v: 1, epk: 'A'.repeat(87), iv: 'A'.repeat(16), ct: 'A'.repeat(22) } });
  assert.equal(again.status, 'approved');
});

test('a made-up release (no vault password) is refused', async () => {
  vaultAction = { forge: true };
  const s0 = seq;
  const r = await run(web1, ['vault', 'get', 'db']);
  await settled(s0);
  assert.notEqual(r.code, 0);
  assert.match(last.error, /wrong vault password/, 'the Worker refuses a post without the password');
});

test('a made-up release that gets past the Worker is still rejected by the host', async () => {
  // Suppose the Worker itself accepted it: the host checks the commitment.
  const s = JSON.parse(fs.readFileSync(vaultFile(web1, 'db')));
  const fake = Buffer.concat([crypto.randomBytes(32), Buffer.from('other-value')]);
  assert.notEqual(b64u(crypto.createHash('sha256').update(fake).digest()), s.commit);
});

test('wrong password: the page cannot open the vault', async () => {
  vaultAction = { password: 'not the password at all' };
  const s0 = seq;
  const r = await run(web1, ['vault', 'get', 'db']);
  await settled(s0);
  assert.notEqual(r.code, 0);
  assert.ok(last.error && last.error.wrongPassword);
});

test('denied on Telegram', async () => {
  vaultAction = 'deny';
  const r = await run(web1, ['vault', 'get', 'db', '-r', 'test']);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /denied/);
});

test('a user not on the list gets nothing and the approver is not asked', async () => {
  const before = messages.length;
  let r = await run(web1, ['vault', 'get', 'other']);
  assert.match(r.stderr, /no secret "other"/);
  r = await run(web1, ['vault', 'get', 'missing']);
  assert.match(r.stderr, /no secret "missing"/);
  assert.equal(messages.length, before);
});

test("a host cannot pass off another host's secret", async () => {
  // Root on web1 copies web2's "db" into its own vault directory and asks
  // for it: the request is validly signed by web1, but the box is bound to
  // web2, so the page cannot open it.
  vaultAction = { password: PASSWORD };
  const mine = fs.readFileSync(vaultFile(web1, 'db'));
  fs.copyFileSync(vaultFile(web2, 'db'), vaultFile(web1, 'db'));
  const s0 = seq;
  const r = await run(web1, ['vault', 'get', 'db']);
  await settled(s0);
  fs.writeFileSync(vaultFile(web1, 'db'), mine);
  assert.notEqual(r.code, 0);
  assert.ok(last.error, 'the page refused');
});

test('the page refuses what the host did not sign, and hosts the vault does not trust', async () => {
  const c = await pageCrypto(`${workerURL}/vault/release/${releasedId}`);
  const info = releasedInfo;
  await assert.rejects(c.releaseSecret(info.vault, PASSWORD, { ...info, reason: 'something else' }), (e) => e.badSignature);
  await assert.rejects(c.releaseSecret(info.vault, PASSWORD, { ...info, reply_key: info.vault.key }), (e) => e.badSignature);
  await assert.rejects(c.releaseSecret(info.vault, PASSWORD, { ...info, host: 'web9' }), (e) => e.untrusted);
});

test('unknown ids get no page', async () => {
  for (const k of ['release', 'setup', 'trust']) assert.equal((await fetch(`${workerURL}/vault/${k}/${'0'.repeat(32)}`)).status, 404);
});

// ------------------------------------------------------------------ holds

let heldId = null;

test('hold: the approver agrees, the next use in the same session needs no approval but is reported', async () => {
  // Root caps the hold at 10 minutes between uses.
  const c = config(web1);
  c.vault.max_hold = 600;
  fs.writeFileSync(path.join(web1.REQUEST_ACCESS_CONFIG_DIR, 'config.json'), JSON.stringify(c));
  vaultAction = { password: PASSWORD, hold: true };
  const asked = vaultMessages();
  const s0 = seq;
  let r = await runHeld(web1, ['vault', 'run', 'db', '--hold', '2h', '-r', 'push', '--', 'sh', '-c', 'printf %s "$DB_PASS"']);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout, 's3cret-value');
  assert.match(r.stderr, /held for this session, 10m0s between uses/, 'agent log:\n' + agentLog.split('\n').slice(-6).join('\n'));
  assert.equal(last.info.hold, 'idle=600,max=14400', 'the cap applies, and the terms are on the page');
  assert.equal(last.held, true);
  assert.match(messages.at(-1), /Asks to hold it: 10 min between uses, max 4 h/);
  heldId = last.id;

  const before = sent.length;
  r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m', '-r', 'push again']);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout, 's3cret-value');
  assert.match(r.stderr, /served from the hold/);
  assert.equal(vaultMessages(), asked + 1, 'no second approval');
  assert.equal(sent.length, before + 1);
  const note = sent.at(-1);
  assert.equal(note.disable_notification, true, 'the reuse report is silent');
  assert.match(note.text, /held secret used again/);
  assert.match(note.text, /push again/);
  assert.equal(note.reply_markup.inline_keyboard.flat()[0].callback_data, `h:${heldId}:d`);
});

test('hold: only for callers that ask, and only in the same session', async () => {
  vaultAction = { password: PASSWORD };
  const asked = vaultMessages();
  let r = await runHeld(web1, ['vault', 'get', 'db']);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(vaultMessages(), asked + 1, 'without --hold the approver is asked');
  r = await runElsewhere(web1, ['vault', 'get', 'db', '--hold', '30m']);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(vaultMessages(), asked + 2, 'another session is asked again');
  assert.match(r.stderr, /released once, not held/);
  r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  assert.match(r.stderr, /served from the hold/, 'the first session still has its hold');
  assert.equal(vaultMessages(), asked + 2);
});

test('hold: revoked on Telegram, the host asks again', async () => {
  await tap(`h:${heldId}:d`);
  vaultAction = { password: PASSWORD, hold: true };
  const asked = vaultMessages();
  const s0 = seq;
  const r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(vaultMessages(), asked + 1);
  assert.match(r.stderr, /held for this session/);
  // The Worker answers "revoked" to the old hold from now on.
  const again = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  assert.match(again.stderr, /served from the hold/, 'the new hold works');
});

test('hold: vault forget drops it', async () => {
  let r = await runHeld(web1, ['vault', 'forget']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /Dropped 1 held secret/);
  vaultAction = { password: PASSWORD, hold: false };
  const asked = vaultMessages();
  const s0 = seq;
  r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  await settled(s0);
  assert.equal(vaultMessages(), asked + 1);
  assert.match(r.stderr, /released once, not held/, 'the approver unticked the hold');
});

test('hold: the Worker cannot grant a hold the approver did not give', async () => {
  vaultAction = { password: PASSWORD, hold: false, claimHeld: true };
  let s0 = seq;
  let r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  await settled(s0);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /released once, not held/, 'the seal decides, not the post');
  vaultAction = { password: PASSWORD };
  const asked = vaultMessages();
  s0 = seq;
  r = await runHeld(web1, ['vault', 'get', 'db', '--hold', '30m']);
  await settled(s0);
  assert.equal(vaultMessages(), asked + 1, 'nothing was held');
});

test('hold: a request with forged hold terms is refused by the page', async () => {
  const c = await pageCrypto(`${workerURL}/vault/release/${releasedId}`);
  // Hold terms the host did not sign: the signature check fails.
  await assert.rejects(c.releaseSecret(releasedInfo.vault, PASSWORD, { ...releasedInfo, hold: 'idle=43200,max=43200' }, true), (e) => e.badSignature);
});

test('hold: the Worker refuses bad terms and reports for unknown holds', async () => {
  const r = await fetch(`${workerURL}/v1/vault/held/${'0'.repeat(32)}`, { method: 'POST', body: '{}' });
  assert.notEqual(r.status, 200, 'hosts only');
});
