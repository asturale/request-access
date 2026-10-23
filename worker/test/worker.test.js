// End-to-end tests of the Worker in Miniflare, with a fake Telegram API.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { Miniflare } from 'miniflare';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const APPROVER = 4242;
const WEBHOOK_SECRET = 'test-webhook-secret';

let mf, tg, tgPort;
const sent = []; // telegram calls
let msgId = 100;

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'jwk' }).x;
  return { pub: raw, priv: privateKey };
}
const signing = crypto.generateKeyPairSync('ed25519');
const host = keypair();
const admin = keypair();

before(async () => {
  tg = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const method = req.url.split('/').pop();
      sent.push({ method, params: JSON.parse(body || '{}') });
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, result: method === 'sendMessage' ? { message_id: ++msgId } : true }));
    });
  });
  await new Promise((r) => tg.listen(0, '127.0.0.1', r));
  tgPort = tg.address().port;
  mf = new Miniflare({
    modules: true,
    scriptPath: new URL('../src/index.js', import.meta.url).pathname,
    compatibilityDate: '2025-09-01',
    durableObjects: { STATE: 'State' },
    bindings: {
      TELEGRAM_API: `http://127.0.0.1:${tgPort}`,
      TELEGRAM_BOT_TOKEN: 'x',
      TELEGRAM_CHAT_ID: String(APPROVER),
      TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
      APPROVER_IDS: String(APPROVER),
      SIGNING_KEY: b64u(signing.privateKey.export({ format: 'der', type: 'pkcs8' })),
      ADMIN_KEYS: admin.pub,
    },
  });
});

after(async () => {
  await mf.dispose();
  tg.close();
});

function signed(keyId, priv, method, path, body = '', tsOffset = 0) {
  const ts = String(Math.floor(Date.now() / 1000) + tsOffset);
  const digest = b64u(crypto.createHash('sha256').update(body).digest());
  const msg = `RA1\n${method}\n${path}\n${ts}\n${digest}`;
  const sig = b64u(crypto.sign(null, Buffer.from(msg), priv));
  return mf.dispatchFetch('http://ra.test' + path, {
    method,
    body: method === 'GET' ? undefined : body,
    headers: { 'RA-Key-Id': keyId, 'RA-Timestamp': ts, 'RA-Signature': sig, 'Content-Type': 'application/json' },
  });
}

async function click(data, from = APPROVER) {
  const res = await mf.dispatchFetch('http://ra.test/telegram/webhook', {
    method: 'POST',
    headers: { 'X-Telegram-Bot-Api-Secret-Token': WEBHOOK_SECRET, 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query: { id: 'cq', from: { id: from, username: 'tester' }, data } }),
  });
  assert.equal(res.status, 200);
}

const nonce = () => crypto.randomBytes(18).toString('base64url');
const lastSend = () => [...sent].reverse().find((s) => s.method === 'sendMessage');

function verifyGrant(grant, workerKey) {
  const pub = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: workerKey }, format: 'jwk' });
  const ok = crypto.verify(null, Buffer.from(grant.payload, 'base64url'), pub, Buffer.from(grant.sig, 'base64url'));
  return ok ? JSON.parse(Buffer.from(grant.payload, 'base64url')) : null;
}

let workerKey;

test('info exposes the worker public key', async () => {
  const r = await (await mf.dispatchFetch('http://ra.test/v1/info')).json();
  workerKey = r.worker_key;
  assert.equal(workerKey, signing.publicKey.export({ format: 'jwk' }).x);
});

test('unknown host is rejected', async () => {
  const res = await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'a', nonce: nonce() }));
  assert.equal(res.status, 401);
});

test('enrollment needs approval on telegram', async () => {
  const res = await mf.dispatchFetch('http://ra.test/v1/enroll', {
    method: 'POST',
    body: JSON.stringify({ name: 'web1', key: host.pub, nonce: nonce() }),
  });
  assert.equal(res.status, 200);
  const { id, fingerprint } = await res.json();
  assert.match(lastSend().params.text, new RegExp(fingerprint.replace(/[+/]/g, '.')));
  // a stranger clicking does nothing
  await click(`e:${id}:a`, 999);
  assert.equal((await (await mf.dispatchFetch(`http://ra.test/v1/enroll/${id}`)).json()).status, 'pending');
  await click(`e:${id}:a`);
  assert.equal((await (await mf.dispatchFetch(`http://ra.test/v1/enroll/${id}`)).json()).status, 'approved');
});

test('access request: approve yields a valid signed grant', async () => {
  const n = nonce();
  const res = await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'alice', rhost: '10.0.0.5', nonce: n }));
  assert.equal(res.status, 200);
  const { id, window } = await res.json();
  assert.equal(window, 900);
  const msg = lastSend().params;
  assert.match(msg.text, /alice/);
  assert.match(msg.text, /10\.0\.0\.5/);
  let st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'pending');
  await click(`r:${id}:a`);
  st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'approved');
  const g = verifyGrant(st.grant, workerKey);
  assert.ok(g, 'grant signature verifies');
  assert.equal(g.host, 'web1');
  assert.equal(g.user, 'alice');
  assert.equal(g.service, 'ssh');
  assert.equal(g.nonce, n);
  assert.equal(g.exp - g.iat, 900);
  // a second click cannot flip it
  await click(`r:${id}:d`);
  st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'approved');
});

test('"just this once" gives a short grant', async () => {
  const res = await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'sudo', user: 'alice', nonce: nonce() }));
  const { id } = await res.json();
  await click(`r:${id}:o`);
  const st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  const g = verifyGrant(st.grant, workerKey);
  assert.equal(g.once, true);
  assert.ok(g.exp - g.iat <= 30);
});

test('deny', async () => {
  const res = await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'bob', nonce: nonce() }));
  const { id } = await res.json();
  await click(`r:${id}:d`);
  const st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'denied');
  assert.equal(st.grant, undefined);
});

test('replayed nonce, stale timestamp and bad signature are rejected', async () => {
  const n = nonce();
  const body = JSON.stringify({ service: 'ssh', user: 'a', nonce: n });
  assert.equal((await signed('host:web1', host.priv, 'POST', '/v1/access', body)).status, 200);
  assert.equal((await signed('host:web1', host.priv, 'POST', '/v1/access', body)).status, 409);
  assert.equal((await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'a', nonce: nonce() }), -300)).status, 401);
  const other = keypair();
  assert.equal((await signed('host:web1', other.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'a', nonce: nonce() }))).status, 401);
});

test('a host cannot read another host\'s request', async () => {
  const other = keypair();
  const e = await (await mf.dispatchFetch('http://ra.test/v1/enroll', { method: 'POST', body: JSON.stringify({ name: 'web2', key: other.pub, nonce: nonce() }) })).json();
  await click(`e:${e.id}:a`);
  const { id } = await (await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'a', nonce: nonce() }))).json();
  assert.equal((await signed('host:web2', other.priv, 'GET', `/v1/access/${id}`)).status, 404);
});

test('webhook without the secret is rejected', async () => {
  const res = await mf.dispatchFetch('http://ra.test/telegram/webhook', { method: 'POST', body: '{}' });
  assert.equal(res.status, 401);
});

test('admin config change applies only after approval', async () => {
  const body = JSON.stringify({ action: 'set_config', config: { windows: { ssh: 1800, 'web1/sudo': 300 } }, nonce: nonce() });
  const res = await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', body);
  assert.equal(res.status, 200);
  const { id } = await res.json();
  assert.match(lastSend().params.text, /windows\.ssh: 900 → 1800/);
  let state = await (await signed('admin:0', admin.priv, 'GET', '/v1/admin/state')).json();
  assert.equal(state.config.windows.ssh, 900);
  await click(`x:${id}:a`);
  state = await (await signed('admin:0', admin.priv, 'GET', '/v1/admin/state')).json();
  assert.equal(state.config.windows.ssh, 1800);
  assert.deepEqual(state.hosts.map((h) => h.name).sort(), ['web1', 'web2']);
  const r = await (await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'sudo', user: 'a', nonce: nonce() }))).json();
  assert.equal(r.window, 300);
});

test('hosts cannot use admin endpoints, invalid config is refused', async () => {
  assert.equal((await signed('host:web1', host.priv, 'GET', '/v1/admin/state')).status, 403);
  const body = JSON.stringify({ action: 'set_config', config: { windows: { ssh: 99999999 } }, nonce: nonce() });
  assert.equal((await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', body)).status, 400);
});

test('remove host after approval', async () => {
  const body = JSON.stringify({ action: 'remove_host', name: 'web2', nonce: nonce() });
  const { id } = await (await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', body)).json();
  await click(`x:${id}:a`);
  const state = await (await signed('admin:0', admin.priv, 'GET', '/v1/admin/state')).json();
  assert.deepEqual(state.hosts.map((h) => h.name), ['web1']);
});

test('routes: per host and per user, with several approvers', async () => {
  const body = JSON.stringify({
    action: 'set_config',
    config: {
      routes: {
        web1: { chat: '-1001', approvers: ['111', '222'], required: 2 },
        'user:ops': { approvers: ['333'] },
      },
    },
    nonce: nonce(),
  });
  const { id: act } = await (await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', body)).json();
  await click(`x:${act}:a`);

  // host route: needs two distinct approvers, posted in the route's chat
  let { id } = await (await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'alice', nonce: nonce() }))).json();
  assert.equal(lastSend().params.chat_id, '-1001');
  await click(`r:${id}:a`); // default approver is not on this route
  await click(`r:${id}:a`, 111);
  await click(`r:${id}:a`, 111); // same person twice does not count double
  let st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'pending');
  await click(`r:${id}:a`, 222);
  st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'approved');

  // user route beats host route
  ({ id } = await (await signed('host:web1', host.priv, 'POST', '/v1/access', JSON.stringify({ service: 'ssh', user: 'ops', nonce: nonce() }))).json());
  assert.equal(lastSend().params.chat_id, '333');
  await click(`r:${id}:a`, 333);
  st = await (await signed('host:web1', host.priv, 'GET', `/v1/access/${id}`)).json();
  assert.equal(st.status, 'approved');

  // admin changes stay with the default approver only
  const b2 = JSON.stringify({ action: 'set_config', config: { routes: { web1: null, 'user:ops': null } }, nonce: nonce() });
  const { id: act2 } = await (await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', b2)).json();
  await click(`x:${act2}:a`, 111);
  let state = await (await signed('admin:0', admin.priv, 'GET', '/v1/admin/state')).json();
  assert.ok(state.config.routes.web1, 'route approver cannot confirm admin changes');
  await click(`x:${act2}:a`);
  state = await (await signed('admin:0', admin.priv, 'GET', '/v1/admin/state')).json();
  assert.deepEqual(state.config.routes, {});
});

test('route validation', async () => {
  const bad = [
    { 'bad key!': { approvers: ['1'] } },
    { web1: { approvers: [] } },
    { web1: { approvers: ['abc'] } },
    { web1: { approvers: ['1', '2'] } }, // several approvers need an explicit chat
    { web1: { approvers: ['1'], required: 2 } },
  ];
  for (const routes of bad) {
    const body = JSON.stringify({ action: 'set_config', config: { routes }, nonce: nonce() });
    assert.equal((await signed('admin:0', admin.priv, 'POST', '/v1/admin/actions', body)).status, 400, JSON.stringify(routes));
  }
});
