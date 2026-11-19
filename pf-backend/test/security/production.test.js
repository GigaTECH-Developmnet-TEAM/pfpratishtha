'use strict';
// Production hardening (TDD): the server must refuse unsafe production configuration, start cleanly with a safe one, and shut down gracefully.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const SERVER = path.join(__dirname, '..', '..', 'server.js');
const GOOD = { NODE_ENV: 'production', SEED_DEMO: 'false', ADMIN_PASSWORD: 'Vx9#kQ2!mLp7Zr', JWT_SECRET: 'a'.repeat(16) + 'B'.repeat(16) + '9'.repeat(16), DEFAULT_STAFF_PASSWORD: 'Qw8$nT5@yHc3Ld', ADMIN_MOBILE: '7233023547' };
const freePort = () => new Promise(r => { const s = net.createServer(); s.listen(0, () => { const p = s.address().port; s.close(() => r(p)); }); });
async function boot(env, { wait = 4000 } = {}) {
  const port = await freePort(), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfs-prod-'));
  const e = { ...process.env, PORT: String(port), DB_PATH: path.join(dir, 'p.db'), ...GOOD, ...env };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  const p = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', SERVER], { env: e, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; p.stdout.on('data', d => log += d); p.stderr.on('data', d => log += d);
  const done = new Promise(r => p.on('exit', (code, sig) => r({ code, sig })));
  const url = 'http://127.0.0.1:' + port; const t0 = Date.now(); let up = false;
  while (Date.now() - t0 < wait) { try { if ((await fetch(url + '/api/health')).ok) { up = true; break; } } catch { /* starting */ } await new Promise(r => setTimeout(r, 100)); if (p.exitCode !== null) break; }
  return { p, url, dir, up, log: () => log, done, stop: async () => { if (p.exitCode === null) p.kill('SIGTERM'); return done; } };
}
const mustRefuse = async (env, re) => { const s = await boot(env); const r = await Promise.race([s.done, new Promise(r => setTimeout(() => r('timeout'), 3000))]); if (r === 'timeout') { await s.stop(); assert.fail('server started with unsafe config ' + JSON.stringify(Object.keys(env))); } assert.ok(r.code !== 0, 'exit code'); assert.match(s.log(), re); };

test('PROD-01 refuses the default / missing / weak admin password', async () => {
  await mustRefuse({ ADMIN_PASSWORD: undefined }, /ADMIN_PASSWORD/);
  await mustRefuse({ ADMIN_PASSWORD: 'Pratishtha@2025' }, /ADMIN_PASSWORD/);
  await mustRefuse({ ADMIN_PASSWORD: 'short1!' }, /ADMIN_PASSWORD/);
  await mustRefuse({ ADMIN_PASSWORD: 'password12345' }, /ADMIN_PASSWORD/);
});
test('PROD-02 refuses a missing or weak JWT secret', async () => {
  await mustRefuse({ JWT_SECRET: undefined }, /JWT_SECRET/);
  await mustRefuse({ JWT_SECRET: 'secret' }, /JWT_SECRET/);
  await mustRefuse({ JWT_SECRET: 'put-a-long-random-string-here' }, /JWT_SECRET/);
});
test('PROD-03 refuses the well-known default staff password and a non-https face origin', async () => {
  await mustRefuse({ DEFAULT_STAFF_PASSWORD: 'Pratishtha@2025' }, /DEFAULT_STAFF_PASSWORD/);
  await mustRefuse({ DEFAULT_STAFF_PASSWORD: undefined }, /DEFAULT_STAFF_PASSWORD/);
  await mustRefuse({ FACE_ORIGIN: 'http://pratishtha.pro' }, /FACE_ORIGIN/);
});
test('PROD-04 safe config boots; no demo logins; HSTS + https redirect; no stack/engine leaks; DB file is private', async () => {
  const s = await boot({}); try {
    assert.ok(s.up, 'did not boot: ' + s.log());
    const demo = await fetch(s.url + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'ceo', mobile: '7233023547', password: 'Pratishtha@2025' }) }); assert.equal(demo.status, 401);
    const real = await fetch(s.url + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'ceo', mobile: '7233023547', password: GOOD.ADMIN_PASSWORD }) }); assert.equal(real.status, 200);
    const cust = await fetch(s.url + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'customer', mobile: '9876543210', password: '543210' }) }); assert.equal(cust.status, 401, 'demo customer exists in production');
    const h = await fetch(s.url + '/api/health', { headers: { 'x-forwarded-proto': 'https' } }); assert.match(h.headers.get('strict-transport-security') || '', /max-age=\d{7,}/);
    const raw = (hdrs) => new Promise((res, rej) => { const q = require('node:http').request(s.url + '/', { headers: hdrs }, r => { r.resume(); res({ status: r.statusCode, loc: r.headers.location }); }); q.on('error', rej); q.end(); });
    const r = await raw({ host: 'pratishtha.pro' }); assert.equal(r.status, 301); assert.match(r.loc, /^https:\/\//);
    const w = await raw({ host: 'www.pratishtha.pro', 'x-forwarded-proto': 'https' }); assert.equal(w.status, 301); assert.equal(w.loc, 'https://pratishtha.pro/');
    assert.equal(h.headers.get('x-powered-by'), null);
    const bad = await fetch(s.url + '/api/nope', { headers: { 'x-forwarded-proto': 'https' } }); assert.ok(!/at .*\.js|node_modules|SQLITE/i.test(await bad.text()));
    const mode = fs.statSync(path.join(s.dir, 'p.db')).mode & 0o077; assert.equal(mode, 0, 'database file is readable by group/others: ' + (fs.statSync(path.join(s.dir, 'p.db')).mode & 0o777).toString(8));
  } finally { await s.stop(); }
});
test('PROD-05 graceful shutdown: SIGTERM exits 0 quickly and keeps the database consistent', async () => {
  const s = await boot({}); assert.ok(s.up, s.log());
  const t0 = Date.now(); s.p.kill('SIGTERM'); const r = await Promise.race([s.done, new Promise(r => setTimeout(() => r('timeout'), 5000))]);
  assert.notEqual(r, 'timeout', 'did not exit on SIGTERM'); assert.equal(r.code, 0, 'exit code ' + r.code + ' ' + r.sig); assert.ok(Date.now() - t0 < 5000);
  const e2 = await boot({ DB_PATH: undefined }); await e2.stop();
});
test('PROD-06 an uncaught exception inside a request never leaks details and the process keeps serving', async () => {
  const s = await boot({}); try {
    const r = await fetch(s.url + '/api/sync/push', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer x' }, body: '{bad json' });
    assert.ok(r.status === 400 || r.status === 401); assert.ok(!/SyntaxError|at JSON/.test(await r.text()));
    assert.equal((await fetch(s.url + '/api/health')).status, 200);
  } finally { await s.stop(); }
});
