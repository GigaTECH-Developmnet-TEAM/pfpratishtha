'use strict';
// Test helpers: start a throw-away server (fresh DB, demo data) on a random port and talk to it over HTTP.
const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');

const freePort = () => new Promise((res, rej) => { const s = net.createServer(); s.listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); s.on('error', rej); });

async function startServer(env = {}) {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfs-test-'));
  const proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, '..', 'server.js')], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(port), DB_PATH: path.join(dir, 'test.db'), SEED_DEMO: 'true', ADMIN_PASSWORD: 'Pratishtha@2025', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = ''; proc.stdout.on('data', d => log += d); proc.stderr.on('data', d => log += d);
  let exited = false; proc.on('exit', () => { exited = true; });
  const url = 'http://127.0.0.1:' + port;
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(url + '/api/health'); if (r.ok) break; } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 100));
    if (exited) throw new Error('server did not start (exited): ' + log.slice(-300));
    if (i === 99) { proc.kill(); throw new Error('server did not start: ' + log.slice(-500)); }
  }
  const tokens = {};
  async function api(method, p, body, token, extraHeaders) {
    const headers = { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...(extraHeaders || {}) };
    const r = await fetch(url + p, { method, headers, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) });
    let j = null; const t = await r.text(); try { j = JSON.parse(t); } catch { j = { raw: t }; }
    return { status: r.status, body: j, headers: r.headers };
  }
  async function login(role, mobile, password) {
    const k = role + mobile;
    if (tokens[k]) return tokens[k];
    const r = await api('POST', '/api/auth/login', { role, mobile, password });
    if (!r.body.token) throw new Error('login failed for ' + role + ': ' + JSON.stringify(r.body));
    return (tokens[k] = r.body.token);
  }
  const creds = {
    ceo: ['ceo', '7233023547', 'Pratishtha@2025'], finance: ['finance', '9900112266', 'Pratishtha@2025'], ops: ['ops', '9900112255', 'Pratishtha@2025'],
    ce: ['ce', '9900112211', 'Pratishtha@2025'], rc: ['rc', '9900112310', 'Pratishtha@2025'], tl: ['tl', '9900112299', 'Pratishtha@2025'], doc: ['doc', '8899001122', 'Pratishtha@2025'], hr: ['hr', '9900112233', 'Pratishtha@2025'],
    customer: ['customer', '9876543210', '543210'], partner: ['partner', '9876511001', '511001'],
    lender: ['lender', '9900112400', '112400'], retailer: ['retailer', '9900113001', '113001'],
  };
  const as = async who => login(...creds[who]);
  const pull = async (who, since = 0) => (await api('GET', '/api/sync/pull?since=' + since, undefined, await as(who))).body;
  const push = async (who, ops) => api('POST', '/api/sync/push', { ops }, await as(who));
  const stop = () => new Promise(res => { proc.once('exit', res); proc.kill(); setTimeout(res, 2000); });
  return { url, api, login, as, pull, push, stop, port, log: () => log };
}
module.exports = { startServer };
