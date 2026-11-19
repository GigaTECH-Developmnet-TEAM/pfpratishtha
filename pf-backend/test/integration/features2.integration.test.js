'use strict';
// Integration (TDD): identity verification on customers, SMS alerts queue, online payment webhook.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http'), crypto = require('node:crypto');
const { startServer } = require('../helpers');

const res = r => ({ ok: r.status === 200, applied: (r.body.applied || []).length, rej: (r.body.rejected || []).length, why: (r.body.rejected || []).map(x => x.reason).join('|') });
const mkAadhaar = base => { const { aadhaarCheck } = require('../../server.js'); for (let d = 0; d < 10; d++) if (aadhaarCheck(base + d).ok) return base + d; };
process.env.DB_PATH = require('path').join(require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'pfs-f2-')), 'x.db');

test('IDV-1 customers: bad PAN / IFSC / bank account refused; good ones normalised; duplicates refused; server stamps kyc_checks', async () => {
  const S = await startServer(); try {
    const base = { id: 5001, customer_code: 'PFS-C-5001', name: 'Sunita Verma', mobile: '9811100001', status: 'active', district: 'Lucknow' };
    let r = res(await S.push('ceo', [{ coll: 'customers', id: '5001', isnew: true, data: { ...base, pan: 'ABCDE1234F' } }])); assert.ok(r.rej === 1 && /PAN/.test(r.why), JSON.stringify(r));
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5001', isnew: true, data: { ...base, bank_ifsc: 'XXXX1234567' } }])); assert.ok(r.rej === 1 && /IFSC/.test(r.why), JSON.stringify(r));
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5001', isnew: true, data: { ...base, bank_account: '12ab' } }])); assert.ok(r.rej === 1 && /account/i.test(r.why), JSON.stringify(r));
    const aa = mkAadhaar('34567890123');
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5001', isnew: true, data: { ...base, pan: 'abcpv1234f', aadhaar: aa, bank_ifsc: 'sbin0004521', bank_account: '32145698701', kyc_checks: { pan: 'ok', forged: true } } }])); assert.equal(r.applied, 1, JSON.stringify(r));
    const row = (await S.pull('ceo')).changes.find(c => c.coll === 'customers' && String(c.id) === '5001').data;
    assert.equal(row.pan, 'ABCPV1234F'); assert.equal(row.bank_ifsc, 'SBIN0004521'); assert.equal(row.kyc_checks.pan, 'ok'); assert.equal(row.kyc_checks.aadhaar, 'checksum_ok'); assert.equal(row.kyc_checks.forged, undefined, 'clients cannot forge kyc_checks'); assert.ok(row.kyc_checks.checked_at);
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5002', isnew: true, data: { ...base, id: 5002, customer_code: 'PFS-C-5002', mobile: '9811100002', pan: 'ABCPV1234F' } }])); assert.ok(r.rej === 1 && /already/i.test(r.why), 'duplicate PAN: ' + JSON.stringify(r));
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5003', isnew: true, data: { ...base, id: 5003, customer_code: 'PFS-C-5003', mobile: '9811100003', aadhaar: aa } }])); assert.ok(r.rej === 1 && /already/i.test(r.why), 'duplicate Aadhaar: ' + JSON.stringify(r));
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5001', data: { ...row, address: 'New address' } }])); assert.equal(r.applied, 1, 'editing own record is not a duplicate: ' + JSON.stringify(r));
    r = res(await S.push('ceo', [{ coll: 'customers', id: '5004', isnew: true, data: { ...base, id: 5004, customer_code: 'PFS-C-5004', mobile: '9811100004', aadhaar: aa.slice(0, 11) + ((+aa[11] + 3) % 10) } }])); assert.equal(r.applied, 1, 'invalid-checksum Aadhaar is flagged, not blocked: ' + JSON.stringify(r)); 
    assert.equal((await S.pull('ceo')).changes.find(c => c.coll === 'customers' && String(c.id) === '5004').data.kyc_checks.aadhaar, 'unverified');
  } finally { await S.stop(); }
});

function mockSms(failFirst) {
  const got = []; let n = 0;
  const srv = http.createServer((q, s) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { got.push({ headers: q.headers, body: b }); n++; if (failFirst && n <= failFirst) { s.statusCode = 500; return s.end('boom'); } s.end('{"ok":true}'); }); });
  return new Promise(r => srv.listen(0, '127.0.0.1', () => r({ got, url: 'http://127.0.0.1:' + srv.address().port + '/send', close: () => srv.close() })));
}
test('SMS-1 customer alerts are queued, sent to the provider once, retried on failure, capped, opt-out respected, logged with masked numbers', async () => {
  const m = await mockSms(1); const S = await startServer({ SMS_URL: m.url, SMS_AUTH: 'authkey: k123', SMS_SENDER: 'PRATFN' }); try {
    const C = await S.as('ceo'), U = await S.as('customer');
    // trigger a customer notification: staff posts an approved collection for customer 1 (hook → notify)
    const col = { id: 6001, collection_code: 'PFS-COL-6001', customer_id: 1, customer_name: 'Ramesh Kumar', amount: 777, status: 'posted', ref_type: 'other', payment_mode: 'cash', collection_date: '2026-11-08' };
    assert.equal(res(await S.push('ceo', [{ coll: 'collections', id: '6001', isnew: true, data: col }])).applied, 1);
    let f = await S.api('POST', '/api/staff/sms-flush', {}, C); assert.equal(f.status, 200);
    f = await S.api('POST', '/api/staff/sms-flush', { force: true }, C);
    const log = (await S.api('GET', '/api/staff/sms-log', undefined, C)).body.rows;
    assert.ok(log.length >= 1); const row = log.find(x => /777/.test(x.text)); assert.ok(row, JSON.stringify(log).slice(0, 300));
    assert.ok(!/9876543210/.test(JSON.stringify(log)), 'full mobile must not be in the log'); assert.match(row.mobile, /^98\*+10$/);
    assert.equal(row.status, 'sent', 'first attempt 500 → retried → sent'); assert.ok(row.tries >= 2);
    assert.ok(m.got.length >= 2); const p = JSON.parse(m.got[m.got.length - 1].body); assert.equal(p.to, '9876543210'); assert.match(p.message, /Pratishtha Finance/); assert.ok(p.message.length <= 160); assert.equal(p.sender, 'PRATFN'); assert.equal(m.got[0].headers.authkey, 'k123');
    // opt-out
    assert.equal((await S.api('POST', '/api/customer/sms-pref', { enabled: false }, U)).status, 200);
    const before = m.got.length; await S.push('ceo', [{ coll: 'collections', id: '6002', isnew: true, data: { ...col, id: 6002, collection_code: 'PFS-COL-6002', amount: 888 } }]);
    await S.api('POST', '/api/staff/sms-flush', { force: true }, C); assert.equal(m.got.length, before, 'opted-out customer gets no SMS');
    // permissions
    assert.equal((await S.api('GET', '/api/staff/sms-log', undefined, await S.as('hr'))).status, 403); assert.equal((await S.api('GET', '/api/staff/sms-log', undefined, U)).status, 403);
    assert.equal((await S.api('POST', '/api/staff/sms-test', { mobile: '12345' }, C)).status, 400);
  } finally { await S.stop(); m.close(); }
});
test('SMS-2 without provider configured nothing leaves the server (dry-run), and the per-number daily cap holds', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo');
    for (let i = 0; i < 14; i++) await S.push('ceo', [{ coll: 'collections', id: String(6100 + i), isnew: true, data: { id: 6100 + i, collection_code: 'PFS-COL-' + (6100 + i), customer_id: 1, customer_name: 'R', amount: 100 + i, status: 'posted', ref_type: 'other', payment_mode: 'cash', collection_date: '2026-11-08' } }]);
    await S.api('POST', '/api/staff/sms-flush', { force: true }, C);
    const rows = (await S.api('GET', '/api/staff/sms-log', undefined, C)).body.rows; assert.ok(rows.length > 0 && rows.length <= 8, 'cap 8/day/number, got ' + rows.length);
    assert.ok(rows.every(r => r.status === 'logged'), 'unconfigured provider must not claim "sent"');
  } finally { await S.stop(); }
});

const SECRET = 'whsec_integration_test_secret_123';
const hook = (S, payload, secret = SECRET, extra = {}) => { const raw = JSON.stringify(payload); return fetch(S.url + '/api/pay/webhook', { method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': crypto.createHmac('sha256', secret).update(raw).digest('hex'), ...extra }, body: raw }); };
const evt = (o = {}) => ({ event: 'payment.captured', payload: { payment: { entity: { id: 'pay_AAA111', amount: 123400, currency: 'INR', status: 'captured', order_id: 'order_X1', notes: { customer_id: '1', ref_type: 'loan', ref_id: '1' }, ...o } } } });
test('PAY-1 webhook: signed + valid creates ONE verified pending payment; replays, tampering, wrong signature, other customers’ loans and odd amounts are refused', async () => {
  const S = await startServer({ GATEWAY_WEBHOOK_SECRET: SECRET }); try {
    const C = await S.as('ceo'); const pend = async () => (await S.pull('ceo')).changes.filter(c => c.coll === 'collections' && c.data.gateway_payment_id).map(c => c.data);
    const loan1 = (await S.pull('ceo')).changes.find(c => c.coll === 'loans' && String(c.data.customer_id) === '1'); assert.ok(loan1);
    const good = evt({ notes: { customer_id: '1', ref_type: 'loan', ref_id: String(loan1.id) } });
    let r = await hook(S, good); assert.equal(r.status, 200); let p = await pend(); assert.equal(p.length, 1); assert.equal(p[0].amount, 1234); assert.equal(p[0].status, 'pending'); assert.equal(p[0].gateway_verified, true); assert.equal(p[0].customer_id, 1); assert.equal(p[0].gateway_payment_id, 'pay_AAA111');
    r = await hook(S, good); assert.equal(r.status, 200); assert.equal((await r.json()).duplicate, true); assert.equal((await pend()).length, 1, 'replay must not create a second payment');
    r = await hook(S, evt({ id: 'pay_BBB' }), 'wrong-secret-value-xxxxxxxxxxxx'); assert.equal(r.status, 401);
    const raw = JSON.stringify(evt({ id: 'pay_CCC' })); r = await fetch(S.url + '/api/pay/webhook', { method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': crypto.createHmac('sha256', SECRET).update(raw).digest('hex') }, body: raw.replace('123400', '999900') }); assert.equal(r.status, 401, 'tampered body');
    r = await fetch(S.url + '/api/pay/webhook', { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw }); assert.equal(r.status, 401, 'no signature');
    for (const [id, o] of [['pay_D1', { notes: { customer_id: '2', ref_type: 'loan', ref_id: String(loan1.id) } }], ['pay_D2', { amount: -500 }], ['pay_D3', { amount: 0 }], ['pay_D4', { currency: 'USD' }], ['pay_D5', { amount: 1e12 }], ['pay_D6', { status: 'failed' }], ['pay_D7', { notes: { customer_id: '1', ref_type: 'loan', ref_id: '99999' } }], ['pay_D8', { amount: 12.5 }]]) {
      const x = await hook(S, evt({ id, ...o })); assert.ok(x.status === 200 || x.status === 400, id + ' → ' + x.status); }
    assert.equal((await pend()).length, 1, 'no refused webhook may create a payment');
    r = await hook(S, { event: 'order.paid', payload: {} }); assert.equal(r.status, 200);
    r = await fetch(S.url + '/api/pay/webhook', { method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': 'x' }, body: '{bad' }); assert.ok(r.status === 400 || r.status === 401);
    assert.equal((await S.api('GET', '/api/pay/gateway/config', undefined, await S.as('customer'))).body.enabled, true);
  } finally { await S.stop(); }
});
test('PAY-2 without GATEWAY_WEBHOOK_SECRET the webhook is closed; the order endpoint is customer-only and validates ownership', async () => {
  const S = await startServer(); try {
    const r = await fetch(S.url + '/api/pay/webhook', { method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': 'abc' }, body: '{}' }); assert.equal(r.status, 503);
    assert.equal((await S.api('GET', '/api/pay/gateway/config', undefined, await S.as('customer'))).body.enabled, false);
    assert.equal((await S.api('POST', '/api/customer/gateway-order', { ref_type: 'loan', ref_id: 1, amount: 100 }, await S.as('ceo'))).status, 403);
    assert.equal((await S.api('POST', '/api/customer/gateway-order', { ref_type: 'loan', ref_id: 1, amount: 100 }, await S.as('customer'))).status, 503);
  } finally { await S.stop(); }
});
test('PAY-3 order creation talks to the gateway with server-set notes (customer id cannot be spoofed)', async () => {
  const got = []; const gw = http.createServer((q, s) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { got.push({ url: q.url, auth: q.headers.authorization, body: JSON.parse(b || '{}') }); s.setHeader('content-type', 'application/json'); s.end(JSON.stringify({ id: 'order_TEST1', amount: 50000, currency: 'INR' })); }); });
  await new Promise(r => gw.listen(0, '127.0.0.1', r));
  const S = await startServer({ GATEWAY_WEBHOOK_SECRET: SECRET, RAZORPAY_KEY_ID: 'rzp_test_abc', RAZORPAY_KEY_SECRET: 'sek', GATEWAY_API_BASE: 'http://127.0.0.1:' + gw.address().port }); try {
    const U = await S.as('customer'); const loan = (await S.pull('ceo')).changes.find(c => c.coll === 'loans' && String(c.data.customer_id) === '1');
    const r = await S.api('POST', '/api/customer/gateway-order', { ref_type: 'loan', ref_id: loan.id, amount: 500, customer_id: 2, notes: { customer_id: '2' } }, U); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.order_id, 'order_TEST1'); assert.equal(r.body.key_id, 'rzp_test_abc'); assert.ok(!JSON.stringify(r.body).includes('sek'));
    assert.equal(got[0].body.amount, 50000); assert.equal(got[0].body.currency, 'INR'); assert.equal(got[0].body.notes.customer_id, '1'); assert.equal(got[0].body.notes.ref_id, String(loan.id)); assert.match(got[0].auth, /^Basic /);
    for (const bad of [{ ref_type: 'loan', ref_id: 999999, amount: 100 }, { ref_type: 'loan', ref_id: loan.id, amount: -1 }, { ref_type: 'loan', ref_id: loan.id, amount: 5e7 }, { ref_type: 'x', ref_id: 1, amount: 10 }]) assert.ok((await S.api('POST', '/api/customer/gateway-order', bad, U)).status >= 400);
  } finally { await S.stop(); gw.close(); }
});
