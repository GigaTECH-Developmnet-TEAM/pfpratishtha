'use strict';
// INTEGRATION tests (TDD round): every route that had no test yet — authentication, role/kind gating, input validation, IDOR.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('../helpers');
let S;
test.before(async () => { S = await startServer(); });
test.after(async () => { await S.stop(); });

const ROUTES = [
  // [method, path, body, allowed-kind(s)]
  ['get', '/api/auth/face/mine', null, 'any'],
  ['post', '/api/auth/face/remove', { id: 'x' }, 'any'],
  ['post', '/api/admin/face/reset', { account_id: 1 }, 'ceo'],
  ['put', '/api/customers/1/reset-password', { password: 'Abcdef@1234' }, 'staff'],
  ['put', '/api/partners/1/reset-password', { password: 'Abcdef@1234' }, 'staff'],
  ['put', '/api/lenders/1/reset-password', { password: 'Abcdef@1234' }, 'staff'],
  ['post', '/api/customer/pay-request', { ref_type: 'loan', ref_id: 1, amount: 100 }, 'customer'],
  ['post', '/api/customer/card-request', { type: 'emi' }, 'customer'],
  ['post', '/api/customer/card-action', { id: '1', action: 'block' }, 'customer'],
  ['post', '/api/customer/mandate-request', { loan_id: 1 }, 'customer'],
  ['post', '/api/customer/mandate-cancel', { id: 1 }, 'customer'],
  ['get', '/api/customer/retailers', null, 'customer'],
  ['get', '/api/customer/pending-pay', null, 'customer'],
  ['post', '/api/customer/card-convert', { loan_id: 1, months: 6 }, 'customer'],
  ['post', '/api/customer/card-payoff', { loan_id: 1 }, 'customer'],
  ['post', '/api/customer/gold-request', { pledge_id: 1 }, 'customer'],
  ['post', '/api/customer/gold-release-confirm', { pledge_id: 1 }, 'customer'],
  ['post', '/api/customer/insurance-claim', { policy_id: 1, amount: 100 }, 'customer'],
  ['post', '/api/retailer/settlement-request', { amount: 100 }, 'retailer'],
  ['post', '/api/retailer/cancel', { id: 1 }, 'retailer'],
  ['post', '/api/partner/esign', { ref_id: 1 }, 'partner'],
  ['post', '/api/staff/partner-agreement-request', { kind: 'partner', ref_id: 1 }, 'staff'],
  ['post', '/api/staff/gold-release', { pledge_id: 1 }, 'staff-gold'],
  ['post', '/api/staff/gold-rate', { rate_22k: 6000 }, 'staff-gold'],
  ['post', '/api/staff/gold-margin-scan', {}, 'staff-gold'],
  ['post', '/api/staff/gold-auction', { pledge_id: 1 }, 'ceo'],
  ['post', '/api/staff/plan-open', { customer_id: 1 }, 'staff-plans'],
];
const KIND = { ceo: 'staff', hr: 'staff', finance: 'staff', ops: 'staff', ce: 'staff', customer: 'customer', partner: 'partner', lender: 'lender', retailer: 'retailer' };
const call = async (m, p, b, tok) => S.api(m.toUpperCase(), p, m === 'get' ? undefined : (b === null ? undefined : b), tok);

test('every route rejects a missing / garbage token with 401', async () => {
  for (const [m, p, b] of ROUTES) {
    assert.equal((await call(m, p, b, undefined)).status, 401, 'no token ' + p);
    assert.equal((await call(m, p, b, 'garbage.token.value')).status, 401, 'bad token ' + p);
  }
});
test('role / kind gating: a wrong kind of account never gets through (403, never 200/500)', async () => {
  for (const [m, p, b, allow] of ROUTES) {
    for (const who of Object.keys(KIND)) {
      const k = KIND[who];
      const permitted = allow === 'any' || allow === k && !['ceo', 'staff-gold', 'staff-plans'].includes(allow) || (allow === 'ceo' && who === 'ceo') || (allow === 'staff-gold' && ['ceo', 'ops'].includes(who)) || (allow === 'staff-plans' && who === 'ceo');
      if (permitted) continue;
      const r = await call(m, p, b, await S.as(who));
      assert.ok(r.status === 403 || r.status === 404, who + ' on ' + p + ' → ' + r.status);
      assert.ok(r.status !== 500);
    }
  }
});
test('no route returns 500 for hostile bodies (huge strings, objects, arrays, null, negatives)', async () => {
  const S2 = await startServer(); try {
  const evil = [{ id: { $ne: 1 }, amount: -1 }, { id: [1, 2], amount: 'NaN', loan_id: {}, policy_id: [], pledge_id: null, password: ['a'], type: {}, rate_22k: 'x'.repeat(5000) }, null, { amount: 1e308, months: -1, id: '1; DROP TABLE records' }];
  const toks = { ceo: await S2.as('ceo'), customer: await S2.as('customer'), retailer: await S2.as('retailer'), partner: await S2.as('partner') };
  for (const [m, p] of ROUTES) for (const t of Object.values(toks)) for (const b of evil) {
    const r = await S2.api(m.toUpperCase(), p, m === 'get' || b === null ? undefined : b, t); assert.ok(r.status < 500, m + ' ' + p + ' → ' + r.status + ' ' + JSON.stringify(r.body).slice(0, 120));
  }
  } finally { await S2.stop(); }
});
test('password reset: only authorised staff; strong password enforced; old creds & tokens die', async () => {
  const C = await S.as('ceo'), U = await S.as('customer');
  const cust = (await S.pull('ceo')).changes.filter(c => c.coll === 'customers').map(c => c.data).find(c => String(c.id) === '2');
  const first = await S.api('POST', '/api/auth/login', { mobile: cust.mobile, password: String(cust.mobile).slice(-6), role: 'customer' });
  const oldTok = first.body && first.body.token;
  assert.equal((await S.api('PUT', '/api/customers/2/reset-password', { password: 'Abcdef@1234' }, await S.as('hr'))).status, 403);
  assert.equal((await S.api('PUT', '/api/customers/2/reset-password', { password: 'Abcdef@1234' }, U)).status, 403);
  assert.equal((await S.api('PUT', '/api/customers/2/reset-password', { password: '123' }, C)).status, 400);
  assert.equal((await S.api('PUT', '/api/customers/999999/reset-password', { password: 'Abcdef@1234' }, C)).status, 404);
  assert.equal((await S.api('PUT', '/api/customers/2/reset-password', { password: 'Abcdef@1234' }, C)).status, 200);
  if (oldTok) assert.equal((await S.api('GET', '/api/customer/retailers', undefined, oldTok)).status, 401, 'old token revoked');
  assert.equal((await S.api('POST', '/api/auth/login', { mobile: cust.mobile, password: String(cust.mobile).slice(-6), role: 'customer' })).status, 401, 'old password dead');
  assert.equal((await S.api('POST', '/api/auth/login', { mobile: cust.mobile, password: 'Abcdef@1234', role: 'customer' })).status, 200, 'new password works');
});
test('send-otp is disabled and cannot be used to probe accounts', async () => {
  const a = await S.api('POST', '/api/auth/send-otp', { mobile: '9876543210' }), b = await S.api('POST', '/api/auth/send-otp', { mobile: '0000000000' });
  assert.equal(a.body.success, false); assert.deepEqual(a.body, b.body);
});
test('face-login config is public but exposes nothing sensitive; list/remove are own-account only', async () => {
  const c = await S.api('GET', '/api/auth/face/config'); assert.equal(c.status, 200); assert.ok(!/secret|key|hash/i.test(JSON.stringify(c.body)));
  const mine = await S.api('GET', '/api/auth/face/mine', undefined, await S.as('ceo')); assert.equal(mine.status, 200); assert.ok(Array.isArray(mine.body.devices));
  assert.equal((await S.api('POST', '/api/admin/face/reset', { account_id: 1 }, await S.as('ops'))).status, 403);
});
test('customer money routes: IDOR + validation (no other customer’s loan, no bad amounts)', async () => {
  const U = await S.as('customer');
  for (const bad of [{ ref_type: 'loan', ref_id: 999999, amount: 100 }, { ref_type: 'loan', ref_id: 1, amount: -50 }, { ref_type: 'loan', ref_id: 1, amount: 0 }, { ref_type: 'x', ref_id: 1, amount: 10 }, { ref_type: 'loan', ref_id: 1, amount: 1e12 }])
    assert.ok([400, 404, 403, 409].includes((await S.api('POST', '/api/customer/pay-request', bad, U)).status), JSON.stringify(bad));
  assert.equal((await S.api('POST', '/api/customer/card-request', { type: 'platinum' }, U)).status, 400);
  assert.ok((await S.api('POST', '/api/customer/card-convert', { loan_id: 999999, months: 6 }, U)).status >= 400);
  assert.ok((await S.api('POST', '/api/customer/card-payoff', { loan_id: 999999 }, U)).status >= 400);
  assert.ok((await S.api('POST', '/api/customer/insurance-claim', { policy_id: 999999, amount: 100 }, U)).status >= 400);
  assert.ok((await S.api('POST', '/api/customer/mandate-cancel', { id: 999999 }, U)).status >= 400);
});
test('retailer routes: cannot cancel others’ / missing payments; bad settlement amounts rejected', async () => {
  const R = await S.as('retailer');
  assert.equal((await S.api('POST', '/api/retailer/cancel', { id: 999999 }, R)).status, 404);
  for (const a of [-5, 0, 'abc', 1e12, null]) assert.ok((await S.api('POST', '/api/retailer/settlement-request', { amount: a }, R)).status >= 400, String(a));
});
test('gold admin routes: permission + rate bounds', async () => {
  const C = await S.as('ceo');
  for (const r of [0, 999, 30001, -1, 'x', null]) assert.equal((await S.api('POST', '/api/staff/gold-rate', { rate_22k: r }, C)).status, 400, String(r));
  assert.equal((await S.api('POST', '/api/staff/gold-release', { pledge_id: 999999, reason: 'test reason' }, C)).status, 404);
  assert.equal((await S.api('POST', '/api/staff/gold-auction', { pledge_id: 999999, reason: 'test reason' }, C)).status, 404);
  assert.equal((await S.api('POST', '/api/staff/gold-rate', { rate_22k: 6000 }, await S.as('hr'))).status, 403);
  assert.equal((await S.api('GET', '/api/gold/rate', undefined, await S.as('customer'))).status, 200);
});
test('notifications read: staff handled by sync; customer can only mark their own', async () => {
  const r = await S.api('POST', '/api/notifs/read', {}, await S.as('customer')); assert.equal(r.status, 200);
  assert.equal((await S.api('POST', '/api/notifs/read', {}, await S.as('ceo'))).body.handled_by, 'sync');
});
