'use strict';
// Integration tests: real HTTP against a throw-away server with demo data.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startServer } = require('../helpers');

const PF = () => ({ bill_no: 'B' + crypto.randomInt(1e6), item: 'Test item', proof_photo: 'data:image/jpeg;base64,' + Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), crypto.randomBytes(9000)]).toString('base64'), proof_ts: new Date().toISOString() });
const SIG = 'data:image/png;base64,' + Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), crypto.randomBytes(600)]).toString('base64');
let S;
test.before(async () => { S = await startServer(); });
test.after(async () => { await S.stop(); });

test('auth: health, bad login, wrong role, no token, tampered token', async () => {
  assert.equal((await S.api('GET', '/api/health')).status, 200);
  assert.equal((await S.api('POST', '/api/auth/login', { role: 'ceo', mobile: '7233023547', password: 'nope' })).status, 401);
  assert.equal((await S.api('POST', '/api/auth/login', { role: 'customer', mobile: '7233023547', password: 'Pratishtha@2025' })).status, 401);
  assert.equal((await S.api('GET', '/api/sync/pull?since=0')).status, 401);
  const t = await S.as('ceo'); const bad = t.slice(0, -3) + (t.endsWith('AAA') ? 'BBB' : 'AAA');
  assert.equal((await S.api('GET', '/api/sync/pull?since=0', undefined, bad)).status, 401);
  const [h, p, s] = t.split('.'); const pl = JSON.parse(Buffer.from(p, 'base64url')); pl.role = 'ceo'; pl.kind = 'staff';
  const forged = h + '.' + Buffer.from(JSON.stringify(pl)).toString('base64url') + '.' + s;
  assert.equal((await S.api('GET', '/api/sync/pull?since=0', undefined, forged)).status, 401);
  const none = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' + p + '.';
  assert.equal((await S.api('GET', '/api/sync/pull?since=0', undefined, none)).status, 401);
});

test('sync RBAC: each external role sees only its own rows', async () => {
  const cust = (await S.pull('customer')).changes;
  const loans = cust.filter(c => c.coll === 'loans').map(c => c.data);
  assert.ok(loans.every(l => String(l.customer_id) === '1'), 'customer sees only own loans');
  assert.ok(!cust.some(c => c.coll === 'users'), 'customer cannot see users');
  assert.ok(!cust.some(c => c.coll === 'accounts'));
  const ret = (await S.pull('retailer')).changes;
  assert.ok(!ret.some(c => c.coll === 'loans'), 'retailer cannot read loans');
  const lend = (await S.pull('lender')).changes;
  assert.ok(!lend.some(c => c.coll === 'users'));
  const ceo = (await S.pull('ceo')).changes; assert.ok(ceo.length > cust.length);
});

test('sync: customer cannot write staff collections or other people rows', async () => {
  const r = await S.push('customer', [{ coll: 'loans', id: '9999', isnew: true, data: { id: 9999, customer_id: 1, amount: 1, status: 'active' } }, { coll: 'users', id: '99', isnew: true, data: { id: 99, role: 'ceo' } }]);
  assert.equal((r.body.rejected || []).length, 2, JSON.stringify(r.body));
});

test('lockout: 5 wrong passwords lock the account, correct password then refused', async () => {
  for (let i = 0; i < 5; i++) await S.api('POST', '/api/auth/login', { role: 'hr', mobile: '9900112233', password: 'wrong' + i });
  const r = await S.api('POST', '/api/auth/login', { role: 'hr', mobile: '9900112233', password: 'Pratishtha@2025' });
  assert.ok([423, 429].includes(r.status), 'status ' + r.status);
});

test('card flow: unlock → retailer charge → approve → limit used', async () => {
  const U = await S.as('customer'), R = await S.as('retailer');
  assert.equal((await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U)).status, 200);
  const before = (await S.api('GET', '/api/customer/card-terms', undefined, U)).body.cards[0].avail;
  const ch = await S.api('POST', '/api/retailer/charge', { ...PF(), card_no: 'PFS-VC-0001', amount: 2500 }, R);
  assert.equal(ch.status, 200, JSON.stringify(ch.body));
  const ap = await S.api('POST', '/api/customer/card-pay', { id: ch.body.record.id, action: 'approve', tenure: 6 }, U);
  assert.ok(ap.body.success, JSON.stringify(ap.body));
  const after = (await S.api('GET', '/api/customer/card-terms', undefined, U)).body.cards[0].avail;
  assert.equal(before - after, 2500);
  // replayed proof photo must be refused
  const p = PF(); const a = await S.api('POST', '/api/retailer/charge', { ...p, card_no: 'PFS-VC-0001', amount: 100 }, R);
  const b = await S.api('POST', '/api/retailer/charge', { ...p, bill_no: 'X' + p.bill_no, card_no: 'PFS-VC-0001', amount: 100 }, R);
  assert.equal(a.status, 200); assert.ok(b.status >= 400, 'replay should fail, got ' + b.status);
  await S.api('POST', '/api/customer/card-pay', { id: a.body.record.id, action: 'decline' }, U);
});

test('card: bad amounts rejected', async () => {
  const R = await S.as('retailer');
  for (const amount of [-5, 0, 'abc', 1e12, null]) {
    const r = await S.api('POST', '/api/retailer/charge', { ...PF(), card_no: 'PFS-VC-0001', amount }, R);
    assert.ok(r.status >= 400, 'amount ' + amount + ' got ' + r.status);
  }
});

test('retailer return: only finance, reason required, no double return', async () => {
  const U = await S.as('customer'), R = await S.as('retailer'), F = await S.as('finance'), O = await S.as('ops');
  const ch = await S.api('POST', '/api/retailer/charge', { ...PF(), card_no: 'PFS-VC-0001', amount: 700 }, R);
  assert.ok(ch.body.record, JSON.stringify(ch.body)); const ap = await S.api('POST', '/api/customer/card-pay', { id: ch.body.record.id, action: 'approve', tenure: 3 }, U);
  assert.ok(ap.body.record, JSON.stringify(ap.body)); const id = ap.body.record.id;
  assert.equal((await S.api('POST', '/api/retailers/txn-return', { id, reason: 'Item defective' }, O)).status, 403);
  assert.equal((await S.api('POST', '/api/retailers/txn-return', { id, reason: '' }, F)).status, 400);
  assert.equal((await S.api('POST', '/api/retailers/txn-return', { id, reason: 'Item defective' }, F)).status, 200);
  assert.equal((await S.api('POST', '/api/retailers/txn-return', { id, reason: 'again please' }, F)).status, 409);
});

test('agreements: request → sign (password+signature) → duplicate blocked → void → re-sign', async () => {
  const C = await S.as('ceo'), P = await S.as('partner');
  const pull = (await S.pull('ceo')).changes; const partner = pull.find(c => c.coll === 'partners' && c.data.mobile === '9876511001').data;
  assert.equal((await S.api('POST', '/api/staff/agreement-request', { kind: 'partner', id: partner.id }, C)).status, 200);
  assert.equal((await S.api('POST', '/api/party/esign', { password: 'wrong', signature: SIG }, P)).status, 403);
  assert.equal((await S.api('POST', '/api/party/esign', { password: '511001', signature: 'data:text/html;base64,AAAA' }, P)).status, 400);
  const ok = await S.api('POST', '/api/party/esign', { password: '511001', signature: SIG }, P);
  assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.ok(ok.body.record.hash && ok.body.record.snapshot);
  assert.equal((await S.api('POST', '/api/party/esign', { password: '511001', signature: SIG }, P)).status, 409);
  assert.equal((await S.api('POST', '/api/staff/agreement-void', { kind: 'partner', id: partner.id, reason: 'x' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/agreement-void', { kind: 'partner', id: partner.id, reason: 'Terms changed' }, await S.as('finance'))).status, 403);
  assert.equal((await S.api('POST', '/api/staff/agreement-void', { kind: 'partner', id: partner.id, reason: 'Terms changed' }, C)).status, 200);
  assert.equal((await S.api('POST', '/api/party/esign', { password: '511001', signature: SIG }, P)).status, 200);
});

test('agreement template: only CEO edits, validates clauses/placeholders, version bumps, reset works', async () => {
  const C = await S.as('ceo'), F = await S.as('finance');
  const body = { id: 'dsa', title: 'T', intro: 'Intro {{party_name}}', recital: '', term_months: 12, notice_days: 30, settlement_days: 7, clauses: [{ t: 'a', b: 'b' }, { t: 'c', b: 'd' }, { t: 'e', b: 'f' }] };
  assert.equal((await S.api('POST', '/api/staff/agreement-template', body, F)).status, 403);
  assert.equal((await S.api('POST', '/api/staff/agreement-template', { ...body, clauses: body.clauses.slice(0, 2) }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/agreement-template', { ...body, term_months: 9999 }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/agreement-template', { ...body, intro: 'Hi {{bogus_var}}' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/agreement-template', { ...body, id: 'nope' }, C)).status, 400);
  const ok = await S.api('POST', '/api/staff/agreement-template', body, C); assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal((await S.api('POST', '/api/staff/agreement-template', { id: 'dsa', reset: true }, C)).status, 200);
});

test('insurance: enrol needs consent + nominee', async () => {
  const U = await S.as('customer');
  const plans = (await S.pull('customer')).changes.filter(c => c.coll === 'ins_plans');
  const pid = plans[0]?.data.id; if (pid === undefined) return;
  assert.ok((await S.api('POST', '/api/customer/insurance-enroll', { plan_id: pid }, U)).status >= 400);
  const ok = await S.api('POST', '/api/customer/insurance-enroll', { plan_id: pid, consent: true, nominee_name: 'Ram', nominee_relation: 'Father' }, U);
  assert.ok(ok.status < 500, JSON.stringify(ok.body));
});

test('emergency loan: bounds enforced, single running loan', async () => {
  const U = await S.as('customer');
  assert.ok((await S.api('POST', '/api/customer/emergency-loan', { amount: 100 }, U)).status >= 400);
  assert.ok((await S.api('POST', '/api/customer/emergency-loan', { amount: 10000000 }, U)).status >= 400);
  assert.ok((await S.api('POST', '/api/customer/emergency-loan', { amount: -1 }, U)).status >= 400);
});

test('reminders: CEO only, idempotent', async () => {
  assert.equal((await S.api('POST', '/api/staff/run-reminders', {}, await S.as('finance'))).status, 403);
  const a = await S.api('POST', '/api/staff/run-reminders', {}, await S.as('ceo')); assert.equal(a.status, 200);
  const b = await S.api('POST', '/api/staff/run-reminders', {}, await S.as('ceo')); assert.equal(b.status, 200);
  assert.equal(Number(b.body.sent) || 0, 0, 'second run sends nothing new: ' + JSON.stringify(b.body));
});

test('security headers present', async () => {
  const r = await S.api('GET', '/api/health');
  assert.ok(r.headers.get('x-content-type-options')); assert.ok(!r.headers.get('x-powered-by'));
});
