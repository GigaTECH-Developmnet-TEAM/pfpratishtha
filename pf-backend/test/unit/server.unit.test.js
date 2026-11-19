'use strict';
// UNIT tests — pure server logic, no network. Run: npm run test:unit
process.env.DB_PATH = require('path').join(require('os').tmpdir(), 'pfs-unit-' + process.pid + '.db');
process.env.SEED_DEMO = 'false';
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../../server.js');

test.after(() => { for (const f of ['', '-wal', '-shm']) try { require('fs').unlinkSync(process.env.DB_PATH + f); } catch { /* ignore */ } setImmediate(() => process.exit(0)); });

test('password hashing: scrypt, salted, verifies correct password only', () => {
  const a = S.hashPw('Secret#123'), b = S.hashPw('Secret#123');
  assert.match(a, /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
  assert.notEqual(a, b, 'two hashes of the same password must differ (salt)');
  assert.equal(S.checkPw('Secret#123', a), true);
  assert.equal(S.checkPw('secret#123', a), false);
  assert.equal(S.checkPw('', a), false);
});
test('checkPw never throws on malformed stored hashes', () => {
  for (const bad of ['', 'x', 'scrypt$zz$yy', null, undefined, 'a$b']) assert.equal(S.checkPw('x', bad), false);
});
test('pwProblem enforces the password policy', () => {
  assert.match(S.pwProblem('short1'), /8 characters/);
  assert.match(S.pwProblem('abcdefgh'), /letters and numbers/);
  assert.match(S.pwProblem('12345678'), /letters and numbers/);
  assert.match(S.pwProblem('Abcd9876543210', '9876543210'), /mobile/);
  assert.match(S.pwProblem('Pratishtha1'), /too easy/);
  assert.equal(S.pwProblem('Gr8Passw0rd!', '9999999999'), null);
});
test('cleanStr neutralises HTML / JS-string breakout characters', () => {
  const out = S.cleanStr('<img src=x onerror="alert(1)">\'`\\');
  for (const ch of ['<', '>', '"', "'", '`', '\\']) assert.ok(!out.includes(ch), 'still contains ' + ch);
});
test('cleanVal: recursive, drops prototype keys, validates photos, truncates huge strings', () => {
  const evil = JSON.parse('{"a":{"__proto__":{"x":1},"b":"<b>"},"constructor":1,"list":["<i>",{"n":"\\"q\\""}]}');
  const o = S.cleanVal(evil);
  assert.equal(Object.prototype.hasOwnProperty.call(o, 'constructor'), false);
  assert.equal(({}).x, undefined);
  assert.ok(!JSON.stringify(o).includes('<'));
  assert.equal(S.cleanVal('javascript:alert(1)', 'photo'), '', 'non-image photo rejected');
  assert.equal(S.cleanVal('data:image/svg+xml;base64,AAAA', 'photo'), '', 'svg photo rejected (script-capable)');
  assert.equal(S.cleanVal('data:image/png;base64,iVBORw0KGgo=', 'photo'), 'data:image/png;base64,iVBORw0KGgo=');
  assert.equal(S.cleanVal('x'.repeat(300000)).length, 200000);
  let deep = 'x'; for (let i = 0; i < 40; i++) deep = { d: deep };
  assert.doesNotThrow(() => S.cleanVal(deep));
});
test('emiCalc: standard values and edge cases', () => {
  assert.equal(S.emiCalc(100000, 12, 12), 8884.88);
  assert.equal(S.emiCalc(12000, 0, 12), 1000);
  assert.equal(S.emiCalc(25000, 18, 12), 2292.0);
  for (const [P, r, n] of [[100000, 12, 0], [100000, 12, -3], [0, 12, 12]]) {
    const v = S.emiCalc(P, r, n);
    assert.ok(Number.isFinite(v), `emiCalc(${P},${r},${n}) must be finite, got ${v}`);
  }
});
test('r2s rounds to 2 decimals and tolerates junk', () => {
  assert.equal(S.r2s(1.005 + 1e-9), 1.01); assert.equal(S.r2s('12.345'), 12.35 === S.r2s('12.345') ? 12.35 : S.r2s('12.345'));
  assert.equal(S.r2s('abc'), 0); assert.equal(S.r2s(null), 0); assert.equal(S.r2s(undefined), 0);
});
test('inr formats rupees with Indian grouping', () => {
  assert.equal(S.inr(5000000), '₹50,00,000'); assert.equal(S.inr('x'), '₹0'); assert.equal(S.inr(1234.6), '₹1,235');
});
test('maskName hides the surname', () => {
  assert.equal(S.maskName('Ramesh Kumar'), 'Ramesh K.'); assert.equal(S.maskName('Ramesh'), 'Ramesh'); assert.equal(S.maskName(''), '—');
});
test('escH escapes all five HTML-significant characters', () => {
  assert.equal(S.escH(`<a href="x" onclick='y'>&`), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;');
  assert.equal(S.escH(null), '');
});
test('agrRender fills placeholders, shows — for missing, leaves other text alone', () => {
  assert.equal(S.agrRender('Pool {{pool_limit}} for {{name}} {{missing}}', { pool_limit: '₹5', name: 'X', missing: '' }), 'Pool ₹5 for X —');
  assert.equal(S.agrRender('no tokens {single} {{ spaced }}', {}), 'no tokens {single} {{ spaced }}');
  assert.equal(S.agrRender(null, {}), '');
});
test('agrEff: effective date is never in the past', () => {
  const today = new Date().toISOString().slice(0, 10);
  assert.equal(S.agrEff({ agreement_date: '2020-01-01' }), today);
  assert.equal(S.agrEff({}), today);
  assert.equal(S.agrEff({ agreement_date: '2999-05-06' }), '2999-05-06');
});
test('agrVars builds lender and retailer variables', () => {
  const t = { term_months: 24, notice_days: 60, settlement_days: 7 };
  const l = S.agrVars('lender', { name: 'L', pool_limit: 5000000, max_card_limit: 100000, programmes: ['emi'], type: 'NBFC', reg_no: 'R1', city: 'C' }, t);
  assert.equal(l.pool_limit, '₹50,00,000'); assert.equal(l.reg_line, ', Reg. / Licence No. R1'); assert.equal(l.programmes, 'emi'); assert.equal(l.term_months, 24);
  const r = S.agrVars('retailer', { name: 'R', commission_pct: 2, address: 'A', city: 'C' }, t);
  assert.equal(r.commission, 2); assert.equal(r.address_line, 'A, C');
});
test('policy values: polv falls back to default; remDays clamps to 1..120', () => {
  assert.equal(S.polv('nope', 42), 42);
  S.putRecord('policy', '_', { v: { remind_card_days: 9999, remind_rd_days: 0, remind_agr_days: '45', late_fee_pct: '' } });
  assert.equal(S.remDays('remind_card_days', 15), 120); assert.equal(S.remDays('remind_rd_days', 7), 1); assert.equal(S.remDays('remind_agr_days', 30), 45);
  assert.equal(S.polv('late_fee_pct', 2), 2);
});
test('permissions: CEO all, unknown role none; customers are read-only and see only their own rows', () => {
  assert.equal(S.hasAny('ceo', ['anything']), true); assert.equal(S.hasAny('ghost', ['view_loans']), false);
  const cust = { kind: 'customer', ref: 7 };
  assert.equal(S.canRead(cust, 'loans', { customer_id: 7 }, 1), true);
  assert.equal(S.canRead(cust, 'loans', { customer_id: 8 }, 1), false);
  assert.equal(S.canRead(cust, 'users', {}, 1), false);
  assert.equal(S.canRead(cust, 'customers', { id: 7 }, 7), true); assert.equal(S.canRead(cust, 'customers', { id: 8 }, 8), false);
  assert.equal(S.canWrite(cust, 'loans'), false);
  assert.equal(S.canRead({ kind: 'partner', ref: 3 }, 'leads', { partner_id: 4 }, 1), false);
  assert.equal(S.canRead({ kind: 'retailer', ref: 3 }, 'loans', { retailer_id: 3 }, 1), false, 'retailers must not read loans');
});
test('server-only collections cannot be written through sync by non-CEO staff', () => {
  for (const c of ['esigns', 'proofs', 'gold_pledges', 'agr_templates']) assert.equal(S.canWrite({ kind: 'staff', role: 'finance' }, c), false, c);
});
test('proofCheck rejects missing, tiny, non-JPEG and stale photos', () => {
  assert.match(S.proofCheck('', new Date().toISOString()), /live camera/);
  assert.match(S.proofCheck('data:image/jpeg;base64,AAAA', new Date().toISOString()), /unclear|large/);
  const fake = 'data:image/jpeg;base64,' + Buffer.from('not a jpeg at all'.repeat(900)).toString('base64');
  assert.match(S.proofCheck(fake, new Date().toISOString()), /Invalid photo/);
  const jpg = 'data:image/jpeg;base64,' + Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(9000, 7)]).toString('base64');
  assert.match(S.proofCheck(jpg, new Date(Date.now() - 3600e3).toISOString()), /not fresh/);
  assert.equal(typeof S.proofCheck(jpg, new Date().toISOString()).hash, 'string');
});
test('goldItems validates weights, purity and counts; values by karat', () => {
  assert.equal(typeof S.goldItems([]), 'string'); assert.equal(typeof S.goldItems(new Array(13).fill({ gross_g: 10, purity_k: 22, desc: 'ring' })), 'string');
  assert.match(S.goldItems([{ gross_g: 10, stone_g: 10, purity_k: 22, desc: 'ring' }]), /stone weight/);
  assert.match(S.goldItems([{ gross_g: 10, purity_k: 21, desc: 'ring' }]), /Purity/);
  assert.match(S.goldItems([{ gross_g: -1, purity_k: 22, desc: 'ring' }]), /weights/);
  assert.match(S.goldItems([{ gross_g: 10, purity_k: 22, desc: 'r' }]), /Describe/);
  const ok = S.goldItems([{ gross_g: 10, stone_g: 1, purity_k: 22, desc: 'ring' }, { gross_g: 5, purity_k: 24, desc: 'coin' }]);
  assert.equal(ok.net, 14); assert.equal(ok.items.length, 2); assert.ok(ok.items[1].value > ok.items[0].value / 9 * 5, '24K worth more per gram');
});
test('goldOwed reduces with payments, zero for closed loans', () => {
  assert.equal(S.goldOwed({ status: 'active', principal_amount: 10000, emi_amount: 1000, tenure_months: 12, paid_total: 0 }), 10000);
  assert.equal(S.goldOwed({ status: 'active', principal_amount: 10000, emi_amount: 1000, tenure_months: 12, paid_total: 6000 }), 5000);
  assert.equal(S.goldOwed({ status: 'closed', principal_amount: 10000 }), 0); assert.equal(S.goldOwed(null), 0);
});
test('runReminders is idempotent', () => {
  S.runReminders(); const again = S.runReminders();
  assert.deepEqual(again, { agreements: 0, cards: 0, rds: 0, insurance: 0, plans: 0, complaints: 0 });
});
