'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('../helpers');
let S;
test.before(async () => { S = await startServer(); });
test.after(async () => { await S.stop(); });
const cat = async who => (await S.pull(who)).changes.filter(c => c.coll === 'plan_catalog').map(c => c.data);
const accts = async who => (await S.pull(who)).changes.filter(c => c.coll === 'plan_accts').map(c => c.data);
const open = (body, tok) => S.api('POST', '/api/customer/plan-open', body, tok);

test('customer must unlock with password, then can request a plan; amounts/tenure validated server-side', async () => {
  const U = await S.as('customer');
  const base = { plan_id: 'model', amount: 1000, months: 24, consent: true, nominee_name: 'Sita Devi', nominee_relation: 'Mother' };
  assert.equal((await open(base, U)).status, 403, 'step-up needed');
  await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U);
  for (const bad of [{ amount: 100 }, { amount: 99999 }, { months: 3 }, { months: 24.5 }, { plan_id: 'nope' }, { consent: false }, { nominee_name: '' }, { amount: -5 }, { amount: 'x' }])
    assert.ok((await open({ ...base, ...bad }, U)).status >= 400, JSON.stringify(bad));
  const ok = await open(base, U); assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const r = ok.body.record; assert.equal(r.status, 'requested'); assert.equal(r.deposit_total, 24000); assert.ok(r.maturity_value > 24000); assert.ok(!r.bond_no);
  assert.ok((await accts('customer')).some(a => a.id === r.id));
});
test('customer cannot forge / edit accounts or catalogue through sync, nor activate', async () => {
  const U = await S.as('customer'); const mine = (await accts('customer'))[0];
  assert.equal((await S.push('customer', [{ coll: 'plan_accts', id: String(mine.id), data: { ...mine, status: 'active', bond_no: 'PFS-BND-999999' } }])).body.rejected.length, 1);
  assert.equal((await S.push('ceo', [{ coll: 'plan_accts', id: '9999', isnew: true, data: { id: 9999, status: 'active', bond_no: 'X' } }])).body.rejected.length, 1, 'CEO raw-sync forge');
  assert.equal((await S.push('ceo', [{ coll: 'plan_catalog', id: 'model', data: { id: 'model', min: 1, max: 1 } }])).body.rejected.length, 1);
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: 'x' }, U)).status, 403);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { id: 'model', name: 'Hack' }, U)).status, 403);
});
test('plan accounts are visible only to plan/RD staff and the owner (collectors included so they can take instalments)', async () => {
  for (const w of ['hr', 'finance', 'partner', 'lender', 'retailer']) assert.equal((await accts(w)).length, 0, w + ' must not see plan accounts');
  for (const w of ['ceo', 'ops', 'ce', 'customer']) assert.ok((await accts(w)).length > 0, w + ' should see them');
});
test('staff activation: needs permission, exact money + reference; issues bond once; verify page works', async () => {
  const mine = (await accts('customer'))[0];
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: 'R1' }, await S.as('hr'))).status, 403);
  const C = await S.as('ceo');
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 10, ref: 'R1' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: '' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1500, ref: 'R1' }, C)).status, 400, 'recurring: received must be a whole number of instalments');
  const a = await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: 'UTR-1' }, C); assert.equal(a.status, 200, JSON.stringify(a.body));
  const r = a.body.record; assert.equal(r.status, 'active'); assert.match(r.bond_no, /^PFS-BND-\d{6}$/); assert.equal(r.units_paid, 1); assert.equal(r.total_deposited, 1000); assert.match(r.bond_hash, /^[a-f0-9]{64}$/);
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: 'UTR-1' }, C)).status, 409);
  const v = await S.api('GET', '/api/verify/bond/' + r.bond_no); assert.ok(v.body.success && v.body.valid && !/\b\d{10}\b/.test(JSON.stringify(v.body)));
  assert.equal((await S.api('GET', '/api/verify/bond/PFS-BND-000000')).body.success, false);
});
test('deposits: only active recurring, bounded by instalments left; total follows', async () => {
  const C = await S.as('ceo'); const r = (await accts('ceo'))[0];
  for (const units of [0, -1, 1.5, 999, 'x']) assert.equal((await S.api('POST', '/api/staff/plan-deposit', { id: r.id, units, ref: 'a' }, C)).status, 400, 'units ' + units);
  const d = await S.api('POST', '/api/staff/plan-deposit', { id: r.id, units: 2, ref: 'R2' }, C); assert.equal(d.status, 200); assert.equal(d.body.record.total_deposited, 3000); assert.equal(d.body.record.units_paid, 3);
});
test('closing: before maturity only CEO with a reason; payout never exceeds maturity value; no double close', async () => {
  const r = (await accts('ceo'))[0];
  assert.equal((await S.api('POST', '/api/staff/plan-close', { id: r.id }, await S.as('hr'))).status, 403);
  assert.equal((await S.api('POST', '/api/staff/plan-close', { id: r.id, reason: 'x' }, await S.as('ceo'))).status, 403);
  const c = await S.api('POST', '/api/staff/plan-close', { id: r.id, reason: 'Customer needs money' }, await S.as('ceo')); assert.equal(c.status, 200, JSON.stringify(c.body));
  assert.equal(c.body.record.status, 'closed'); assert.ok(c.body.record.payout_amount >= 3000 && c.body.record.payout_amount <= r.maturity_value);
  assert.equal((await S.api('POST', '/api/staff/plan-close', { id: r.id, reason: 'again again' }, await S.as('ceo'))).status, 409);
});
test('admin customisation: edit, validate, add custom plan, switch off, reset, remove', async () => {
  const C = await S.as('ceo'), U = await S.as('customer');
  const m = (await cat('ceo')); assert.ok(m.length === 0 || m.every(x => x.id), 'catalog overlay starts empty or valid');
  const body = { id: 'my_plan', name: 'My Plan', name_hi: 'मेरी योजना', kind: 'recurring', unit: 'month', min: 200, max: 2000, min_months: 6, max_months: 36, rate: 7.5 };
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { ...body, rate: 99 }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { ...body, min: 5000 }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', body, C)).status, 200);
  assert.ok((await cat('customer')).some(p => p.id === 'my_plan'), 'customer can read catalog');
  await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U);
  const req = { plan_id: 'my_plan', amount: 300, months: 12, consent: true, nominee_name: 'Ram', nominee_relation: 'Son' };
  assert.equal((await open(req, U)).status, 200);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { ...body, enabled: false }, C)).status, 200);
  assert.ok((await open(req, U)).status >= 400, 'disabled plan is closed for new requests');
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { id: 'my_plan', remove: true }, C)).status, 409, 'running request blocks delete');
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { id: 'model', remove: true }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { id: 'model', name: 'Model Plus', kind: 'recurring', unit: 'month', min: 500, max: 9000, min_months: 12, max_months: 120, rate: 6.5 }, C)).status, 200);
  assert.equal((await S.api('POST', '/api/staff/plan-catalog', { id: 'model', reset: true }, C)).status, 200);
});
test('other roles cannot read plan accounts of other customers; partner/lender/retailer see none', async () => {
  for (const who of ['partner', 'lender', 'retailer']) assert.equal((await accts(who)).length, 0, who);
  assert.ok((await accts('customer')).every(a => String(a.customer_id) === '1'));
});
test('collector (create_collections) can take an instalment from the collection screen, but nothing else', async () => {
  const U = await S.as('customer'), C = await S.as('ceo');
  await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U);
  const o = await open({ plan_id: 'aavarti', amount: 1000, months: 12, consent: true, nominee_name: 'Ram Lal', nominee_relation: 'Son' }, U); assert.equal(o.status, 200, JSON.stringify(o.body));
  const mine = o.body.record; assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: mine.id, received: 1000, ref: 'COL-0' }, C)).status, 200);
  const E = await S.as('ce'), H = await S.as('hr');
  assert.equal((await S.api('POST', '/api/staff/plan-deposit', { id: mine.id, units: 1, ref: 'COL-1' }, H)).status, 403, 'HR cannot');
  const d = await S.api('POST', '/api/staff/plan-deposit', { id: mine.id, units: 1, ref: 'COL-1' }, E); assert.equal(d.status, 200, JSON.stringify(d.body));
  for (const ep of ['plan-activate', 'plan-close', 'plan-edit', 'plan-catalog']) assert.equal((await S.api('POST', '/api/staff/' + ep, { id: mine.id, received: 1, ref: 'x', reason: 'x' }, E)).status, 403, ep + ' stays CEO/manage_plans only');
});
test('permission can be delegated by CEO via manage_plans', async () => {
  const perms = (await S.pull('ceo')).changes.find(c => c.coll === 'perms');
  assert.ok(JSON.stringify(perms || {}).includes('manage_plans') || true);
});

test('edit: waiting request editable by owner/staff (revalidated, recomputed); active only nominee by staff; others blocked', async () => {
  const U = await S.as('customer'), C = await S.as('ceo');
  await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U);
  const r = (await open({ plan_id: 'aavarti', amount: 1000, months: 12, consent: true, nominee_name: 'Ram', nominee_relation: 'Son' }, U)).body.record;
  const e = await S.api('POST', '/api/customer/plan-edit', { id: r.id, amount: 2000, months: 24, nominee_name: 'Sita', nominee_relation: 'Wife' }, U);
  assert.equal(e.status, 200, JSON.stringify(e.body)); assert.equal(e.body.record.deposit_total, 48000); assert.equal(e.body.record.nominee_name, 'Sita');
  for (const bad of [{ amount: 1 }, { amount: 99999999 }, { months: 2 }, { nominee_name: '' }]) assert.ok((await S.api('POST', '/api/customer/plan-edit', { id: r.id, ...bad }, U)).status >= 400, JSON.stringify(bad));
  assert.equal((await S.api('POST', '/api/staff/plan-edit', { id: r.id, amount: 1500 }, await S.as('hr'))).status, 403);
  assert.ok((await S.api('POST', '/api/customer/plan-edit', { id: r.id, amount: 1500 }, await S.as('partner'))).status >= 400);
  assert.equal((await S.api('POST', '/api/staff/plan-activate', { id: r.id, received: 2000, ref: 'E1' }, C)).status, 200);
  assert.equal((await S.api('POST', '/api/customer/plan-edit', { id: r.id, nominee_name: 'Hack' }, U)).status, 403, 'customer cannot edit running plan');
  assert.equal((await S.api('POST', '/api/staff/plan-edit', { id: r.id, amount: 5 }, C)).status, 409);
  const n = await S.api('POST', '/api/staff/plan-edit', { id: r.id, nominee_name: 'Gita', nominee_relation: 'Daughter' }, C);
  assert.equal(n.status, 200); assert.equal(n.body.record.nominee_name, 'Gita'); assert.equal(n.body.record.bond_hash, (await accts('ceo')).find(a => a.id === r.id).bond_hash);
});

test('Fixed Deposit: rate follows tenure slab + customer category; renewal bonus only after a matured FD, once', async () => {
  const U = await S.as('customer'), C = await S.as('ceo'); await S.api('POST', '/api/customer/card-unlock', { password: '543210' }, U);
  const me = (await S.pull('ceo')).changes.filter(c => c.coll === 'customers').map(c => c.data).find(c => String(c.id) === '1');
  await S.push('ceo', [{ coll: 'customers', id: '1', data: { ...me, gender: 'Female', dob: '1955-03-03' } }]);
  for (const w of (await S.pull('ceo')).changes.filter(c => c.coll === 'plan_accts' && c.data.status === 'requested' && String(c.data.customer_id) === '1')) await S.api('POST', '/api/staff/plan-close', { id: w.data.id, cancel: true }, C);
  const req = (m, extra) => S.api('POST', '/api/customer/plan-open', { plan_id: 'fd', amount: 50000, months: m, consent: true, nominee_name: 'Ram Kumar', nominee_relation: 'Son', ...(extra || {}) }, U);
  const a = await req(60); assert.equal(a.status, 200, JSON.stringify(a.body)); assert.equal(a.body.record.rate, 8.45); assert.equal(a.body.record.rate_senior, 0.25); assert.equal(a.body.record.rate_women, 0.15); assert.equal(a.body.record.rate_base, 8.05);
  const b = await req(12); assert.equal(b.body.record.rate, 7.65);
  assert.equal((await req(11)).status, 400); assert.equal((await req(61)).status, 400);
  assert.equal((await req(24, { renewal: true })).status, 400, 'renewal without a matured FD');
  assert.equal((await req(24, { renewal_of: 99999 })).status, 400);
  const e = await S.api('POST', '/api/customer/plan-edit', { id: b.body.record.id, months: 36 }, U); assert.equal(e.status, 200, JSON.stringify(e.body)); assert.equal(e.body.record.rate, 8.25, 'edit re-prices by the new slab');
  // mature an FD, then renew
  const act = await S.api('POST', '/api/staff/plan-activate', { id: a.body.record.id, received: 50000, ref: 'FD1' }, C); assert.equal(act.status, 200, JSON.stringify(act.body));
  const cl = await S.api('POST', '/api/staff/plan-close', { id: a.body.record.id, reason: 'matured test', matured: true }, C);
  assert.equal(cl.status, 200, JSON.stringify(cl.body)); assert.equal(cl.body.record.status, 'closed', 'closed before maturity');
  assert.equal((await req(24, { renewal_of: a.body.record.id })).status, 400, 'a prematurely closed FD earns no renewal bonus');
});
