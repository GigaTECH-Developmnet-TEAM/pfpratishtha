'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('../helpers');
let S;
test.before(async () => { S = await startServer(); });
test.after(async () => { await S.stop(); });
const pull = async (who, coll) => (await S.pull(who)).changes.filter(c => c.coll === coll).map(c => c.data);

test('9 default documents exist and only known placeholders are used', () => {
  const { PLAN_DOC_DEFAULTS, planDocNorm } = require('../../server.js');
  assert.equal(Object.keys(PLAN_DOC_DEFAULTS).length, 9);
  for (const d of Object.values(PLAN_DOC_DEFAULTS)) { assert.ok(d.clauses.length >= 6, d.id); assert.ok(!planDocNorm(d).error, d.id + ': ' + (planDocNorm(d).error || '')); }
});
test('template edit: CEO only, validated, versioned, reset; unknown placeholder / id rejected', async () => {
  const C = await S.as('ceo'), body = { id: 'privacy', title: 'Privacy Policy', intro: 'Hello {{company}}', clauses: [{ t: 'A', b: 'b' }, { t: 'B', b: 'c <b>x</b>' }] };
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', body, await S.as('hr'))).status, 403);
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', body, await S.as('customer'))).status, 403);
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', { ...body, intro: 'x {{bogus}}' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', { ...body, id: 'nope' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', { ...body, id: '__proto__' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', { ...body, clauses: [] }, C)).status, 400);
  const ok = await S.api('POST', '/api/staff/plan-doc-template', body, C); assert.equal(ok.status, 200); assert.equal(ok.body.doc.version, 1); assert.ok(!/[<>]/.test(JSON.stringify(ok.body.doc)));
  assert.ok((await pull('customer', 'plan_doc_tpl')).some(d => d.id === 'privacy'), 'customer can read templates');
  assert.equal((await S.push('ceo', [{ coll: 'plan_doc_tpl', id: 'terms', data: { id: 'terms', clauses: [] } }])).body.rejected.length, 1, 'raw sync forge');
  assert.equal((await S.api('POST', '/api/staff/plan-doc-template', { id: 'privacy', reset: true }, C)).status, 200);
});
test('complaint register: customer raises, validation, cap, staff resolves, TAT, notifications', async () => {
  const U = await S.as('customer'), C = await S.as('ceo');
  assert.equal((await S.api('POST', '/api/customer/complaint', { subject: 'x', details: 'short' }, U)).status, 400);
  const r = await S.api('POST', '/api/customer/complaint', { subject: 'Receipt not given', details: 'Agent took cash without receipt', category: 'Deposit or receipt', status: 'resolved', customer_id: 2 }, U);
  assert.equal(r.status, 200, JSON.stringify(r.body)); const c = r.body.record;
  assert.match(c.complaint_no, /^PFS-CMP-\d{5}$/); assert.equal(c.status, 'open'); assert.equal(String(c.customer_id), '1'); assert.ok(c.due_date > new Date().toISOString().slice(0, 10));
  assert.ok((await pull('customer', 'complaints')).some(x => x.id === c.id));
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'resolved', note: 'ok ok ok' }, U)).status, 403);
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'resolved', note: 'ok ok ok' }, await S.as('hr'))).status, 403);
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'resolved', note: '' }, C)).status, 400);
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'bogus', note: 'xxxxxx' }, C)).status, 409);
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'in_progress', note: 'Looking into it' }, C)).status, 200);
  const done = await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'resolved', note: 'Receipt issued and agent warned' }, C);
  assert.equal(done.status, 200); assert.equal(done.body.record.within_tat, true); assert.equal(done.body.record.timeline.length, 3);
  assert.equal((await S.api('POST', '/api/staff/complaint-update', { id: c.id, status: 'open', note: 'reopen!' }, C)).status, 409, 'closed cannot reopen');
  for (let i = 0; i < 6; i++) { const x = await S.api('POST', '/api/customer/complaint', { subject: 'Another ' + i, details: 'details details' }, U); if (i === 5) assert.equal(x.status, 409, 'cap of 5 open complaints'); }
});
test('complaints are private: other roles/customers cannot read; sync cannot forge or edit', async () => {
  for (const who of ['partner', 'lender', 'retailer']) assert.equal((await pull(who, 'complaints')).length, 0, who);
  assert.ok((await pull('customer', 'complaints')).every(c => String(c.customer_id) === '1'));
  const mine = (await pull('customer', 'complaints'))[0];
  assert.equal((await S.push('customer', [{ coll: 'complaints', id: String(mine.id), data: { ...mine, status: 'resolved' } }])).body.rejected.length, 1);
  assert.equal((await S.push('ceo', [{ coll: 'complaints', id: '999', isnew: true, data: { id: 999, status: 'open' } }])).body.rejected.length, 1);
  const add = await S.api('POST', '/api/staff/complaint-add', { customer_id: 2, subject: 'Branch walk-in', details: 'Customer visited branch about payout', channel: 'Branch' }, await S.as('ceo')); assert.equal(add.status, 200);
  assert.equal((await S.api('POST', '/api/staff/complaint-add', { customer_id: 1, subject: 'Branch walk-in', details: 'Customer visited branch' }, await S.as('customer'))).status, 403);
});
test('XSS in complaint text is neutralised', async () => {
  const r = await S.api('POST', '/api/staff/complaint-add', { customer_id: 2, subject: '<script>alert(1)</script>Hello', details: '<img src=x onerror=alert(1)> details here' }, await S.as('ceo'));
  assert.equal(r.status, 200); assert.ok(!/[<>]/.test(JSON.stringify(r.body.record)));
});
