'use strict';
// Integration (TDD): the six PFS agreement types — templates + issued agreement documents (client, associate, employee/agent, franchise).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { startServer } = require('../helpers');
const DEF = JSON.parse(fs.readFileSync(path.join(__dirname, '../../agreement-defaults.json'), 'utf8'));
const rows = async (S, who, coll) => (await S.pull(who)).changes.filter(c => c.coll === coll).map(c => c.data);
const LIB = ['client', 'associate', 'employee', 'franchise'];

test('AGL-1 templates: all six agreement types exist with substantial, valid English wording', () => {
  for (const id of ['dsa', 'lender', 'retailer', ...LIB]) {
    const t = DEF[id]; assert.ok(t, id); assert.ok(t.clauses.length >= 12, id + ' clauses'); assert.ok(t.title.length > 5);
    assert.ok(t.clauses.every(c => c.t && c.b && c.b.length <= 1500 && !/[ऀ-ॿ]/.test(c.b)), id + ' must be English only');
    assert.ok(t.clauses.some(c => /grievance/i.test(c.t)), id + ' grievance'); assert.ok(t.clauses.some(c => /governing law/i.test(c.t)), id + ' law');
  }
  assert.match(DEF.client.title, /Client Service Agreement/); assert.match(DEF.associate.title, /Business Associate/); assert.match(DEF.employee.title, /Employee.*Agent/); assert.match(DEF.franchise.title, /Branch.*Franchise/); assert.match(DEF.lender.title, /Service Partner/);
});

test('AGL-2 issue → sign → void lifecycle, snapshot rendered, numbers sequential', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo');
    const mk = o => S.api('POST', '/api/staff/agreement-doc', { tpl: 'employee', party_name: 'Ravi Kumar', mobile: '9876500011', address: '12 Gomti Nagar', city: 'Lucknow', party_id: 'ABCDE1234F', role_title: 'Field Agent', territory: 'Lucknow East', fee_text: '2% commission', effective_date: '2026-11-15', ...o }, C);
    const a = await mk(); assert.equal(a.status, 200, JSON.stringify(a.body)); const d = a.body.record;
    assert.match(d.doc_no, /^AGD-\d{5}$/); assert.equal(d.status, 'issued'); assert.equal(d.snapshot.title, DEF.employee.title);
    const text = JSON.stringify(d.snapshot); assert.ok(text.includes('Ravi Kumar') && text.includes('Field Agent') && text.includes('Lucknow East') && !/\{\{/.test(text), 'placeholders rendered');
    const b = await mk({ tpl: 'franchise', party_name: 'Gupta Franchise', amount_text: '₹50,000' }); assert.notEqual(b.body.record.doc_no, d.doc_no);
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: d.id, signed_on: '2026-11-10', witness: 'A. Singh' }, C)).status, 200);
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: d.id, signed_on: '2026-11-10', witness: 'A. Singh' }, C)).status, 409, 'cannot sign twice');
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-void', { id: d.id, reason: 'x' }, C)).status, 400, 'reason needed');
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-void', { id: d.id, reason: 'Wrong party details' }, C)).status, 200);
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: d.id, signed_on: '2026-11-10', witness: 'A. Singh' }, C)).status, 409, 'void cannot be signed');
    const got = (await rows(S, 'ceo', 'agr_docs')); assert.equal(got.length, 2); assert.equal(got.find(x => x.id === d.id).status, 'void');
  } finally { await S.stop(); }
});

test('AGL-3 validation and permissions', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo'), ok = { tpl: 'client', party_name: 'Sita Devi', mobile: '9876500012', city: 'Kanpur', effective_date: '2026-11-15' };
    assert.equal((await S.api('POST', '/api/staff/agreement-doc', ok, await S.as('ops'))).status, 403);
    assert.equal((await S.api('POST', '/api/staff/agreement-doc', ok, await S.as('customer'))).status, 403);
    for (const bad of [{ tpl: 'dsa' }, { tpl: '__proto__' }, { tpl: 'x' }, { party_name: '' }, { party_name: 'A' }, { party_name: 'x'.repeat(200) }, { mobile: '123' }, { mobile: { a: 1 } }, { effective_date: 'tomorrow' }, { effective_date: '2026-02-31' }, { fee_text: 'x'.repeat(300) }, { address: 'x'.repeat(500) }, { customer_id: 99999 }])
      assert.equal((await S.api('POST', '/api/staff/agreement-doc', { ...ok, ...bad }, C)).status, 400, JSON.stringify(bad).slice(0, 50));
    const x = await S.api('POST', '/api/staff/agreement-doc', { ...ok, party_name: '<img src=x onerror=alert(1)> Co', address: '<script>1</script>' }, C); assert.equal(x.status, 200);
    assert.ok(!/[<>]/.test(JSON.stringify(x.body.record)), 'markup defused everywhere');
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: 'nope', signed_on: '2026-11-10', witness: 'W' }, C)).status, 404);
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: x.body.record.id, signed_on: '2999-01-01', witness: 'W' }, C)).status, 400, 'no future signing date');
    assert.equal((await S.api('POST', '/api/staff/agreement-doc-sign', { id: x.body.record.id, signed_on: '2026-11-10', witness: 'W' }, await S.as('ops'))).status, 403);
  } finally { await S.stop(); }
});

test('AGL-4 documents are server-only: not writable through sync, invisible to customers/partners/ops; new templates are editable', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo'); const d = (await S.api('POST', '/api/staff/agreement-doc', { tpl: 'client', party_name: 'Sita Devi', effective_date: '2026-11-15' }, C)).body.record;
    const push = (ops, tok) => S.api('POST', '/api/sync/push', { ops }, tok);
    assert.equal((await push([{ coll: 'agr_docs', id: String(d.id), data: { ...d, status: 'signed' } }], C)).body.applied.length, 0, 'CEO cannot forge status via sync');
    assert.equal((await push([{ coll: 'agr_docs', id: '99', isnew: true, data: { id: 99, status: 'signed' } }], C)).body.applied.length, 0);
    for (const who of ['customer', 'partner', 'ops', 'lender']) assert.equal((await rows(S, who, 'agr_docs')).length, 0, who);
    const body = { id: 'franchise', title: 'Branch / Franchise Agreement', intro: 'Between {{company}} and {{party_name}} at {{party_address}} for {{territory}}', recital: '', term_months: 36, notice_days: 90, settlement_days: 0, clauses: [{ t: 'a', b: '{{fee_text}}' }, { t: 'c', b: '{{amount_text}} {{role_title}} {{party_mobile}} {{party_id}}' }, { t: 'e', b: 'f' }] };
    assert.equal((await S.api('POST', '/api/staff/agreement-template', body, C)).status, 200);
    assert.equal((await S.api('POST', '/api/staff/agreement-template', body, await S.as('ops'))).status, 403);
    const e = await S.api('POST', '/api/staff/agreement-doc', { tpl: 'franchise', party_name: 'Gupta Franchise', address: '5 Mall Road', territory: 'Kanpur', fee_text: '10%', effective_date: '2026-11-15' }, C);
    assert.equal(e.body.record.tpl_version, 1); assert.match(JSON.stringify(e.body.record.snapshot), /5 Mall Road/);
  } finally { await S.stop(); }
});
