'use strict';
// Integration (TDD): Receptionist role + Front Desk (visitors with tokens, appointments, phone messages).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('../helpers');
const rows = async (S, who, coll) => (await S.pull(who)).changes.filter(c => c.coll === coll).map(c => c.data);
const ist = off => new Date(Date.now() + 19800000 + off * 864e5).toISOString().slice(0, 10), today = ist(0), tomorrow = ist(1), yesterday = ist(-1);

test('FD-1 receptionist exists with a small, safe permission set (no money, no loans, no accounting)', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'); assert.ok(R);
    const perms = JSON.parse(require('node:fs').readFileSync(require('node:path').join(__dirname, '../../perms-default.json'), 'utf8')).rc;
    assert.ok(perms.includes('manage_frontdesk') && perms.includes('view_dashboard'));
    for (const bad of ['create_collections', 'approve_loans', 'disburse_loans', 'view_accounting', 'delete_customers', 'edit_customers', 'create_users', 'system_settings', 'view_salary']) assert.ok(!perms.includes(bad), bad);
    for (const coll of ['journal', 'collections', 'loans', 'sav_accts', 'agr_docs', 'customers', 'leads']) assert.equal((await rows(S, 'rc', coll)).length, 0, 'receptionist must not read ' + coll);
    assert.ok((await rows(S, 'rc', 'users')).length <= 1, 'only their own staff record');
    assert.equal((await S.api('POST', '/api/staff/sav-deposit', { id: 1, amount: 100, ref: 'x' }, R)).status, 403);
  } finally { await S.stop(); }
});

test('FD-2 visitor check-in: server tokens are sequential per day; lifecycle waiting → with staff → done; only forward', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'), post = (p, b, t = R) => S.api('POST', '/api/staff/' + p, b, t);
    const a = await post('fd-visitor', { name: 'Ramesh Gupta', mobile: '9876500001', purpose: 'loan_enquiry', meet_user_id: 2, notes: 'Wants ₹2 lakh business loan' });
    assert.equal(a.status, 200, JSON.stringify(a.body)); const v = a.body.record; assert.equal(v.kind, 'visitor'); assert.equal(v.status, 'waiting'); assert.match(v.token, /^T-\d{3}$/); assert.equal(v.date, today);
    const b = await post('fd-visitor', { name: 'Sita', purpose: 'emi_payment' }); assert.notEqual(b.body.record.token, v.token);
    assert.equal(+b.body.record.token.slice(2), +v.token.slice(2) + 1);
    assert.equal((await post('fd-update', { id: v.id, status: 'with_staff' })).status, 200);
    assert.equal((await post('fd-update', { id: v.id, status: 'waiting' })).status, 409, 'cannot go backwards');
    assert.equal((await post('fd-update', { id: v.id, status: 'done' })).status, 200);
    assert.equal((await post('fd-update', { id: v.id, status: 'with_staff' })).status, 409, 'done is final');
    const got = (await rows(S, 'rc', 'fd_entries')).find(x => x.id === v.id); assert.equal(got.status, 'done'); assert.ok(got.start_at && got.out_at);
  } finally { await S.stop(); }
});

test('FD-3 validation, permissions and markup defusing', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'), post = (p, b, t = R) => S.api('POST', '/api/staff/' + p, b, t), ok = { name: 'Ramesh', mobile: '9876500001', purpose: 'loan_enquiry' };
    for (const who of ['customer', 'partner', 'ce', 'finance']) assert.equal((await post('fd-visitor', ok, await S.as(who))).status, 403, who);
    for (const bad of [{ name: '' }, { name: 'A' }, { name: 'x'.repeat(100) }, { purpose: 'steal' }, { purpose: { a: 1 } }, { mobile: '123' }, { mobile: { a: 1 } }, { notes: 'x'.repeat(400) }, { meet_user_id: 9999 }, { meet_user_id: 'abc' }, { customer_id: 9999 }])
      assert.equal((await post('fd-visitor', { ...ok, ...bad })).status, 400, JSON.stringify(bad).slice(0, 40));
    const x = await post('fd-visitor', { ...ok, name: '<img src=x onerror=alert(1)> Co', notes: '<script>1</script>' }); assert.equal(x.status, 200); assert.ok(!/[<>]/.test(JSON.stringify(x.body.record)));
    assert.equal((await post('fd-update', { id: 99999, status: 'done' })).status, 404);
    assert.equal((await post('fd-update', { id: x.body.record.id, status: 'hacked' })).status, 400);
    assert.equal((await post('fd-update', { id: x.body.record.id, status: 'done' }, await S.as('customer'))).status, 403);
  } finally { await S.stop(); }
});

test('FD-4 appointments: no past dates, arrival creates a visitor token once, cancel/no-show are final', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'), post = (p, b) => S.api('POST', '/api/staff/' + p, b, R), ok = { name: 'Geeta Devi', mobile: '9876500002', purpose: 'document_submission', with_user_id: 2, date: tomorrow, time: '11:30' };
    for (const bad of [{ date: yesterday }, { date: 'x' }, { time: '25:00' }, { time: '9:5' }, { time: 5 }, { date: '2026-02-31' }, { with_user_id: 99999 }]) assert.equal((await post('fd-appointment', { ...ok, ...bad })).status, 400, JSON.stringify(bad));
    const a = await post('fd-appointment', ok); assert.equal(a.status, 200); const ap = a.body.record; assert.equal(ap.kind, 'appointment'); assert.equal(ap.status, 'scheduled');
    const arr = await post('fd-update', { id: ap.id, status: 'arrived' }); assert.equal(arr.status, 200); assert.ok(arr.body.visitor && arr.body.visitor.token, 'arrival creates a visitor');
    assert.equal((await post('fd-update', { id: ap.id, status: 'arrived' })).status, 409);
    const all = await rows(S, 'rc', 'fd_entries'); assert.equal(all.filter(x => x.kind === 'visitor' && x.appointment_id === ap.id).length, 1);
    const b = (await post('fd-appointment', ok)).body.record; assert.equal((await post('fd-update', { id: b.id, status: 'cancelled' })).status, 200); assert.equal((await post('fd-update', { id: b.id, status: 'arrived' })).status, 409);
    const c = (await post('fd-appointment', ok)).body.record; assert.equal((await post('fd-update', { id: c.id, status: 'no_show' })).status, 200);
  } finally { await S.stop(); }
});

test('FD-5 phone messages: take → close; callback flag; and convert an enquiry into a lead without duplicates', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'), post = (p, b) => S.api('POST', '/api/staff/' + p, b, R);
    const m = await post('fd-message', { name: 'Mohan Lal', mobile: '9876500003', message: 'Call back about EMI date', for_user_id: 2, callback: true }); assert.equal(m.status, 200); assert.equal(m.body.record.status, 'open'); assert.equal(m.body.record.callback, true);
    assert.equal((await post('fd-message', { name: 'M', message: '' })).status, 400); assert.equal((await post('fd-message', { name: 'Mohan', message: 'x'.repeat(500) })).status, 400);
    assert.equal((await post('fd-update', { id: m.body.record.id, status: 'closed' })).status, 200); assert.equal((await post('fd-update', { id: m.body.record.id, status: 'open' })).status, 409);
    const v = (await post('fd-visitor', { name: 'Ramesh Gupta', mobile: '9876500009', purpose: 'loan_enquiry', notes: 'Business loan 2 lakh' })).body.record;
    const l1 = await post('fd-lead', { id: v.id }); assert.equal(l1.status, 200, JSON.stringify(l1.body)); assert.ok(l1.body.lead_id);
    assert.equal((await post('fd-lead', { id: v.id })).status, 409, 'cannot convert twice');
    const msgOnly = await post('fd-lead', { id: m.body.record.id }); assert.equal(msgOnly.status, 400, 'messages cannot be converted');
    const lead = (await S.pull('ceo')).changes.filter(c => c.coll === 'leads').map(c => c.data).find(x => x.id === l1.body.lead_id); assert.ok(lead && lead.mobile === '9876500009' && lead.source === 'Walk-in');
  } finally { await S.stop(); }
});

test('FD-6 front-desk records are server-only (no sync writes) and the staff directory exposes no secrets', async () => {
  const S = await startServer(); try {
    const R = await S.as('rc'), v = (await S.api('POST', '/api/staff/fd-visitor', { name: 'Ramesh', purpose: 'other' }, R)).body.record;
    const push = (ops, t) => S.api('POST', '/api/sync/push', { ops }, t);
    for (const t of [R, await S.as('ceo')]) { assert.equal((await push([{ coll: 'fd_entries', id: String(v.id), data: { ...v, status: 'done' } }], t)).body.applied.length, 0); assert.equal((await push([{ coll: 'fd_entries', id: '999', isnew: true, data: { id: 999, kind: 'visitor' } }], t)).body.applied.length, 0); }
    const dir = await S.api('GET', '/api/staff/directory', undefined, R); assert.equal(dir.status, 200); assert.ok(dir.body.users.length >= 5);
    for (const u of dir.body.users) assert.deepEqual(Object.keys(u).sort(), ['id', 'name', 'role']);
    assert.equal((await S.api('GET', '/api/staff/directory', undefined, await S.as('customer'))).status, 403);
    for (const who of ['customer', 'partner', 'lender']) assert.equal((await rows(S, who, 'fd_entries')).length, 0);
    const lk = await S.api('GET', '/api/staff/fd-lookup?q=9876', undefined, R); assert.equal(lk.status, 200);
    for (const c of lk.body.customers) assert.deepEqual(Object.keys(c).sort(), ['active_loan', 'city', 'code', 'id', 'mobile', 'name']);
    assert.equal((await S.api('GET', '/api/staff/fd-lookup?q=9876', undefined, await S.as('finance'))).status, 403);
    assert.equal((await S.api('GET', '/api/staff/fd-lookup?q=a', undefined, R)).status, 400, 'query too short');
  } finally { await S.stop(); }
});

test('LIVE-1 the server marks the page as live so demo data / offline demo login never appear in production', async () => {
  const S = await startServer(); try {
    for (const p of ['/', '/index.html', '/c/ABC123']) { const r = await fetch(S.url + p); assert.equal(r.status, 200, p); const t = await r.text(); assert.match(t, /<meta name="pf-live" content="1">/, p); assert.match(t, /<title>/); }
    const html = require('node:fs').readFileSync(require('node:path').join(__dirname, '../../public/index.html'), 'utf8');
    assert.match(html, /const LIVE_HOST = !!document\.querySelector\('meta\[name="pf-live"\]'\)/);
    assert.match(html, /if\(LIVE_HOST\)\{T\('❌ Cannot reach the server/, 'no offline demo login on the live host');
    assert.match(html, /id==='m-pass'&&MUST_CHANGE/, 'forced password change cannot be dismissed');
  } finally { await S.stop(); }
});
