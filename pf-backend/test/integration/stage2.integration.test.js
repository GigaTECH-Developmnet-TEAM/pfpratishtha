'use strict';
// Integration (TDD): Master Data, Group (JLG) loans, Savings accounts.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('../helpers');
const res = r => ({ ok: r.status === 200, applied: (r.body.applied || []).length, rej: (r.body.rejected || []).length, why: (r.body.rejected || []).map(x => x.reason).join('|') });
const rows = async (S, who, coll) => (await S.pull(who)).changes.filter(c => c.coll === coll).map(c => c.data);

test('MST-1 master lists: defaults exist, only the CEO edits, items cleaned and validated, reset works, everyone on staff can read', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo'), O = await S.as('ops');
    let r = await S.api('GET', '/api/staff/masters', undefined, O); assert.equal(r.status, 200); assert.ok(r.body.masters.loan_purpose.items.length >= 5); assert.ok(r.body.masters.occupation.items.includes('Shopkeeper'));
    assert.equal((await S.api('POST', '/api/staff/master', { key: 'occupation', items: ['A'] }, O)).status, 403);
    assert.equal((await S.api('POST', '/api/staff/master', { key: 'occupation', items: ['Farmer', 'Driver', 'driver', '<b>Tailor</b>'] }, C)).status, 200);
    r = await S.api('GET', '/api/staff/masters', undefined, O); assert.deepEqual(r.body.masters.occupation.items, ['Farmer', 'Driver', '＜b＞Tailor＜/b＞'], 'duplicates (case-insens.) dropped, markup defused');
    for (const bad of [{ key: '__proto__', items: ['a'] }, { key: 'nope', items: ['a'] }, { key: 'occupation', items: 'x' }, { key: 'occupation', items: [] }, { key: 'occupation', items: Array.from({ length: 80 }, (_, i) => 'Item' + i) }, { key: 'occupation', items: ['x'.repeat(100)] }, { key: 'occupation', items: [{}, 5] }])
      assert.equal((await S.api('POST', '/api/staff/master', bad, C)).status, 400, JSON.stringify(bad).slice(0, 60));
    assert.equal((await S.api('POST', '/api/staff/master', { key: 'occupation', reset: true }, C)).status, 200);
    assert.ok((await S.api('GET', '/api/staff/masters', undefined, O)).body.masters.occupation.items.includes('Shopkeeper'));
    assert.equal((await S.api('GET', '/api/staff/masters', undefined, await S.as('customer'))).status, 403);
    assert.equal((await S.api('POST', '/api/staff/master', { key: 'occupation', items: ['Z'] }, await S.as('customer'))).status, 403);
  } finally { await S.stop(); }
});

test('GRP-1 groups: validated membership, one active group per customer, leader in group, loans must belong to a member', async () => {
  const S = await startServer(); try {
    const g = (id, o) => ({ coll: 'groups', id: String(id), isnew: true, data: { id, group_code: 'PFS-G-' + String(id).padStart(4, '0'), name: 'Saraswati Mahila Group', leader_id: 1, member_ids: [1, 2, 3], meeting_day: 'Mon', status: 'active', ...(o || {}) } });
    const ids = (await rows(S, 'ceo', 'customers')).filter(c => c.status !== 'deleted').map(c => c.id); assert.ok(ids.length >= 4, 'need seed customers');
    const [a, b, c, d] = ids;
    const base = o => g(7001, { leader_id: a, member_ids: [a, b, c], ...(o || {}) });
    let r = res(await S.push('ops', [base()])); assert.equal(r.applied, 1, JSON.stringify(r));
    for (const [why, o] of [['one member', { member_ids: [a], leader_id: a }], ['unknown member', { member_ids: [a, 987654] }], ['duplicate member', { member_ids: [a, a, b] }], ['leader outside', { leader_id: d, member_ids: [a, b, c] }], ['26 members', { member_ids: Array.from({ length: 26 }, (_, i) => i + 1) }], ['short name', { name: 'ab' }], ['markup name', { name: '<script>x</script>' }], ['bad status', { status: 'hacked' }], ['bad day', { meeting_day: 'Funday' }], ['non-array', { member_ids: 'all' }]]) {
      const x = res(await S.push('ops', [g(7100 + Math.floor(Math.random() * 800), o)])); assert.ok(x.rej === 1 || (why === 'markup name' && x.applied === 1), why + ' → ' + JSON.stringify(x));
    }
    const sneaky = (await rows(S, 'ceo', 'groups')).filter(x => /<script/.test(x.name || '')); assert.equal(sneaky.length, 0);
    r = res(await S.push('ops', [g(7002, { leader_id: b, member_ids: [b, d] })])); assert.ok(r.rej === 1 && /already in group/i.test(r.why), 'member in two active groups: ' + JSON.stringify(r));
    r = res(await S.push('ops', [g(7003, { leader_id: d, member_ids: [d, ids[4] || 999] })])); // ok or reject only if ids[4] missing
    assert.ok(r.applied === 1 || r.rej === 1);
    // loans may carry a group id only when the borrower is a member of an active group
    const mk = (cid, gid, id) => ({ coll: 'loans', id: String(id), isnew: true, data: { id, loan_code: 'T-' + id, customer_id: cid, customer_name: 'X', principal_amount: 5000, interest_rate: 12, tenure_months: 6, emi_amount: 863, status: 'pending', loan_type: 'personal', group_id: gid } });
    assert.equal(res(await S.push('ops', [mk(a, 7001, 7501)])).applied, 1);
    r = res(await S.push('ops', [mk(d, 7001, 7502)])); assert.ok(r.rej === 1 && /member/i.test(r.why), JSON.stringify(r));
    r = res(await S.push('ops', [mk(a, 999999, 7503)])); assert.ok(r.rej === 1, JSON.stringify(r));
    // group cannot be closed while a member loan under it is open
    const cur = (await rows(S, 'ceo', 'groups')).find(x => x.id === 7001);
    r = res(await S.push('ops', [{ coll: 'groups', id: '7001', data: { ...cur, status: 'closed' } }])); assert.ok(r.rej === 1 && /open loan/i.test(r.why), JSON.stringify(r));
    assert.equal(res(await S.push('hr', [base({ name: 'Hacked' })])).applied, 0, 'hr has no group permission');
  } finally { await S.stop(); }
});

test('SAV-1 savings account: open / deposit / withdraw / interest / close with limits, roles, idempotency and an exact running balance', async () => {
  const S = await startServer(); try {
    const C = await S.as('ceo'), O = await S.as('ops'), U = await S.as('customer');
    let r = await S.api('POST', '/api/staff/sav-open', { customer_id: 1, opening: 1000, ref: 'RCPT-1', nominee_name: 'Sita Devi' }, O); assert.equal(r.status, 200, JSON.stringify(r.body));
    const a = r.body.record; assert.match(a.acct_no, /^PFS-SA-\d{6}$/); assert.equal(a.balance, 1000); assert.equal(a.status, 'active'); assert.equal(a.rate, 3.5);
    assert.equal((await S.api('POST', '/api/staff/sav-open', { customer_id: 1, opening: 100, ref: 'x' }, C)).status, 400, 'below minimum opening');
    assert.equal((await S.api('POST', '/api/staff/sav-open', { customer_id: 1, opening: 1000 }, C)).status, 400, 'receipt reference required');
    assert.equal((await S.api('POST', '/api/staff/sav-open', { customer_id: 1, opening: 1000, ref: 'dup' }, C)).status, 409, 'one active savings account per customer');
    assert.equal((await S.api('POST', '/api/staff/sav-open', { customer_id: 2, opening: 1000, ref: 'r' }, await S.as('hr'))).status, 403);
    assert.equal((await S.api('POST', '/api/staff/sav-open', { customer_id: 2, opening: 1000, ref: 'r' }, U)).status, 403);
    const dep = amt => S.api('POST', '/api/staff/sav-deposit', { id: a.id, amount: amt, ref: 'D' + amt + Math.random() }, O);
    assert.equal((await dep(2500.5)).body.record.balance, 3500.5);
    for (const bad of [0, -5, 'abc', null, 1e9, NaN, '1e3x']) assert.equal((await dep(bad)).status, 400, String(bad));
    const wd = (amt, tok, id) => S.api('POST', '/api/staff/sav-withdraw', { id: id || a.id, amount: amt, ref: 'W' + Math.random() }, tok || O);
    assert.equal((await wd(3200)).status, 409, 'would breach the ₹500 minimum balance');
    assert.equal((await wd(1000)).body.record.balance, 2500.5);
    assert.equal((await wd(1e6, C)).status, 409);
    await dep(60000); assert.equal((await wd(25000)).status, 403, 'above ₹20,000 needs the CEO');
    assert.equal((await wd(25000, C)).body.record.balance, 37500.5);
    assert.equal((await wd(30000, C)).status, 409, 'daily withdrawal limit ₹50,000 reached (25,000 + 1,000 + 30,000 > limit 50,000)');
    // statement: every txn has a running balance that reconciles
    const txns = (await rows(S, 'ceo', 'sav_txns')).filter(t => t.acct_id === a.id).sort((x, y) => x.id - y.id); let bal = 0;
    for (const t of txns) { bal = Math.round((bal + (['withdraw', 'close'].includes(t.type) ? -t.amount : t.amount)) * 100) / 100; assert.equal(t.balance_after, bal, 'txn ' + t.id + ' ' + t.type); }
    assert.equal(bal, 37500.5);
    // customer sees only own account and statement
    const mine = await rows(S, 'customer', 'sav_accts'); assert.equal(mine.length, 1); assert.equal(mine[0].customer_id, 1);
    assert.ok((await rows(S, 'customer', 'sav_txns')).every(t => t.customer_id === 1));
    // customer cannot forge anything via sync
    assert.equal(res(await S.push('customer', [{ coll: 'sav_accts', id: String(a.id), data: { ...a, balance: 9e9 } }])).applied, 0);
    assert.equal(res(await S.push('ceo', [{ coll: 'sav_accts', id: String(a.id), data: { ...a, balance: 9e9 } }])).applied, 0, 'even the CEO cannot edit balances through raw sync');
    // interest: once per month, exact, CEO only
    assert.equal((await S.api('POST', '/api/staff/sav-interest-run', {}, O)).status, 403);
    const ym = new Date().toISOString().slice(0, 7);
    let i1 = await S.api('POST', '/api/staff/sav-interest-run', { month: ym }, C); assert.equal(i1.status, 200); assert.equal(i1.body.credited, 1);
    const acc = (await rows(S, 'ceo', 'sav_accts'))[0]; assert.equal(acc.balance, Math.round((37500.5 + 37500.5 * 3.5 / 1200) * 100) / 100);
    const i2 = await S.api('POST', '/api/staff/sav-interest-run', { month: ym }, C); assert.equal(i2.body.credited, 0, 'idempotent per month');
    assert.equal((await S.api('POST', '/api/staff/sav-interest-run', { month: '2999-01' }, C)).status, 400, 'future month');
    // concurrency: parallel withdrawals can never overdraw
    const bal0 = acc.balance; const par = await Promise.all(Array.from({ length: 12 }, (_, i) => wd(4000, C))); const okN = par.filter(x => x.status === 200).length;
    const after = (await rows(S, 'ceo', 'sav_accts'))[0]; assert.ok(after.balance >= 500 && after.balance === Math.round((bal0 - okN * 4000) * 100) / 100);
    // close: CEO only; pays out the balance; no more movement
    assert.equal((await S.api('POST', '/api/staff/sav-close', { id: a.id, reason: 'customer request' }, O)).status, 403);
    const cl = await S.api('POST', '/api/staff/sav-close', { id: a.id, reason: 'customer request' }, C); assert.equal(cl.status, 200); assert.equal(cl.body.record.status, 'closed'); assert.equal(cl.body.record.balance, 0);
    assert.equal((await dep(100)).status, 409); assert.equal((await wd(1, C)).status, 409);
  } finally { await S.stop(); }
});
