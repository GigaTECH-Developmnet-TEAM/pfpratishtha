'use strict';
// UNIT tests — pure client-side functions of the web app, executed in a real browser (Chromium) against a throw-away server.
const test = require('node:test');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { startServer } = require('../helpers');

let srv, browser, page;
test.before(async () => {
  srv = await startServer();
  browser = await chromium.launch();
  page = await browser.newPage();
  await page.goto(srv.url, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof loanSchedule === 'function' && typeof numWords === 'function');
});
test.after(async () => { await browser?.close(); await srv?.stop(); setImmediate(() => process.exit(0)); });
const ev = (fn, arg) => page.evaluate(fn, arg);

test('numWords: Indian number words', async () => {
  const r = await ev(() => [0, 7, 19, 21, 100, 12345, 35000, 100000, 2500000, 10000000, 123456789].map(numWords));
  assert.deepEqual(r, ['Zero', 'Seven', 'Nineteen', 'Twenty One', 'One Hundred', 'Twelve Thousand Three Hundred Forty Five', 'Thirty Five Thousand', 'One Lakh', 'Twenty Five Lakh', 'One Crore', 'Twelve Crore Thirty Four Lakh Fifty Six Thousand Seven Hundred Eighty Nine']);
});
test('masking helpers hide all but the last digits', async () => {
  const r = await ev(() => [maskAcct('123456789012'), maskAcct('1234'), maskAadhaar('2345 6789 0123'), maskAadhaar('x'), maskPan('ABCPR1234K'), maskPan('')]);
  assert.deepEqual(r, ['XXXXXXXX9012', '1234', 'XXXX XXXX 0123', 'x', 'ABXXXXX34K', '—']);
});
test('esc2 escapes HTML and quotes; handles null', async () => {
  const r = await ev(() => [esc2(`<img src=x onerror="a('b')">&`), esc2(null), esc2(0)]);
  assert.equal(r[0], '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;'); assert.equal(r[1], ''); assert.equal(r[2], '0');
});
test('F formats Indian grouping and compact units', async () => {
  const r = await ev(() => [F(1234567), F('abc'), F(150000, true), F(4500, true), F(999, true)]);
  assert.deepEqual(r, ['12,34,567', '0', '1.5L', '5K', '999']);
});
test('dFmt: ISO dates formatted, blanks become dash, junk is escaped', async () => {
  const r = await ev(() => [dFmt('2026-10-27'), dFmt(''), dFmt(null), dFmt('<b>x</b>')]);
  assert.equal(r[0], '27 Oct 2026'); assert.equal(r[1], '—'); assert.equal(r[2], '—'); assert.ok(!r[3].includes('<'));
});
test('loanSchedule: principal adds up, balance ends at zero, monthly dates', async () => {
  const r = await ev(() => { const s = loanSchedule({ principal_amount: 25000, interest_rate: 18, tenure_months: 12, emi_amount: 2292, disbursement_date: '2026-01-31' }); return { n: s.length, p: Math.round(s.reduce((a, x) => a + x.principal, 0) * 100) / 100, last: s[11].balance, dates: s.map(x => x.due_date), mono: s.every((x, i) => i === 0 || x.balance < s[i - 1].balance) }; });
  assert.equal(r.n, 12); assert.equal(r.p, 25000); assert.equal(r.last, 0); assert.ok(r.mono);
  assert.ok(r.dates.every((d, i) => i === 0 || d > r.dates[i - 1]), 'dates ascending (month-end rollover must not repeat a date)');
});
test('loanSchedule: zero-rate and 1-month loans', async () => {
  const r = await ev(() => [loanSchedule({ principal_amount: 12000, interest_rate: 0, tenure_months: 12, emi_amount: 1000, disbursement_date: '2026-01-01' }).map(x => x.interest).every(v => v === 0), loanSchedule({ principal_amount: 5000, interest_rate: 12, tenure_months: 1, emi_amount: 5050, disbursement_date: '2026-01-01' }).length]);
  assert.deepEqual(r, [true, 1]);
});
test('loanSchedule never produces NaN, even for garbage input', async () => {
  const r = await ev(() => JSON.stringify(loanSchedule({ principal_amount: 'x', interest_rate: undefined, tenure_months: 0 })));
  assert.ok(!/NaN|null|Infinity/.test(r), r);
});
test('rdMaturity: simple interest on deposits', async () => {
  const r = await ev(() => rdMaturity({ daily_amount: 100, total_days: 365, interest_rate: 7 }));
  assert.deepEqual(r, { principal: 36500, interest: 2555, maturityValue: 39055 });
});
test('foreclosureQuote returns finite numbers and total >= outstanding principal', async () => {
  const r = await ev(() => { const l = { id: 99002, loan_code: 'T-2', customer_name: 'T', principal_amount: 50000, interest_rate: 12, tenure_months: 12, emi_amount: 4442, status: 'active', disbursed_on: tdy(), disbursement_date: tdy(), start_date: tdy() }; DL.push(l); const q = foreclosureQuote(l); return { q, bad: Object.entries(q).filter(([k, v]) => typeof v === 'number' && !Number.isFinite(v)).map(([k]) => k) }; });
  assert.deepEqual(r.bad, []); assert.ok(r.q.total >= r.q.principal, JSON.stringify(r.q));
});
test('disbursementQuote: net = principal - fee - gst - e-stamp ₹10', async () => {
  const r = await ev(() => disbursementQuote({ principal_amount: 100000 }));
  assert.equal(r.stamp, 10);
  assert.ok(Math.abs(r.net - (r.principal - r.fee - r.gst - r.stamp)) < 0.005, JSON.stringify(r));
});
test('disbursementQuote: stamp=0 when policy 0 or no principal; never negative', async () => {
  const r = await ev(() => { const o = DPOLICY.stamp_duty; DPOLICY.stamp_duty = 0; const a = disbursementQuote({ principal_amount: 50000 }); DPOLICY.stamp_duty = -5; const b = disbursementQuote({ principal_amount: 50000 }); if (o === undefined) delete DPOLICY.stamp_duty; else DPOLICY.stamp_duty = o; return { a, b, c: disbursementQuote({ principal_amount: 0 }) }; });
  assert.equal(r.a.stamp, 0); assert.equal(r.b.stamp, 0); assert.equal(r.c.stamp, 0);
});
test('postDisbursement: journal balances with stamp line, net recorded on loan', async () => {
  const r = await ev(() => { const l = { id: 99001, loan_code: 'T-1', customer_name: 'T', principal_amount: 50000, interest_rate: 12, tenure_months: 6, emi_amount: 8600, status: 'approved' }; DL.push(l); const q = postDisbursement(l, { date: tdy() }); const j = (typeof DJOURNAL !== 'undefined' ? DJOURNAL : []).find(x => x.id === l.disb_journal); return { q, net: l.net_disbursed, stamp: l.stamp_duty, j: j ? j.lines : null }; });
  assert.equal(r.stamp, 10); assert.equal(r.net, r.q.net);
  if (r.j) { const dr = r.j.reduce((a, x) => a + (x.dr || 0), 0), cr = r.j.reduce((a, x) => a + (x.cr || 0), 0); assert.ok(Math.abs(dr - cr) < 0.01, 'unbalanced ' + dr + ' vs ' + cr); }
});
test('agreement engine: render parity with the server and validity states', async () => {
  const r = await ev(() => {
    const out = { render: agrRender('Pool {{pool_limit}} for {{name}} {{missing}}', { pool_limit: '₹5', name: 'X', missing: '' }) };
    const p = { id: 991, name: 'T', agreement_date: '2020-01-01' };
    DESIGNS.push({ doc_type: 'lender_agreement', ref_id: 991, effective_date: '2020-01-01', signed_at: '2020-01-01T00:00:00Z', snapshot: { term_months: 12 } }); out.expired = agrValidity('lender', p).state;
    DESIGNS.push({ doc_type: 'lender_agreement', ref_id: 992, effective_date: new Date().toISOString().slice(0, 10), signed_at: new Date().toISOString(), snapshot: { term_months: 24 } }); out.valid = agrValidity('lender', { id: 992 }).state;
    DESIGNS.push({ doc_type: 'lender_agreement', ref_id: 993, status: 'void', effective_date: '2026-01-01', signed_at: '2026-01-01T00:00:00Z' }); out.voidIgnored = agrSign('lender', 993) === undefined;
    const d = new Date(); d.setDate(d.getDate() - 340); DESIGNS.push({ doc_type: 'lender_agreement', ref_id: 994, effective_date: d.toISOString().slice(0, 10), signed_at: d.toISOString(), snapshot: { term_months: 12 } }); out.expiring = agrValidity('lender', { id: 994 }).state;
    return out;
  });
  assert.equal(r.render, 'Pool ₹5 for X —'); assert.equal(r.expired, 'expired'); assert.equal(r.valid, 'valid'); assert.equal(r.voidIgnored, true); assert.equal(r.expiring, 'expiring');
});
test('policy accessor: defaults apply, bad values fall back', async () => {
  const r = await ev(() => { const a = pol('gold_ltv_pct'); const old = DPOLICY.late_fee_pct; DPOLICY.late_fee_pct = 'zzz'; const b = pol('late_fee_pct'); DPOLICY.late_fee_pct = old; return [a, b, POLICY_DEFAULT.late_fee_pct]; });
  assert.equal(r[0], 75); assert.equal(r[1], r[2]);
});
test('csvEsc: spreadsheet formula injection is neutralised, numbers/negatives untouched', async () => {
  const r = await ev(() => ['=HYPERLINK("http://x")', '+cmd|calc', '-2+3', '@SUM(A1)', '\tx', '-500', '12.5', 'Ramesh', 'a,b'].map(csvEsc));
  for (const i of [0, 1, 2, 3, 4]) assert.ok(/^"?'/.test(r[i]), 'not neutralised: ' + r[i]);
  assert.equal(r[5], '-500'); assert.equal(r[6], '12.5'); assert.equal(r[7], 'Ramesh'); assert.equal(r[8], '"a,b"');
});

test('static markup has no duplicate element ids (getElementById would hit the wrong field)', async () => {
  const dup = await ev(() => { const seen = {}, d = new Set(); document.querySelectorAll('[id]').forEach(e => { if (seen[e.id]) d.add(e.id); seen[e.id] = 1; }); return [...d]; });
  assert.deepEqual(dup, []);
});

test('no top-level function is declared twice, and every popup gets a close button (back/close everywhere)', async () => {
  const fs = require('node:fs'), path = require('node:path');
  const html = fs.readFileSync(path.join(__dirname, '../../public/index.html'), 'utf8');
  const body = html.slice(html.indexOf('<script>'));
  const names = [...body.matchAll(/^(?:async )?function (\w+)\(/gm)].map(m => m[1]);
  const dup = names.filter((n, i) => names.indexOf(n) !== i);
  assert.deepEqual(dup, [], 'duplicate function declarations: ' + dup);
  assert.match(body, /\.mclose/, 'universal popup close button present');
  assert.match(body, /addEventListener\('popstate'/, 'phone Back handler present');
});

test('receptionist role is wired everywhere, and the branded footer is attached to every printed document', async () => {
  const fs = require('node:fs'), path = require('node:path');
  const html = fs.readFileSync(path.join(__dirname, '../../public/index.html'), 'utf8');
  assert.match(html, /rc:\['dashboard','frontdesk'/, 'rc navigation');
  assert.match(html, /rc:\s+\['dashboard','frontdesk'/, 'rc bottom navigation');
  assert.match(html, /<option value="rc">/, 'role selectable at login and in user forms');
  assert.match(html, /"manage_frontdesk"/, 'permission known to the roles editor');
  assert.match(html, /id="pfs-ftr"/, 'footer markup');
  assert.match(html, /Pratishtha Finance Services<\/b><br>Dream/, 'footer wording');
  assert.match(html, /window\.open=function\(url\)/, 'print windows are intercepted to add the footer');
});
