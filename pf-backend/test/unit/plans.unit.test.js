'use strict';
// TDD: pure plan engine (written before the implementation).
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os'), path = require('path'), fs = require('fs');
process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pfs-plan-')), 'u.db');
const { planCalc, planCheck, planNorm, PLAN_DEFAULTS, planRateFor, planRenewalCheck, putRecord } = require('../../server.js');

test('10 default plans exist with sane ranges', () => {
  assert.equal(Object.keys(PLAN_DEFAULTS).length, 11);
  for (const p of Object.values(PLAN_DEFAULTS)) { assert.ok(p.min > 0 && p.max >= p.min && p.rate >= 0 && p.max_months >= p.min_months); assert.ok(p.name_hi); }
});
test('recurring monthly: deposits and maturity (annuity-due, monthly compounding)', () => {
  const p = PLAN_DEFAULTS.model; const c = planCalc(p, 500, 12);
  assert.equal(c.deposit, 6000); assert.ok(c.maturity > 6000 && c.maturity < 6400, JSON.stringify(c));
  assert.ok(Math.abs(c.benefit - (c.maturity - c.deposit)) < 0.011);
  const z = planCalc({ ...p, rate: 0 }, 500, 12); assert.equal(z.maturity, 6000); assert.equal(z.benefit, 0);
});
test('recurring daily: deposit = per-day x days in tenure', () => {
  const c = planCalc(PLAN_DEFAULTS.daily, 20, 12); assert.equal(c.units, 365); assert.equal(c.deposit, 7300); assert.ok(c.maturity > 7300);
});
test('income plan: monthly payout, principal returned', () => {
  const c = planCalc(PLAN_DEFAULTS.masik, 12000, 12); assert.equal(c.monthly_payout, 60); assert.equal(c.maturity, 12000); assert.equal(c.benefit, 720);
});
test('certificate: quarterly compounding lump sum', () => {
  const c = planCalc(PLAN_DEFAULTS.vikas, 100000, 120); assert.ok(c.maturity > 180000 && c.maturity < 190000, JSON.stringify(c)); assert.equal(c.deposit, 100000);
});
test('planCalc is monotonic in amount, tenure and rate; never NaN/negative', () => {
  const p = PLAN_DEFAULTS.aavarti; let last = 0;
  for (const m of [6, 12, 24, 60, 120]) { const c = planCalc(p, 1000, m); assert.ok(c.maturity > last); last = c.maturity; }
  assert.ok(planCalc({ ...p, rate: 9 }, 1000, 24).maturity > planCalc(p, 1000, 24).maturity);
  for (const bad of [[0, 12], [-5, 12], [1000, 0], [NaN, 12], ['x', 12], [1000, 1e9]]) { const c = planCalc(p, ...bad); assert.ok(c === null || (Number.isFinite(c.maturity) && c.maturity >= 0), String(bad)); }
});
test('planCheck: amount / tenure windows, fixed tenure list, disabled plan', () => {
  assert.equal(planCheck(PLAN_DEFAULTS.model, 500, 12), '');
  assert.ok(planCheck(PLAN_DEFAULTS.model, 499, 12));       // below min
  assert.ok(planCheck(PLAN_DEFAULTS.model, 5001, 12));      // above max
  assert.ok(planCheck(PLAN_DEFAULTS.model, 1000, 11));      // tenure below min
  assert.ok(planCheck(PLAN_DEFAULTS.model, 1000, 121));
  assert.ok(planCheck(PLAN_DEFAULTS.model, 1000, 12.5));
  assert.equal(planCheck(PLAN_DEFAULTS.aavarti, 1000, 6), '');
  assert.equal(planCheck(PLAN_DEFAULTS.vikas, 5000, 36), ''); assert.ok(planCheck(PLAN_DEFAULTS.vikas, 5000, 24));
  assert.ok(planCheck({ ...PLAN_DEFAULTS.model, enabled: false }, 1000, 12));
  assert.ok(planCheck(PLAN_DEFAULTS.model, 'abc', 12));
});
test('planNorm: validates admin input, strips html, rejects junk', () => {
  const ok = planNorm({ id: 'my_plan', name: 'My <b>Plan</b>', kind: 'recurring', unit: 'month', min: 100, max: 1000, min_months: 6, max_months: 60, rate: 7 });
  assert.ok(ok.plan && !/[<>]/.test(ok.plan.name), JSON.stringify(ok));
  for (const b of [{ id: 'X Y' }, { id: 'a' }, { name: '' }, { kind: 'weird' }, { min: 0 }, { max: 1e12 }, { rate: 99 }, { rate: -1 }, { min_months: 0 }, { max_months: 9999 }, { min: 500, max: 100 }, { tenure_list: [0] }])
    assert.ok(planNorm({ id: 'my_plan', name: 'P', kind: 'recurring', unit: 'month', min: 100, max: 1000, min_months: 6, max_months: 60, rate: 7, ...b }).error, JSON.stringify(b));
});

test('Fixed Deposit: tenure 12–60 months, slab rates, senior / women / renewal extras, headline "up to 8.45%"', () => {
  const fd = PLAN_DEFAULTS.fd; assert.ok(fd); assert.equal(fd.kind, 'certificate'); assert.equal(fd.min_months, 12); assert.equal(fd.max_months, 60);
  const r = (m, c, ren) => planRateFor(fd, m, c, ren);
  const gent = { gender: 'Male', dob: '1990-01-01' }, woman = { gender: 'Female', dob: '1990-01-01' }, senior = { gender: 'Male', dob: '1950-05-05' }, srWoman = { gender: 'female', dob: '1955-01-01' };
  assert.equal(r(12, gent).total, 7.25); assert.equal(r(24, gent).total, 7.6); assert.equal(r(36, gent).total, 7.85); assert.equal(r(60, gent).total, 8.05);
  assert.equal(r(60, woman).women, 0.15); assert.equal(r(60, woman).total, 8.2);
  assert.equal(r(60, senior).senior, 0.25); assert.equal(r(60, senior).total, 8.3);
  assert.equal(r(60, srWoman).total, 8.45, 'senior + woman at the top slab = the advertised maximum');
  assert.equal(r(60, srWoman, true).renewal, 0.15); assert.equal(r(60, srWoman, true).total, 8.6);
  assert.equal(r(12, null).total, 7.25, 'unknown customer details never add extras');
  assert.equal(r(12, { gender: 'Male', dob: 'garbage' }).senior, 0);
  assert.equal(planRateFor(PLAN_DEFAULTS.model, 12, srWoman, true).total, PLAN_DEFAULTS.model.rate, 'plans without extras are unaffected');
  assert.ok(Math.max(...[12, 24, 36, 48, 60].map(m => r(m, srWoman).total)) === 8.45);
  const c = planCalc({ ...fd, rate: 8.45 }, 100000, 60); assert.ok(c.maturity > 150000 && c.maturity < 160000, String(c.maturity));
});
test('catalogue accepts slabs / extras and rejects absurd ones', () => {
  const base = { id: 'fd2', name: 'FD two', kind: 'certificate', min: 1000, max: 100000, min_months: 12, max_months: 60, rate: 7 };
  const ok = planNorm({ ...base, slabs: [{ from: 12, rate: 7 }, { from: 36, rate: 7.5 }], senior_bonus: 0.25, women_bonus: 0.15, renewal_bonus: 0.15 }); assert.ok(ok.plan, JSON.stringify(ok)); assert.equal(ok.plan.slabs.length, 2); assert.equal(ok.plan.senior_bonus, 0.25);
  for (const bad of [{ slabs: [{ from: 12, rate: 99 }] }, { slabs: [{ from: -1, rate: 7 }] }, { slabs: 'x' }, { slabs: Array.from({ length: 20 }, (_, i) => ({ from: 12 + i, rate: 7 })) }, { senior_bonus: 50 }, { women_bonus: -1 }, { renewal_bonus: 'abc' }, { senior_age: 5 }])
    assert.ok(planNorm({ ...base, ...bad }).error, JSON.stringify(bad));
});

test('renewal bonus: only for a matured deposit of the same plan, owned by the customer, once', () => {
  putRecord('plan_accts', '9001', { id: 9001, customer_id: 1, plan_id: 'fd', status: 'matured' });
  putRecord('plan_accts', '9002', { id: 9002, customer_id: 1, plan_id: 'fd', status: 'closed' });
  putRecord('plan_accts', '9003', { id: 9003, customer_id: 2, plan_id: 'fd', status: 'matured' });
  putRecord('plan_accts', '9004', { id: 9004, customer_id: 1, plan_id: 'model', status: 'matured' });
  assert.equal(planRenewalCheck(1, 'fd', 9001), '');
  for (const [c, p, id] of [[1, 'fd', 9002], [1, 'fd', 9003], [1, 'fd', 9004], [1, 'fd', 123456], [1, 'fd', undefined], [2, 'fd', 9001]]) assert.ok(planRenewalCheck(c, p, id), [c, p, id].join());
  putRecord('plan_accts', '9005', { id: 9005, customer_id: 1, plan_id: 'fd', status: 'requested', renewal_of: '9001' });
  assert.match(planRenewalCheck(1, 'fd', 9001), /already/);
});
