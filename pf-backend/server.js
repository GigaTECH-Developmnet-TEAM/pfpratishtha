'use strict';
/**
 * Pratishtha Finance — backend
 * Express + SQLite (node:sqlite, built into Node >= 22.5) — no native modules to compile.
 *
 *  - Real login (scrypt-hashed passwords, JWT, lockout after repeated failures)
 *  - Role-based access enforced on the SERVER (CEO controls permissions)
 *  - Generic record sync used by the web app: /api/sync/pull, /api/sync/push
 *  - Serves the web app itself from /public (same origin => no CORS problems)
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { DatabaseSync } = require('node:sqlite');
const swa = require('@simplewebauthn/server');

// ───────────────────────── config ─────────────────────────
const PORT = +process.env.PORT || 5000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'pratishtha.db');
const ADMIN_MOBILE = process.env.ADMIN_MOBILE || '7233023547';
const ADMIN_NAME = process.env.ADMIN_NAME || 'CEO Pratishtha';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Pratishtha@2025';
const DEFAULT_STAFF_PASSWORD = process.env.DEFAULT_STAFF_PASSWORD || 'Pratishtha@2025';
const SEED_DEMO = String(process.env.SEED_DEMO || 'false') === 'true';
const CORS_ORIGIN = process.env.CORS_ORIGIN || ''; // comma separated list, empty = same-origin only
const IS_PROD = process.env.NODE_ENV === 'production';
if (IS_PROD && SEED_DEMO && process.env.ALLOW_DEMO_IN_PROD !== 'yes-i-understand') { console.error('[FATAL] SEED_DEMO=true creates demo logins with known passwords — refusing to start in production. Set SEED_DEMO=false.'); process.exit(1); }
const TOKEN_TTL = process.env.TOKEN_TTL || '12h';
process.umask(0o077);                                      // every file we create (database, WAL, backups) is private to the service user
if (IS_PROD) {                                             // production refuses unsafe configuration instead of running with known secrets
  const COMMON = /^(password|admin|changeme|change.?this|letmein|welcome|qwerty|pratishtha|123456|put-a-long)/i, DEF = 'Pratishtha@2025', bad = [];
  const strong = (v, n) => typeof v === 'string' && v.length >= n && /[A-Za-z]/.test(v) && /\d/.test(v) && !COMMON.test(v) && v !== DEF;
  if (!strong(process.env.ADMIN_PASSWORD, 12)) bad.push('ADMIN_PASSWORD must be set to a strong, non-default value (12+ characters with letters and digits)');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32 || COMMON.test(process.env.JWT_SECRET)) bad.push('JWT_SECRET must be set to a random string of 32+ characters');
  if (!strong(process.env.DEFAULT_STAFF_PASSWORD, 10)) bad.push('DEFAULT_STAFF_PASSWORD must be set to a non-default value (10+ characters)');
  if (process.env.FACE_ORIGIN && !/^https:\/\//.test(process.env.FACE_ORIGIN)) bad.push('FACE_ORIGIN must be an https:// origin');
  if (bad.length) { for (const b of bad) console.error('[FATAL] ' + b); process.exit(1); }
}

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true, mode: 0o700 });
const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,            -- staff | customer | partner | lender
  ref_id INTEGER NOT NULL,       -- id of the users / customers / partners record
  mobile TEXT NOT NULL,
  role TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  token_ver INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(kind, ref_id)
);
CREATE INDEX IF NOT EXISTS ix_acc_mobile ON accounts(mobile);
CREATE TABLE IF NOT EXISTS webauthn(
  id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, public_key TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT, label TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used TEXT
);
CREATE INDEX IF NOT EXISTS ix_wa_acc ON webauthn(account_id);
CREATE TABLE IF NOT EXISTS records(
  coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
  rev INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(coll,id)
);
CREATE INDEX IF NOT EXISTS ix_rec_rev ON records(rev);
CREATE TABLE IF NOT EXISTS sms_queue(
  id INTEGER PRIMARY KEY AUTOINCREMENT, mobile TEXT NOT NULL, text TEXT NOT NULL, kind TEXT, status TEXT NOT NULL DEFAULT 'queued',
  tries INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, sent_at INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS ix_sms_status ON sms_queue(status, next_at);
CREATE TABLE IF NOT EXISTS gateway_events(pid TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  account_id INTEGER, role TEXT, action TEXT, coll TEXT, rec_id TEXT, ip TEXT
);
`);

const getMeta = k => db.prepare('SELECT v FROM meta WHERE k=?').get(k)?.v;
const setMeta = (k, v) => db.prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v));

let JWT_SECRET = process.env.JWT_SECRET || getMeta('jwt_secret');
if (!JWT_SECRET) { JWT_SECRET = crypto.randomBytes(48).toString('hex'); setMeta('jwt_secret', JWT_SECRET); }
if (!getMeta('rev')) setMeta('rev', 0);
try { db.exec('ALTER TABLE accounts ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0'); } catch { /* already there */ }

// ───────────────────────── helpers ─────────────────────────
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(pw), salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + h.toString('hex');
}
function checkPw(pw, stored) {
  try {
    const [, s, h] = stored.split('$');
    const calc = crypto.scryptSync(String(pw), Buffer.from(s, 'hex'), 64);
    return crypto.timingSafeEqual(calc, Buffer.from(h, 'hex'));
  } catch { return false; }
}
// Stored-XSS defence: the web app renders records with innerHTML / inline handlers, so characters that can
// break out of HTML or a JS string are neutralised on every write (photos are validated separately).
const PHOTO_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
function cleanStr(v) { return v.replace(/[<>"`\\]/g, c => ({ '<': '＜', '>': '＞', '"': '”', '`': '´', '\\': '／' }[c])).replace(/'/g, '’'); }
// credential-like keys are never stored in business records (passwords travel only through the dedicated auth endpoints)
const CRED_KEYS = new Set(['password', 'pass_hash', 'passwd', 'new_password', 'old_password', 'current_password', 'jwt_secret', 'secret', 'token_ver']);
function cleanVal(v, key, depth = 0) {
  if (depth > 12) return null;
  if (typeof v === 'string') {
    if (key === 'photo' || key === 'logo') return v === '' || (v.length <= 400000 && PHOTO_RE.test(v)) ? v : '';
    if ((key === 'aadhaar' || key === 'pan' || key === 'address') && v.startsWith('data:image/')) return v.length <= 400000 && PHOTO_RE.test(v) ? v : '';
    return v.length > 200000 ? v.slice(0, 200000) : cleanStr(v);
  }
  if (Array.isArray(v)) return v.map(x => cleanVal(x, key, depth + 1));
  if (v && typeof v === 'object') { const o = {}; for (const k of Object.keys(v)) { if (k === '__proto__' || k === 'constructor' || k === 'prototype' || CRED_KEYS.has(k)) continue; o[k] = cleanVal(v[k], k, depth + 1); } return o; }
  return v;
}
function pwProblem(pw, mobile) {
  pw = String(pw || '');
  if (pw.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Password must contain both letters and numbers';
  if (mobile && pw.includes(String(mobile))) return 'Password must not contain your mobile number';
  if (/^(password|pratishtha|12345678|qwerty)/i.test(pw)) return 'Password is too easy to guess';
  return null;
}
const DUMMY_HASH = hashPw('not-a-real-password');
const nextRev = () => { const r = +getMeta('rev') + 1; setMeta('rev', r); return r; };
const curRev = () => +getMeta('rev');
const parse = s => { try { return JSON.parse(s); } catch { return null; } };
const audit = (req, action, coll, rec) => {
  try {
    db.prepare('INSERT INTO audit(account_id,role,action,coll,rec_id,ip) VALUES(?,?,?,?,?,?)')
      .run(req.auth?.aid || null, req.auth?.role || null, action, coll || null, rec == null ? null : String(rec), req.ip);
  } catch { /* never break a request for audit */ }
};

// ───────────────────────── record store ─────────────────────────
const stmtGet = db.prepare('SELECT * FROM records WHERE coll=? AND id=?');
const stmtPut = db.prepare(`INSERT INTO records(coll,id,data,rev,deleted) VALUES(?,?,?,?,0)
  ON CONFLICT(coll,id) DO UPDATE SET data=excluded.data, rev=excluded.rev, deleted=0`);
const stmtDel = db.prepare(`INSERT INTO records(coll,id,data,rev,deleted) VALUES(?,?, '{}', ?,1)
  ON CONFLICT(coll,id) DO UPDATE SET data='{}', rev=excluded.rev, deleted=1`);
const putRecord = (coll, id, data) => { const r = nextRev(); stmtPut.run(coll, String(id), JSON.stringify(data), r); return r; };
const delRecord = (coll, id) => { const r = nextRev(); stmtDel.run(coll, String(id), r); return r; };
const getRecord = (coll, id) => { const row = stmtGet.get(coll, String(id)); return row && !row.deleted ? parse(row.data) : null; };

// ───────────────────────── collections & permissions ─────────────────────────
// read:  staff need ANY of these permissions to receive the collection
// write: staff need ANY of these permissions to change it
// 'ceo' always passes. customer / partner accounts are scoped separately below.
const STAFF_ANY = '*';
const COLL = {
  customers:     { read: ['view_customers', 'view_loans', 'view_collections', 'view_kyc', 'view_rd', 'view_receipt', 'view_defaulters', 'create_collections'], write: ['create_customers', 'edit_customers', 'delete_customers', 'verify_kyc', 'create_loans'] },
  kyc_status:    { read: ['view_kyc', 'view_customers', 'verify_kyc'], write: ['verify_kyc', 'create_customers', 'edit_customers'] },
  loans:         { read: ['view_loans', 'view_collections', 'view_defaulters', 'view_kyc', 'view_customers', 'view_accounting'], write: ['create_loans', 'approve_loans', 'disburse_loans', 'create_collections', 'edit_collections'] },
  rds:           { read: ['view_rd', 'view_collections', 'view_customers', 'view_kyc'], write: ['create_rd', 'create_collections'] },
  collections:   { read: ['view_collections', 'view_receipt', 'view_accounting', 'view_customers'], write: ['create_collections', 'edit_collections'] },
  defaulters:    { read: ['view_defaulters', 'view_collections'], write: ['create_collections', 'edit_collections'] },
  notifs:        { read: [STAFF_ANY], write: [STAFF_ANY] },
  branches:      { read: ['view_branches', 'view_users', 'create_users', 'manage_branches'], write: ['manage_branches'] },
  leads:         { read: ['view_leads', 'manage_leads', 'view_marketing', 'view_partners', 'view_reports'], write: ['manage_leads', 'view_leads'] },
  calls:         { read: ['view_leads', 'manage_leads'], write: ['view_leads', 'manage_leads'] },
  campaigns:     { read: ['view_marketing', 'manage_leads'], write: ['view_marketing'] },
  users:         { read: ['view_users', 'create_users', 'edit_users', 'view_attendance', 'view_salary', 'view_roles', 'view_performance', 'manage_salary'], write: ['create_users', 'edit_users', 'delete_users', 'assign_roles'] },
  salary:        { read: ['view_salary', 'manage_salary'], write: ['manage_salary'] },
  leaves:        { read: ['view_attendance', 'edit_users'], write: ['view_attendance', 'edit_users'] },
  leave_balance: { read: ['view_attendance'], write: ['edit_users'] },
  commission:    { read: ['view_commission', 'manage_commission'], write: ['manage_commission'] },
  payouts:       { read: ['view_commission', 'manage_commission', 'view_partners', 'settle_retailers', 'view_retailers', 'manage_payout_rules'], write: ['manage_commission', 'manage_partners', 'settle_retailers', 'manage_payout_rules'] },
  payout_rules:  { read: ['manage_payout_rules', 'view_commission', 'manage_commission', 'view_partners', 'view_retailers', 'view_lenders'], write: ['manage_payout_rules'] },
  partners:      { read: ['view_partners', 'manage_partners', 'view_commission'], write: ['manage_partners'] },
  partner_team:  { read: ['view_partners', 'manage_partners'], write: ['manage_partners'] },
  bank_accounts: { read: ['view_accounting', 'manage_accounting', 'disburse_loans'], write: ['manage_accounting'] },
  vouchers:      { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  acc_bank:      { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  acc_income:    { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  acc_expense:   { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  acc_base:      { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  journal:       { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting', 'create_collections', 'disburse_loans', 'approve_loans', 'manage_commission', 'manage_salary', 'create_rd', 'manage_retailers', 'settle_retailers', 'manage_insurance'] },
  closings:      { read: ['view_accounting', 'manage_accounting'], write: ['manage_accounting'] },
  cards:         { read: ['view_cards', 'manage_cards', 'view_customers'], write: ['manage_cards', 'activate_cards'] },
  lenders:       { read: ['view_lenders', 'manage_lenders'], write: ['manage_lenders'] },
  retailers:     { read: ['view_retailers', 'manage_retailers'], write: ['manage_retailers'] },
  card_txns:     { read: ['view_retailers', 'manage_retailers', 'view_cards', 'manage_cards'], write: ['settle_retailers'] },
  kyc_docs:      { read: ['view_kyc', 'view_customers', 'verify_kyc'], write: ['create_customers', 'edit_customers', 'verify_kyc'] },
  proofs:        { read: ['view_retailers', 'manage_retailers', 'view_cards', 'manage_cards', 'view_loans', 'approve_loans', 'disburse_loans', 'view_kyc', 'view_gold', 'manage_gold'], write: [] },
  gold_pledges:  { read: ['view_gold', 'manage_gold', 'view_loans', 'approve_loans', 'disburse_loans', 'view_collections'], write: [] },   // created / changed only by the gold-loan endpoints   // live proof photos — created by the server only
  comm_log:      { read: ['send_reminders', 'view_collections'], write: ['send_reminders'] },
  mandates:      { read: ['manage_autodebit', 'view_collections', 'view_loans'], write: ['manage_autodebit'] },
  esigns:        { read: ['view_loans', 'view_customers', 'view_partners', 'manage_partners', 'view_lenders', 'manage_lenders', 'view_retailers', 'manage_retailers', 'manage_agreements'], write: [] },
  agr_templates: { read: ['view_partners', 'manage_partners', 'view_lenders', 'manage_lenders', 'view_retailers', 'manage_retailers', 'manage_agreements'], write: [] },
  ins_plans:     { read: [STAFF_ANY], write: ['manage_insurance'] },
  ins_policies:  { read: ['view_insurance', 'manage_insurance', 'view_customers'], write: ['manage_insurance'] },
  ins_claims:    { read: ['view_insurance', 'manage_insurance', 'view_customers'], write: ['manage_insurance'] },
  policy:        { read: [STAFF_ANY], write: ['system_settings'] },
  plan_catalog:  { read: [STAFF_ANY], write: [] },
  plan_doc_tpl:  { read: [STAFF_ANY], write: [] },
  complaints:    { read: ['manage_plans', 'view_customers'], write: [] },
  plan_accts:    { read: ['view_rd', 'manage_plans', 'create_collections'], write: [] },
  agr_docs:      { read: ['manage_agreements'], write: [] },
  fd_entries:    { read: ['manage_frontdesk'], write: [] },
  sav_accts:     { read: ['view_rd', 'manage_plans', 'create_collections'], write: [] },
  sav_txns:      { read: ['view_rd', 'manage_plans', 'create_collections'], write: [] },
  groups:        { read: ['view_customers', 'view_loans', 'create_collections'], write: ['create_loans', 'edit_customers', 'create_customers'] },
  perms:         { read: [STAFF_ANY], write: [] },          // only CEO may write
};
const PARTNER_READ = { agr_templates: null, esigns: 'partner_id', payout_rules: 'partner_id', partners: 'id', partner_team: 'partner_id', payouts: 'partner_id', leads: 'partner_id', notifs: '__own', perms: null };
const PARTNER_WRITE = { leads: 'partner_id', partner_team: 'partner_id' };
const LENDER_READ = { agr_templates: null, esigns: 'lender_id', payout_rules: 'lender_id', payouts: 'lender_id', lenders: 'id', cards: 'lender_id', notifs: '__own', perms: null };
const RETAILER_READ = { agr_templates: null, esigns: 'retailer_id', payout_rules: 'retailer_id', retailers: 'id', card_txns: 'retailer_id', proofs: 'retailer_id', payouts: 'retailer_id', notifs: '__own', perms: null };
const CUSTOMER_READ = { sav_accts: 'customer_id', sav_txns: 'customer_id', customers: 'id', loans: 'customer_id', rds: 'customer_id', collections: 'customer_id', cards: 'customer_id', card_txns: 'customer_id', proofs: 'customer_id', gold_pledges: 'customer_id', ins_policies: 'customer_id', ins_claims: 'customer_id', ins_plans: null, plan_catalog: null, plan_accts: 'customer_id', plan_doc_tpl: null, complaints: 'customer_id', mandates: 'customer_id', esigns: 'customer_id', kyc_status: '__key', notifs: '__own', perms: null };

function livePerms() {
  const rec = getRecord('perms', '_');
  if (rec && rec.v) return rec.v;
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'perms-default.json'), 'utf8'));
}
function hasAny(role, list) {
  if (role === 'ceo') return true;
  if (list.includes(STAFF_ANY)) return true;
  const p = livePerms()[role] || [];
  return list.some(x => p.includes(x));
}
function canRead(auth, coll, rec, id) {
  const def = COLL[coll]; if (!def) return false;
  if (coll === 'notifs' && auth.kind !== 'staff') return !!rec && rec.for_kind === auth.kind && String(rec.for_id) === String(auth.ref);
  if (coll === 'notifs' && auth.kind === 'staff') return !!rec && rec.for_kind === 'staff' && (auth.role === 'ceo' || (!!rec.for_user && String(rec.for_user) === String(auth.ref)) || (!!rec.for_perm && hasAny(auth.role, [rec.for_perm])));
  if (auth.kind === 'staff') return hasAny(auth.role, def.read) || (coll === 'users' && String(id) === String(auth.ref));
  if (auth.kind === 'customer') {
    if (!(coll in CUSTOMER_READ)) return false;
    const f = CUSTOMER_READ[coll]; if (f === null) return true;
    if (f === '__key') return String(id) === String(auth.ref);
    return String(rec?.[f]) === String(auth.ref);
  }
  if (auth.kind === 'partner') {
    if (!(coll in PARTNER_READ)) return false;
    const f = PARTNER_READ[coll]; if (f === null) return true;
    return String(rec?.[f]) === String(auth.ref);
  }
  if (auth.kind === 'lender') {
    if (!(coll in LENDER_READ)) return false;
    const f = LENDER_READ[coll]; if (f === null) return true;
    return String(rec?.[f]) === String(auth.ref);
  }
  if (auth.kind === 'retailer') {
    if (!(coll in RETAILER_READ)) return false;
    const f = RETAILER_READ[coll]; if (f === null) return true;
    return String(rec?.[f]) === String(auth.ref);
  }
  return false;
}
// Records that only the server's own endpoints may create/change (signatures, proofs, pledges, templates) — not even the CEO via raw sync
const SERVER_ONLY = new Set(['fd_entries', 'agr_docs', 'sav_accts', 'sav_txns', 'esigns', 'proofs', 'gold_pledges', 'agr_templates', 'plan_catalog', 'plan_accts', 'plan_doc_tpl', 'complaints']);
function canWrite(auth, coll) {
  const def = COLL[coll]; if (!def) return false;
  if (auth.kind === 'staff') return (auth.role === 'ceo' && !SERVER_ONLY.has(coll)) || (def.write.length > 0 && hasAny(auth.role, def.write));
  if (auth.kind === 'partner') return coll in PARTNER_WRITE;
  if (auth.kind === 'lender') return coll === 'cards';          // further limited row-by-row in /api/sync/push
  return false; // customers are read-only on the server
}

// ───────────────────────── accounts <-> records ─────────────────────────
function ensureAccount(kind, refId, mobile, role, status, password) {
  const ex = db.prepare('SELECT * FROM accounts WHERE kind=? AND ref_id=?').get(kind, refId);
  if (!ex) {
    const pw = password || (kind === 'staff' ? DEFAULT_STAFF_PASSWORD : String(mobile).slice(-6));
    db.prepare('INSERT INTO accounts(kind,ref_id,mobile,role,pass_hash,status,must_change) VALUES(?,?,?,?,?,?,1)')
      .run(kind, refId, mobile, role, hashPw(pw), status || 'active');
    return;
  }
  const bump = (ex.role !== role || ex.status !== (status || 'active') || ex.mobile !== mobile) ? 1 : 0;
  db.prepare('UPDATE accounts SET mobile=?, role=?, status=?, token_ver=token_ver+? WHERE id=?')
    .run(mobile, role, status || 'active', bump, ex.id);
  if (password) db.prepare('UPDATE accounts SET pass_hash=?, failed=0, locked_until=0, token_ver=token_ver+1, must_change=1 WHERE id=?').run(hashPw(password), ex.id);
}
// Everyone may change ONLY the 'photo' field of their own profile record
function selfPhoto(auth, coll, id, op) {
  const own = { users: 'staff', partners: 'partner', customers: 'customer', lenders: 'lender', retailers: 'retailer' }[coll];
  if (!own || auth.kind !== own || String(id) !== String(auth.ref) || op.del || !op.data || typeof op.data !== 'object') return false;
  const cur = getRecord(coll, id); if (!cur) return false;
  if (typeof op.data.photo === 'string' && (op.data.photo.length > 400000 || !op.data.photo.startsWith('data:image/'))) return false;
  const strip = o => { const c = { ...o }; delete c.photo; return JSON.stringify(Object.keys(c).sort().map(k => [k, c[k]])); };
  return strip(cur) === strip(op.data);
}
function afterWrite(coll, id, data, pw) {
  if (coll === 'users' && data) ensureAccount('staff', +id, String(data.mobile), data.role, data.status, pw);
  if (coll === 'customers' && data) ensureAccount('customer', +id, String(data.mobile), 'customer', data.status, pw);
  if (coll === 'partners' && data) ensureAccount('partner', +id, String(data.mobile), 'partner', data.status, pw);
  if (coll === 'retailers' && data) {        // login only once onboarding is complete
    const has = db.prepare("SELECT 1 FROM accounts WHERE kind='retailer' AND ref_id=?").get(+id);
    if (data.status === 'active' || data.status === 'suspended' || has) ensureAccount('retailer', +id, String(data.mobile), 'retailer', data.status === 'active' ? 'active' : 'suspended', pw);
  }
  if (coll === 'lenders' && data) {          // a lender gets a login only when onboarding reaches 'active' (or later 'suspended')
    const has = db.prepare("SELECT 1 FROM accounts WHERE kind='lender' AND ref_id=?").get(+id);
    if (data.status === 'active' || data.status === 'suspended' || has) ensureAccount('lender', +id, String(data.mobile), 'lender', data.status === 'active' ? 'active' : 'suspended', pw);
  }
}
function afterDelete(coll, id) {
  const kind = { users: 'staff', customers: 'customer', partners: 'partner', lenders: 'lender', retailers: 'retailer' }[coll];
  if (kind) db.prepare("UPDATE accounts SET status='deleted', token_ver=token_ver+1 WHERE kind=? AND ref_id=?").run(kind, +id);
}

// ───────────────────────── bootstrap ─────────────────────────
function bootstrap() {
  if (getMeta('bootstrapped')) return;
  // CEO account + record (the CEO is user id 1)
  const ceo = { id: 1, name: ADMIN_NAME, mobile: ADMIN_MOBILE, role: 'ceo', zone: 'HO', status: 'active', employee_id: 'EMP-001' };
  if (SEED_DEMO && fs.existsSync(path.join(__dirname, 'seed.json'))) {
    const seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'seed.json'), 'utf8'));
    const BLOBS = ['defaulters', 'acc_bank', 'acc_income', 'acc_expense', 'acc_base', 'leave_balance', 'policy'];
    for (const [coll, rows] of Object.entries(seed)) {
      if (!COLL[coll]) continue;
      if (BLOBS.includes(coll)) putRecord(coll, '_', { v: rows });
      else if (Array.isArray(rows)) rows.forEach((r, i) => { const id = r.id ?? r.user_id ?? i; putRecord(coll, id, r); afterWrite(coll, id, r); });
      else for (const [k, v] of Object.entries(rows)) putRecord(coll, k, v);
    }
    // demo staff get DEFAULT_STAFF_PASSWORD, demo customers/partners the last 6 digits of their mobile
  }
  const u1 = getRecord('users', 1);
  if (!u1) putRecord('users', 1, ceo);
  const c = getRecord('users', 1) || ceo;
  c.mobile = ADMIN_MOBILE; c.role = 'ceo'; c.status = 'active'; putRecord('users', 1, c);
  ensureAccount('staff', 1, ADMIN_MOBILE, 'ceo', 'active', ADMIN_PASSWORD);
  if (!process.env.ADMIN_PASSWORD) db.prepare('UPDATE accounts SET must_change=1 WHERE kind=\'staff\' AND ref_id=1').run();
  putRecord('perms', '_', { v: JSON.parse(fs.readFileSync(path.join(__dirname, 'perms-default.json'), 'utf8')) });
  if (SEED_DEMO) db.prepare('UPDATE accounts SET must_change=0').run();   // demo data only: no forced password change
  setMeta('bootstrapped', new Date().toISOString());
  console.log(`[bootstrap] done. CEO login: ${ADMIN_MOBILE}  (SEED_DEMO=${SEED_DEMO})`);
  if (!process.env.ADMIN_PASSWORD) console.warn('[WARN] ADMIN_PASSWORD not set — using default. Change it after first login!');
}
bootstrap();

// ───────────────────────── app ─────────────────────────
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
// Production: always https, and the apex domain pratishtha.pro is the canonical host (www → apex)
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(self), geolocation=(self), microphone=(), payment=()'); next(); });
app.use((req, res, next) => {
  if (!IS_PROD || req.path === '/api/health') return next();
  const host = req.hostname;
  const local = host === 'localhost' || /^[\d.]+$/.test(host);
  if (!local && req.protocol !== 'https') return res.redirect(301, 'https://' + req.get('host') + req.originalUrl);
  if (host === 'www.pratishtha.pro') return res.redirect(301, 'https://pratishtha.pro' + req.originalUrl);
  next();
});
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  contentSecurityPolicy: { useDefaults: false, directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com'],
    scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com'],
    imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
    connectSrc: ["'self'", 'https://nominatim.openstreetmap.org', 'https://api.ipify.org', 'https://api.razorpay.com', 'https://lumberjack.razorpay.com'],
    frameSrc: ["'self'", 'blob:', 'https://www.google.com', 'https://api.razorpay.com', 'https://checkout.razorpay.com'],
    objectSrc: ["'none'"], baseUri: ["'none'"], formAction: ["'self'"], frameAncestors: ["'none'"],
  } },
}));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
if (CORS_ORIGIN) app.use(cors({ origin: CORS_ORIGIN.split(',').map(s => s.trim()), credentials: false }));
app.use(express.json({ limit: '6mb', verify: (req, res, buf) => { if (req.originalUrl && req.originalUrl.startsWith('/api/pay/webhook')) req.rawBody = buf; } }));

const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 400, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Too many requests — slow down.' } });
app.use('/api', apiLimiter);
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Too many attempts. Try again later.' } });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  try {
    const p = jwt.verify(t, JWT_SECRET, { algorithms: ['HS256'] });
    const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(p.aid);
    if (!acc || acc.status !== 'active' || acc.token_ver !== p.tv) return res.status(401).json({ success: false, message: 'Session expired' });
    if (acc.must_change && !['/api/auth/change-password', '/api/auth/logout'].includes(req.originalUrl.split('?')[0]))
      return res.status(403).json({ success: false, must_change: true, message: 'Please set a new password first' });
    req.auth = { aid: acc.id, kind: acc.kind, role: acc.role, ref: acc.ref_id };
    next();
  } catch { res.status(401).json({ success: false, message: 'Unauthorized' }); }
}

app.get('/api/health', (req, res) => res.json({ success: true, demo: SEED_DEMO, service: 'pratishtha-finance', time: new Date().toISOString(), rev: curRev() }));

const GHOST = new Map();
app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { mobile, password, role } = req.body || {};
  if (typeof mobile !== 'string' || typeof password !== 'string' || typeof role !== 'string' || !mobile || !password || !role) return res.status(400).json({ success: false, message: 'Mobile, password and role are required' });
  const kind = role === 'customer' ? 'customer' : role === 'partner' ? 'partner' : role === 'lender' ? 'lender' : role === 'retailer' ? 'retailer' : 'staff';
  const acc = db.prepare('SELECT * FROM accounts WHERE mobile=? AND kind=? AND (kind!=\'staff\' OR role=?)').get(String(mobile), kind, role);
  const bad = () => res.status(401).json({ success: false, message: 'Invalid mobile, role or password' });
  if (!acc || acc.status === 'deleted') {
    // unknown accounts get the same lockout behaviour as real ones, so lockout cannot be used to discover valid mobiles
    const gk = kind + '|' + role + '|' + String(mobile).slice(0, 20), now = Date.now(); let g = GHOST.get(gk) || { n: 0, until: 0 };
    if (g.until > now) return res.status(429).json({ success: false, message: 'Account locked for a few minutes after repeated failures' });
    g.n++; if (g.n >= 5) { g.n = 0; g.until = now + 10 * 60 * 1000; } GHOST.set(gk, g); if (GHOST.size > 5000) for (const [k, v] of GHOST) { if (v.until < now) GHOST.delete(k); if (GHOST.size <= 4000) break; }
    checkPw(password, DUMMY_HASH); return bad();
  }
  if (acc.locked_until > Date.now()) return res.status(429).json({ success: false, message: 'Account locked for a few minutes after repeated failures' });
  if (!checkPw(password, acc.pass_hash)) {
    const f = acc.failed + 1;
    db.prepare('UPDATE accounts SET failed=?, locked_until=? WHERE id=?').run(f >= 5 ? 0 : f, f >= 5 ? Date.now() + 10 * 60 * 1000 : 0, acc.id);
    req.auth = { aid: acc.id, role: acc.role }; audit(req, f >= 5 ? 'login_locked' : 'login_failed');
    return bad();
  }
  if (acc.status !== 'active') return res.status(403).json({ success: false, message: `This account is ${acc.status} — contact your admin` });
  db.prepare('UPDATE accounts SET failed=0, locked_until=0 WHERE id=?').run(acc.id);
  issueLogin(req, res, acc, 'login');
});

function issueLogin(req, res, acc, action) {
  const kind = acc.kind;
  const coll = { staff: 'users', customer: 'customers', partner: 'partners', lender: 'lenders', retailer: 'retailers' }[kind];
  const rec = getRecord(coll, acc.ref_id) || {};
  const user = { id: acc.ref_id, name: rec.name || 'User', mobile: acc.mobile, role: kind === 'staff' ? acc.role : kind,
    zone: rec.zone || rec.district || rec.city || '—', employee_id: rec.employee_id || rec.customer_code || rec.partner_code || rec.lender_code || rec.retailer_code || '' };
  const token = jwt.sign({ aid: acc.id, tv: acc.token_ver }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  req.auth = { aid: acc.id, role: user.role };
  audit(req, action, coll, acc.ref_id);
  res.json({ success: true, token, user, must_change: !!acc.must_change });
}

// ───────────────────────── Face / biometric login (WebAuthn platform authenticator) ─────────────────────────
// The browser asks the device itself (Face ID, Windows Hello, Android face/fingerprint unlock) to verify the person;
// the server only stores a public key. Nothing about the face ever leaves the phone. CEO switches it on/off.
const FACE_CH = new Map();   // challenge store (single instance)
const faceCfg = () => {
  let roles = null; try { roles = JSON.parse(getMeta('face_roles') || 'null'); } catch {}
  return { enabled: getMeta('face_enabled') === '1', roles };
};
const faceAllowed = acc => { const c = faceCfg(); return c.enabled && (!Array.isArray(c.roles) || c.roles.includes(acc.kind === 'staff' ? acc.role : acc.kind)); };
const faceRP = req => {
  const rpID = process.env.FACE_RP_ID || (/(^|\.)pratishtha\.pro$/.test(req.hostname) ? 'pratishtha.pro' : req.hostname);   // one passkey for pratishtha.pro and www
  const origin = process.env.FACE_ORIGIN || req.headers.origin || (req.protocol + '://' + req.get('host'));
  return { rpID, origin };
};
const putCh = (data) => { const id = crypto.randomBytes(16).toString('hex'); FACE_CH.set(id, { ...data, exp: Date.now() + 5 * 60 * 1000 });
  for (const [k, v] of FACE_CH) if (v.exp < Date.now()) FACE_CH.delete(k); return id; };
const takeCh = (id, type) => { const c = FACE_CH.get(id); FACE_CH.delete(id); return c && c.exp > Date.now() && c.type === type ? c : null; };
const accFor = (mobile, role) => { const kind = role === 'customer' ? 'customer' : role === 'partner' ? 'partner' : role === 'lender' ? 'lender' : role === 'retailer' ? 'retailer' : 'staff';
  return db.prepare('SELECT * FROM accounts WHERE mobile=? AND kind=? AND (kind!=\'staff\' OR role=?)').get(String(mobile || ''), kind, role); };
const credsOf = aid => db.prepare('SELECT * FROM webauthn WHERE account_id=?').all(aid);
const b64u = u8 => Buffer.from(u8).toString('base64url');

app.get('/api/auth/face/config', (req, res) => { const c = faceCfg(); res.json({ success: true, enabled: c.enabled, roles: c.roles }); });

app.post('/api/auth/face/register-options', auth, async (req, res) => {
  try {
    const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.auth.aid);
    if (!faceAllowed(acc)) return res.status(403).json({ success: false, message: 'Face login is not enabled for your role — ask the CEO' });
    const { rpID } = faceRP(req);
    const options = await swa.generateRegistrationOptions({
      rpName: 'Pratishtha Finance', rpID, userName: acc.mobile, userDisplayName: acc.mobile, userID: new TextEncoder().encode('acc-' + acc.id),
      attestationType: 'none', excludeCredentials: credsOf(acc.id).map(c => ({ id: c.id })),
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    });
    res.json({ success: true, options, ch: putCh({ type: 'reg', aid: acc.id, challenge: options.challenge }) });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Could not start registration' }); }
});

app.post('/api/auth/face/register-verify', auth, async (req, res) => {
  try {
    const c = takeCh(req.body?.ch, 'reg');
    if (!c || c.aid !== req.auth.aid) return res.status(400).json({ success: false, message: 'Request expired — try again' });
    const { rpID, origin } = faceRP(req);
    const v = await swa.verifyRegistrationResponse({ response: req.body.response, expectedChallenge: c.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
    if (!v.verified) return res.status(400).json({ success: false, message: 'Could not verify this device' });
    const cr = v.registrationInfo.credential;
    db.prepare('INSERT OR REPLACE INTO webauthn(id,account_id,public_key,counter,transports,label) VALUES(?,?,?,?,?,?)')
      .run(cr.id, c.aid, b64u(cr.publicKey), cr.counter || 0, JSON.stringify(cr.transports || []), String(req.body.label || 'This device').slice(0, 60));
    audit(req, 'face_register'); res.json({ success: true });
  } catch (e) { console.error(e.message); res.status(400).json({ success: false, message: 'Face / biometric setup failed: ' + e.message }); }
});

app.get('/api/auth/face/mine', auth, (req, res) => {
  res.json({ success: true, devices: credsOf(req.auth.aid).map(c => ({ id: c.id, label: c.label, created_at: c.created_at, last_used: c.last_used })) });
});
app.post('/api/auth/face/remove', auth, (req, res) => {
  db.prepare('DELETE FROM webauthn WHERE id=? AND account_id=?').run(String(req.body?.id || ''), req.auth.aid); audit(req, 'face_remove'); res.json({ success: true });
});

app.post('/api/auth/face/login-options', loginLimiter, async (req, res) => {
  try {
    const acc = accFor(req.body?.mobile, req.body?.role);
    const cs = acc && acc.status === 'active' && faceAllowed(acc) ? credsOf(acc.id) : [];
    if (!cs.length) return res.status(400).json({ success: false, message: 'Face login is not set up for this account on this server. Login with your password first, then enable it in your profile.' });
    const { rpID } = faceRP(req);
    const options = await swa.generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: cs.map(c => ({ id: c.id, transports: JSON.parse(c.transports || '[]') })) });
    res.json({ success: true, options, ch: putCh({ type: 'auth', aid: acc.id, challenge: options.challenge }) });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Could not start face login' }); }
});

app.post('/api/auth/face/login-verify', loginLimiter, async (req, res) => {
  const fail = m => res.status(401).json({ success: false, message: m || 'Face login failed' });
  try {
    const c = takeCh(req.body?.ch, 'auth'); if (!c) return fail('Request expired — try again');
    const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(c.aid);
    if (!acc || acc.status !== 'active' || acc.must_change || !faceAllowed(acc)) return fail();
    if (acc.locked_until > Date.now()) return res.status(429).json({ success: false, message: 'Account locked for a few minutes after repeated failures' });
    const cred = db.prepare('SELECT * FROM webauthn WHERE id=? AND account_id=?').get(String(req.body?.response?.id || ''), acc.id); if (!cred) return fail();
    const { rpID, origin } = faceRP(req);
    const v = await swa.verifyAuthenticationResponse({ response: req.body.response, expectedChallenge: c.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
      credential: { id: cred.id, publicKey: Buffer.from(cred.public_key, 'base64url'), counter: cred.counter, transports: JSON.parse(cred.transports || '[]') } });
    if (!v.verified) return fail();
    db.prepare('UPDATE webauthn SET counter=?, last_used=CURRENT_TIMESTAMP WHERE id=?').run(v.authenticationInfo.newCounter, cred.id);
    issueLogin(req, res, acc, 'login_face');
  } catch (e) { console.error(e.message); fail(); }
});

// CEO controls
app.get('/api/admin/face', auth, (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false });
  const c = faceCfg();
  const rows = db.prepare('SELECT a.id, a.kind, a.role, a.mobile, a.ref_id, COUNT(w.id) n FROM accounts a JOIN webauthn w ON w.account_id=a.id GROUP BY a.id').all()
    .map(r => ({ account_id: r.id, role: r.kind === 'staff' ? r.role : r.kind, mobile: r.mobile, devices: r.n,
      name: (getRecord({ staff: 'users', customer: 'customers', partner: 'partners', lender: 'lenders', retailer: 'retailers' }[r.kind], r.ref_id) || {}).name || r.mobile }));
  res.json({ success: true, enabled: c.enabled, roles: c.roles, registered: rows });
});
app.post('/api/admin/face', auth, (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false });
  setMeta('face_enabled', req.body?.enabled ? '1' : '0');
  if ('roles' in (req.body || {})) setMeta('face_roles', JSON.stringify(Array.isArray(req.body.roles) ? req.body.roles : null));
  audit(req, 'face_config', 'meta', req.body?.enabled ? 'on' : 'off'); res.json({ success: true });
});
app.post('/api/admin/face/reset', auth, (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false });
  db.prepare('DELETE FROM webauthn WHERE account_id=?').run(+req.body?.account_id || 0); audit(req, 'face_reset'); res.json({ success: true });
});

app.post('/api/auth/logout', auth, (req, res) => {   // invalidates every token of this account
  db.prepare('UPDATE accounts SET token_ver=token_ver+1 WHERE id=?').run(req.auth.aid); try { CARD_STEPUP.delete(req.auth.aid); } catch {} audit(req, 'logout'); res.json({ success: true });
});
app.post('/api/auth/send-otp', loginLimiter, (req, res) => res.json({ success: false, message: 'OTP login is not configured — use password login' }));

app.post('/api/auth/change-password', auth, (req, res) => {
  const { old_password, new_password } = req.body || {};
  const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.auth.aid);
  const prob = pwProblem(new_password, acc.mobile); if (prob) return res.status(400).json({ success: false, message: prob });
  if (String(new_password) === String(old_password)) return res.status(400).json({ success: false, message: 'New password must be different from the current one' });
  if (acc.locked_until > Date.now()) return res.status(429).json({ success: false, message: 'Locked for a few minutes after repeated wrong passwords' });
  if (!checkPw(String(old_password || ''), acc.pass_hash)) {
    const f = acc.failed + 1;
    db.prepare('UPDATE accounts SET failed=?, locked_until=? WHERE id=?').run(f >= 5 ? 0 : f, f >= 5 ? Date.now() + 10 * 60 * 1000 : 0, acc.id);
    audit(req, f >= 5 ? 'change_pw_locked' : 'change_pw_failed');
    return res.status(f >= 5 ? 429 : 400).json({ success: false, message: f >= 5 ? 'Too many wrong attempts — locked for 10 minutes' : 'Current password is wrong' });
  }
  db.prepare('UPDATE accounts SET pass_hash=?, token_ver=token_ver+1, must_change=0, failed=0 WHERE id=?').run(hashPw(new_password), acc.id);
  audit(req, 'change_password');
  const token = jwt.sign({ aid: acc.id, tv: acc.token_ver + 1 }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  res.json({ success: true, token });
});

// Admin: reset somebody's password  (CEO, or staff with edit_users; customers/partners: edit_customers / manage_partners)
app.put('/api/users/:id/reset-password', auth, (req, res) => resetPw(req, res, 'staff', ['edit_users']));
app.put('/api/customers/:id/reset-password', auth, (req, res) => resetPw(req, res, 'customer', ['edit_customers']));
app.put('/api/partners/:id/reset-password', auth, (req, res) => resetPw(req, res, 'partner', ['manage_partners']));
app.put('/api/retailers/:id/reset-password', auth, (req, res) => resetPw(req, res, 'retailer', ['manage_retailers']));
app.put('/api/lenders/:id/reset-password', auth, (req, res) => resetPw(req, res, 'lender', ['manage_lenders']));
function resetPw(req, res, kind, perms) {
  if (req.auth.kind !== 'staff' || !hasAny(req.auth.role, perms)) return res.status(403).json({ success: false, message: 'Not allowed' });
  const pw = req.body?.password;
  const rp = pwProblem(pw, null); if (rp) return res.status(400).json({ success: false, message: rp });
  const acc = db.prepare('SELECT * FROM accounts WHERE kind=? AND ref_id=?').get(kind, +req.params.id);
  if (!acc) return res.status(404).json({ success: false, message: 'Account not found' });
  if (acc.kind === 'staff' && acc.role === 'ceo' && req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only CEO can reset the CEO password' });
  db.prepare('UPDATE accounts SET pass_hash=?, failed=0, locked_until=0, token_ver=token_ver+1, must_change=1 WHERE id=?').run(hashPw(pw), acc.id);
  audit(req, 'reset_password', kind, req.params.id);
  res.json({ success: true });
}

// ─── sync ───
app.get('/api/sync/pull', auth, (req, res) => {
  const since = Math.max(0, +req.query.since || 0);
  const cursor = curRev();
  const rows = db.prepare('SELECT coll,id,data,rev,deleted FROM records WHERE rev>? ' + (since === 0 ? 'AND deleted=0 ' : '') + 'ORDER BY rev').all(since);
  const changes = [];
  for (const r of rows) {
    if (!COLL[r.coll]) continue;
    const data = r.deleted ? null : parse(r.data);
    if (!r.deleted && !canRead(req.auth, r.coll, data, r.id)) continue;
    if (r.deleted && req.auth.kind === 'staff' && !hasAny(req.auth.role, COLL[r.coll].read)) continue;
    changes.push({ coll: r.coll, id: r.id, rev: r.rev, deleted: !!r.deleted, data });
  }
  res.json({ success: true, cursor, full: since === 0, changes });
});

app.post('/api/sync/push', auth, (req, res) => {
  const ops = Array.isArray(req.body?.ops) ? req.body.ops : [];
  if (ops.length > 2000) return res.status(413).json({ success: false, message: 'Too many operations' });
  const applied = [], rejected = [], remap = []; let settleSum = 0;
  db.exec('BEGIN');
  try {
    for (const op of ops) {
      const { coll, id } = op || {};
      if (!COLL[coll] || id == null) { rejected.push({ coll, id, reason: 'unknown collection' }); continue; }
      if (!canWrite(req.auth, coll) && !selfPhoto(req.auth, coll, id, op)) { rejected.push({ coll, id, reason: 'permission denied' }); continue; }
      let existing = getRecord(coll, id);
      if (coll === 'loans' && op.data && typeof op.data === 'object' && !op.del) {
        const d = op.data, RNG = { principal_amount: [0, 1e9], amount: [0, 1e9], emi_amount: [0, 1e9], total_payable: [0, 1e10], outstanding_amount: [0, 1e10], outstanding: [0, 1e10], paid_total: [0, 1e10], penalty_paid: [0, 1e9], proc_fee: [0, 1e8], gst_on_fee: [0, 1e8], stamp_duty: [0, 1e5], net_disbursed: [0, 1e9], processing_fee: [0, 1e8], tenure_months: [1, 600], tenure: [1, 600], interest_rate: [0, 100], paid_emis: [0, 600] };
        const badNum = Object.keys(RNG).find(k => { const v = d[k]; if (v === undefined || v === null || v === '') return false; const n = Number(v); return !Number.isFinite(n) || n < RNG[k][0] || n > RNG[k][1]; });
        if (badNum) { rejected.push({ coll, id, reason: 'invalid number in ' + badNum }); continue; }
        if (d.group_id != null && d.group_id !== '') { const gr = getRecord('groups', String(d.group_id)); if (!gr || gr.status !== 'active' || !(gr.member_ids || []).map(Number).includes(Number(d.customer_id))) { rejected.push({ coll, id, reason: 'The borrower must be a member of the active group' }); continue; } }
        if (d.net_disbursed != null && d.net_disbursed !== '' && +d.net_disbursed > (+d.principal_amount || +d.amount || 0) + 0.005) { rejected.push({ coll, id, reason: 'net disbursed cannot exceed the sanctioned amount' }); continue; }
        for (const k of ['estamp_no', 'estamp_state', 'disb_ref', 'disb_bank', 'disb_ifsc']) if (typeof d[k] === 'string' && d[k].length > 60) d[k] = d[k].slice(0, 60);
        if (req.auth.role !== 'ceo') {   // loan workflow: apply → approve → disburse, each by the person who holds that permission
          const os = existing ? existing.status : null, ns = d.status;
          if (ns !== os) {
            if (ns === 'approved' && !hasAny(req.auth.role, ['approve_loans'])) { rejected.push({ coll, id, reason: 'you cannot approve loans' }); continue; }
            if (ns === 'active' && (!os || os === 'pending' || os === 'rejected' || os === 'draft')) { rejected.push({ coll, id, reason: 'a loan must be approved before it can go active' }); continue; }
            if (ns === 'active' && os === 'approved' && !hasAny(req.auth.role, ['disburse_loans'])) { rejected.push({ coll, id, reason: 'you cannot disburse loans' }); continue; }
          }
        }
      }
      let opId = id;
      if (op.isnew && existing && op.data && typeof op.data === 'object' && /^\d+$/.test(String(id)) && !op.del) {
        // someone else created a record with this id a moment ago → give this new record the next free id
        const mx = db.prepare('SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll=?').get(coll).m || 0;
        opId = String(mx + 1); op.data.id = +opId; remap.push({ coll, from: String(id), to: +opId }); existing = null;
        op.id = opId;
      }
      if (req.auth.kind === 'partner' && coll in PARTNER_WRITE) {            // partners may only touch their own rows
        const f = PARTNER_WRITE[coll];
        if (existing && String(existing[f]) !== String(req.auth.ref)) { rejected.push({ coll, id, reason: 'not your record' }); continue; }
        if (op.data) op.data[f] = req.auth.ref;
      }
      if (coll === 'cards') {
        if (req.auth.kind === 'lender') {                                      // a lender may only decide requests that were sent to it
          if (op.del || !existing || String(existing.lender_id) !== String(req.auth.ref) || existing.status !== 'lender_review') { rejected.push({ coll, id, reason: 'not your card request' }); continue; }
          const nd = op.data || {}, lend = getRecord('lenders', req.auth.ref) || {};
          if (!['approved', 'rejected'].includes(nd.status)) { rejected.push({ coll, id, reason: 'invalid decision' }); continue; }
          let lim = null;
          if (nd.status === 'approved') {
            lim = Math.round((+nd.limit || 0) * 100) / 100;
            const cap = +lend.max_card_limit || 0, pool = +lend.pool_limit || 0;
            const used = db.prepare("SELECT data FROM records WHERE coll='cards' AND deleted=0").all().map(r => parse(r.data)).filter(c => c && String(c.lender_id) === String(req.auth.ref) && String(c.id) !== String(existing.id) && ['approved', 'inactive', 'active'].includes(c.status)).reduce((s, c) => s + (+c.limit || 0), 0);
            if (!(lim > 0) || (cap && lim > cap)) { rejected.push({ coll, id, reason: 'limit must be between 1 and ₹' + cap }); continue; }
            if (pool && used + lim > pool) { rejected.push({ coll, id, reason: 'exceeds your programme pool limit' }); continue; }
          }
          op.data = { ...existing, status: nd.status, limit: lim, remarks: String(nd.remarks || '').slice(0, 120), lender_decision_date: new Date().toISOString().slice(0, 10), lender_decision_by: String(nd.lender_decision_by || '').slice(0, 60) };
        } else if (op.data && !op.del) {
          const to = op.data.status, from = existing && existing.status;
          if (to === 'active' && from !== 'active' && !(req.auth.role === 'ceo' || hasAny(req.auth.role, ['activate_cards']))) { rejected.push({ coll, id, reason: 'only CEO / Admin can activate a card' }); continue; }
          if (existing && existing.status === 'lender_review' && to && to !== 'lender_review' && to !== 'rejected' && to !== 'blocked') { rejected.push({ coll, id, reason: 'waiting for the lender’s decision' }); continue; }
          if (op.data.lender_id && ['emi', 'shopping'].includes(op.data.type) && ['inactive', 'active'].includes(to) && from !== to && !(existing && ['approved', 'inactive', 'active', 'blocked'].includes(from))) { rejected.push({ coll, id, reason: 'card needs the lender’s approval first' }); continue; }
        }
      }
      if (coll === 'lenders' && op.data && !op.del) {
        if (op.data.status === 'active') {
          const st = op.data.stages || {};
          if (!(st.kyc && st.agreement && st.credit)) { rejected.push({ coll, id, reason: 'complete KYC, agreement and credit approval before go-live' }); continue; }
          if (!/^\d{10}$/.test(String(op.data.mobile || ''))) { rejected.push({ coll, id, reason: 'valid 10-digit mobile needed for the lender login' }); continue; }
        }
      }
      if (coll === 'retailers' && op.data && !op.del) {
        if (op.data.status === 'active') {
          const st = op.data.stages || {};
          if (!(st.kyc && st.agreement)) { rejected.push({ coll, id, reason: 'complete KYC and agreement before go-live' }); continue; }
          if (!/^\d{10}$/.test(String(op.data.mobile || ''))) { rejected.push({ coll, id, reason: 'valid 10-digit mobile needed for the retailer login' }); continue; }
        }
      }
      if (coll === 'policy' && op.data && typeof op.data === 'object' && !op.del) {
        const CAP = { stamp_duty: 1000, proc_fee_pct: 10, gst_pct: 40, late_fee_pct: 20, foreclosure_pct: 20, card_emerg_max: 25000, card_emerg_rate: 48, card_purchase_rate: 48, card_emerg_tenure: 6, card_txn_max: 200000, gold_ltv_pct: 75, gold_rate_pct: 48, gold_rate_22k: 30000, gold_max_loan: 5000000, grace_days: 60, lock_days: 365, remind_agr_days: 120, remind_card_days: 120, remind_rd_days: 120, remind_ins_days: 120, grievance_days: 90 };
        const pv = op.data.v && typeof op.data.v === 'object' ? op.data.v : {};
        const bad = Object.keys(pv).find(k => { const v = pv[k]; if (v === null || v === '' || typeof v === 'object') return false; const n = Number(v); return !Number.isFinite(n) || n < 0 || n > (CAP[k] ?? 1e8); });
        if (bad) { rejected.push({ coll, id, reason: 'invalid value for setting ' + bad }); continue; }
      }
      if (coll === 'gold_pledges') { rejected.push({ coll, id, reason: 'gold pledges change only through the gold-loan actions' }); continue; }
      if (coll === 'loans' && existing && op.data && !op.del && existing.loan_type === 'gold') { const gp = getRecord('gold_pledges', String(existing.gold_id)); op.data.gold_id = existing.gold_id; op.data.loan_type = 'gold'; if (op.data.status === 'active' && existing.status !== 'active' && (!gp || gp.status !== 'vaulted')) { rejected.push({ coll, id, reason: 'gold must be sealed in the vault before this loan is disbursed' }); continue; } if (+op.data.principal_amount !== +existing.principal_amount && existing.status !== 'pending') { rejected.push({ coll, id, reason: 'a gold loan amount cannot change after approval' }); continue; } }
      if (coll === 'proofs') { rejected.push({ coll, id, reason: 'proof photos are captured live in the app and cannot be edited' }); continue; }
      if (existing && op.data && !op.del && (coll === 'loans' || coll === 'card_txns')) { if (existing.proof_id != null) { op.data.proof_id = existing.proof_id; op.data.has_proof = true; } else { delete op.data.proof_id; delete op.data.has_proof; } }
      if (coll === 'loans' && existing && op.data && !op.del && existing.source === 'card_emergency' && existing.status !== 'active' && op.data.status === 'active' && !existing.proof_id && req.auth.role !== 'ceo') { rejected.push({ coll, id, reason: 'this cash loan has no live proof photo — only the CEO can release it' }); continue; }
      if (coll === 'card_txns') {                // transactions are created by the retailer/customer endpoints only; staff may only settle (returns use /api/retailers/txn-return)
        if (op.del || !existing) { rejected.push({ coll, id, reason: 'transactions cannot be created or deleted here' }); continue; }
        const nd = op.data || {};
        const same = ['amount', 'retailer_id', 'card_id', 'customer_id', 'loan_id', 'txn_code', 'commission_pct'].every(k => String(nd[k]) === String(existing[k]));
        if (!same || existing.status !== 'approved' || nd.status !== 'settled') { rejected.push({ coll, id, reason: 'only approved payments can be marked settled' }); continue; }
        if (!existing.proof_id && req.auth.role !== 'ceo') { rejected.push({ coll, id, reason: existing.txn_code + ' has no live proof photo — only the CEO can settle it' }); continue; }
        settleSum += (+existing.amount || 0) * (1 - (+existing.commission_pct || 0) / 100);
        if (req.auth.role !== 'ceo' && settleSum > polv('settle_cap', 50000)) { rejected.push({ coll, id, reason: 'settlements above ₹' + polv('settle_cap', 50000) + ' need CEO approval' }); continue; }
      }
      if (coll === 'payout_rules' && op.data && !op.del) {
        const d = op.data, ids = ['partner_id', 'retailer_id', 'lender_id'].filter(k => d[k] != null && d[k] !== '');
        const tbl = { partner_id: 'partners', retailer_id: 'retailers', lender_id: 'lenders' };
        if (ids.length !== 1 || !getRecord(tbl[ids[0]], d[ids[0]])) { rejected.push({ coll, id, reason: 'choose exactly one existing partner / retailer / lender' }); continue; }
        if (!RULE_BASIS[d.basis]) { rejected.push({ coll, id, reason: 'unknown payout basis' }); continue; }
        const rt = +d.rate; if (!(rt >= 0) || (/pct/.test(d.basis) && rt > 100) || rt > 10000000) { rejected.push({ coll, id, reason: 'enter a valid rate / amount' }); continue; }
        if (String(d.reason || '').trim().length < 3) { rejected.push({ coll, id, reason: 'enter why this payout is given' }); continue; }
        d.status = d.status === 'paused' ? 'paused' : 'active';
      }
      if (coll === 'payouts' && op.data && !op.del) {
        const ex = getRecord('payouts', id), d = op.data;
        if (!ex) {
          const ids = ['partner_id', 'retailer_id', 'lender_id'].filter(k => d[k] != null && d[k] !== '');
          const tbl = { partner_id: 'partners', retailer_id: 'retailers', lender_id: 'lenders' };
          if (d.kind !== 'award' || !hasAny(req.auth.role, ['manage_payout_rules'])) { rejected.push({ coll, id, reason: 'payout claims are raised by the partner / retailer; awards need payout-rule access' }); continue; }
          if (ids.length !== 1 || !getRecord(tbl[ids[0]], d[ids[0]]) || !(+d.amount >= 1) || +d.amount > 10000000 || String(d.reason || '').trim().length < 3) { rejected.push({ coll, id, reason: 'an award needs one party, an amount and a reason' }); continue; }
          d.status = 'approved'; d.payout_code = payCode(id); d.date = todayS(); d.awarded_by = String(req.auth.name || req.auth.role);
        } else {
          const ok = ['pending', 'approved'].includes(ex.status) && ['paid', 'rejected'].includes(d.status) && ['amount', 'partner_id', 'retailer_id', 'lender_id', 'party', 'payout_code', 'kind', 'reason'].every(k => String(d[k] ?? '') === String(ex[k] ?? ''));
          const same = ex.status === d.status;
          if (!ok && !same) { rejected.push({ coll, id, reason: 'a payout can only move to paid / rejected, and its amount and reason cannot change' }); continue; }
          if (ok && d.status === 'rejected' && String(d.reject_reason || '').trim().length < 3) { rejected.push({ coll, id, reason: 'enter a reason for rejecting the claim' }); continue; }
        }
      }
      if (coll === 'kyc_docs' && op.data && !op.del) {
        const bad = ['aadhaar', 'pan', 'address'].some(k => op.data[k] != null && (typeof op.data[k] !== 'string' || op.data[k].length > 400000 || !op.data[k].startsWith('data:image/')));
        if (bad) { rejected.push({ coll, id, reason: 'documents must be images under 400 KB' }); continue; }
      }
      if (coll === 'mandates' && op.data && !op.del) {
        if (!existing) { rejected.push({ coll, id, reason: 'mandates are requested by the customer' }); continue; }
        const nd = op.data;
        if (['customer_id', 'loan_id', 'account_no', 'ifsc', 'max_amount'].some(k => String(existing[k]) !== String(nd[k]))) { rejected.push({ coll, id, reason: 'mandate bank details cannot be edited' }); continue; }
        if (nd.status === 'active' && !(String(nd.umrn || '').length >= 5)) { rejected.push({ coll, id, reason: 'enter the UMRN from the bank before activating' }); continue; }
        if (existing.status === 'cancelled') { rejected.push({ coll, id, reason: 'cancelled mandates cannot be reopened' }); continue; }
      }
      if (coll === 'ins_policies' && op.data && !op.del) {
        const nd = op.data;
        if (!getRecord('ins_plans', String(nd.plan_id))) { rejected.push({ coll, id, reason: 'unknown insurance plan' }); continue; }
        if (nd.status === 'active' && !(nd.premium_paid === true && nd.cert_no && nd.start_date && nd.end_date)) { rejected.push({ coll, id, reason: 'a policy can be activated only after the premium is collected' }); continue; }
        if (existing && existing.status !== 'requested' && ['plan_id', 'customer_id', 'premium', 'sum_insured', 'ref_type', 'ref_id'].some(k => String(existing[k] ?? '') !== String(nd[k] ?? ''))) { rejected.push({ coll, id, reason: 'policy terms cannot be changed after activation' }); continue; }
        if (existing && existing.premium_paid && nd.premium_paid !== true) { rejected.push({ coll, id, reason: 'premium status cannot be reverted' }); continue; }
      }
      if (coll === 'ins_claims' && op.data && !op.del) {
        const nd = op.data, pol = getRecord('ins_policies', String(nd.policy_id));
        if (!pol || String(pol.customer_id) !== String(nd.customer_id)) { rejected.push({ coll, id, reason: 'claim does not match a policy of this customer' }); continue; }
        if (!existing && pol.status !== 'active') { rejected.push({ coll, id, reason: 'claims need an active policy' }); continue; }
        if (!['submitted', 'docs_pending', 'under_review', 'forwarded', 'approved', 'settled', 'rejected'].includes(nd.status)) { rejected.push({ coll, id, reason: 'invalid claim status' }); continue; }
        if (existing && ['settled', 'rejected'].includes(existing.status) && JSON.stringify(existing) !== JSON.stringify(nd)) { rejected.push({ coll, id, reason: 'closed claims cannot be changed' }); continue; }
        if (existing && (String(existing.policy_id) !== String(nd.policy_id) || (existing.timeline || []).length > (nd.timeline || []).length)) { rejected.push({ coll, id, reason: 'claim history cannot be altered' }); continue; }
        if (['approved', 'settled'].includes(nd.status) && !(+nd.approved_amount > 0 && +nd.approved_amount <= +pol.sum_insured)) { rejected.push({ coll, id, reason: 'approved amount must be within the cover amount' }); continue; }
      }
      if (coll === 'journal') {
        if (op.del || existing) {                 // the ledger is append-only; only opening-balance entries may be replaced, and only by finance
          const ok = existing && existing.type === 'opening' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_accounting']));
          if (!ok) { rejected.push({ coll, id, reason: 'ledger entries cannot be edited or deleted — post a reversal instead' }); continue; }
        }
        if (op.data) {
          const ls = Array.isArray(op.data.lines) ? op.data.lines : [];
          if (ls.length > 60 || ls.some(l => !l || typeof l !== 'object' || ![l.dr, l.cr].every(v => v === undefined || v === null || v === '' || (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1e9)) || (+l.dr > 0 && +l.cr > 0))) { rejected.push({ coll, id, reason: 'invalid journal line (negative, both-sided or absurd amount)' }); continue; }
          if (!(req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_accounting'])) && ['journal', 'adjust', 'opening', 'contra', 'payment', 'receipt'].includes(String(op.data.type || 'journal'))) { rejected.push({ coll, id, reason: 'manual / adjusting entries can be posted only by the accounts team' }); continue; }
          const dr = ls.reduce((s, l) => s + (+l.dr || 0), 0), cr = ls.reduce((s, l) => s + (+l.cr || 0), 0);
          if (!ls.length || Math.abs(dr - cr) > 0.01) { rejected.push({ coll, id, reason: 'unbalanced journal entry' }); continue; }
        }
      }
      if (coll === 'collections') {
        const d = op.data && typeof op.data === 'object' ? op.data : null, isCeo = req.auth.role === 'ceo';
        if (op.del) { if (existing && existing.status !== 'pending' && !isCeo) { rejected.push({ coll, id, reason: 'posted collections cannot be deleted — reverse them instead' }); continue; } }
        else if (d) {
          for (const k of ['gateway_verified', 'gateway_payment_id']) { if (existing && existing[k] !== undefined) d[k] = existing[k]; else delete d[k]; }   // only the signed webhook may set these
          for (const k of ['amount', 'principal', 'interest', 'penalty']) {
            if (d[k] === undefined || d[k] === null || d[k] === '') { if (k === 'amount') { rejected.push({ coll, id, reason: 'amount required' }); continue; } else continue; }
            const n = typeof d[k] === 'number' ? d[k] : NaN; if (!Number.isFinite(n) || n < (k === 'amount' ? 0.01 : 0) || n > 1e8) { rejected.push({ coll, id, reason: 'invalid ' + k }); d.__bad = 1; break; }
          }
          if (d.__bad || d.amount === undefined || d.amount === null || d.amount === '') { if (d.__bad) delete d.__bad; continue; }
          if (existing && existing.status !== 'pending' && !isCeo) {
            const FIX = ['amount', 'customer_id', 'ref_type', 'ref_id', 'principal', 'interest', 'penalty', 'collection_date', 'payment_mode', 'journal_id', 'collection_code'];
            const changed = FIX.find(k => String(existing[k] ?? '') !== String(d[k] ?? ''));
            if (changed || (existing.status !== d.status && !(existing.status === 'posted' && d.status === 'reversed'))) { rejected.push({ coll, id, reason: 'posted collections cannot be edited — reverse them instead' }); continue; }
          }
        }
      }
      if (coll === 'groups' && op.data && typeof op.data === 'object' && !op.del) {
        const d = op.data, mem = Array.isArray(d.member_ids) ? d.member_ids.map(Number) : null; let bad = '';
        const custs = new Set(allOf('customers').filter(c => c.status !== 'deleted').map(c => +c.id));
        if (typeof d.name !== 'string' || d.name.trim().length < 3 || d.name.length > 60) bad = 'Group name must be 3–60 characters';
        else if (!mem || mem.length < 2 || mem.length > 25 || mem.some(m => !Number.isInteger(m))) bad = 'A group needs 2 to 25 members';
        else if (new Set(mem).size !== mem.length) bad = 'A member is listed twice';
        else if (mem.some(m => !custs.has(m))) bad = 'Every member must be an existing customer';
        else if (!mem.includes(Number(d.leader_id))) bad = 'The group leader must be one of the members';
        else if (!['active', 'closed'].includes(d.status || 'active')) bad = 'Invalid group status';
        else if (d.meeting_day && !['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].includes(d.meeting_day)) bad = 'Invalid meeting day';
        if (!bad && (d.status || 'active') === 'active') { const other = allOf('groups').find(g => String(g.id) !== String(id) && g.status === 'active' && (g.member_ids || []).some(m => mem.includes(Number(m)))); if (other) bad = 'A member is already in group ' + (other.group_code || other.id); }
        if (!bad && d.status === 'closed' && allOf('loans').some(l => String(l.group_id) === String(id) && ['pending', 'approved', 'active'].includes(l.status))) bad = 'This group still has an open loan — close the loan first';
        if (bad) { rejected.push({ coll, id, reason: bad }); continue; }
        d.member_ids = mem; d.leader_id = Number(d.leader_id); d.status = d.status || 'active'; if (!d.group_code) d.group_code = 'PFS-G-' + String(id).padStart(4, '0');
      }
      if (coll === 'customers' && op.data && typeof op.data === 'object' && !op.del) {
        const d = op.data; let bad = '';
        const exPan = existing && String(existing.pan || '').trim().toUpperCase();
        if (d.pan != null && String(d.pan).trim() !== '') { const p = panCheck(d.pan, d.name); if (!p.ok && !(exPan && exPan === String(d.pan).trim().toUpperCase())) bad = 'Invalid PAN — ' + p.reason; else if (p.ok) d.pan = p.pan; }   // an unchanged legacy PAN never blocks an unrelated edit
        if (!bad && d.bank_ifsc != null && String(d.bank_ifsc).trim() !== '') { const i = ifscCheck(d.bank_ifsc); if (!i.ok) bad = 'Invalid IFSC code'; else d.bank_ifsc = i.ifsc; }
        if (!bad && d.bank_account != null && String(d.bank_account).trim() !== '') { const a = acctCheck(d.bank_account); if (!a.ok) bad = 'Invalid bank account number (9–18 digits)'; }
        const aaN = d.aadhaar != null && String(d.aadhaar).trim() !== '' ? String(d.aadhaar).replace(/\D/g, '') : '';
        if (!bad) {
          const others = allOf('customers').filter(c => String(c.id) !== String(id) && c.status !== 'deleted');
          if (d.pan && others.some(c => String(c.pan || '').toUpperCase() === d.pan)) bad = 'This PAN is already registered to another customer';
          else if (aaN && others.some(c => String(c.aadhaar || '').replace(/\D/g, '') === aaN)) bad = 'This Aadhaar is already registered to another customer';
        }
        if (bad) { rejected.push({ coll, id, reason: bad }); continue; }
        d.kyc_checks = { pan: d.pan ? (panCheck(d.pan).ok ? 'ok' : 'invalid') : 'none', pan_type: d.pan ? panCheck(d.pan).type : undefined, aadhaar: aaN ? (aadhaarCheck(aaN).ok ? 'checksum_ok' : 'unverified') : 'none', ifsc: d.bank_ifsc ? 'ok' : 'none', checked_at: new Date().toISOString() };
        if (d.kyc_checks.pan_type === undefined) delete d.kyc_checks.pan_type;
      }
      if (coll === 'users' && op.data) {
        if (op.data.role === 'ceo' && req.auth.role !== 'ceo') { rejected.push({ coll, id, reason: 'only CEO can create a CEO' }); continue; }
        if (existing?.role === 'ceo' && req.auth.role !== 'ceo') { rejected.push({ coll, id, reason: 'only CEO can edit the CEO' }); continue; }
        if (!ROLE_KEYS.includes(op.data.role)) { rejected.push({ coll, id, reason: 'invalid role' }); continue; }
        if (+id === 1) { op.data.role = 'ceo'; op.data.status = 'active'; }            // the founder account can never be demoted/blocked
      }
      if (op.del) {
        if (+id === 1 && coll === 'users') { rejected.push({ coll, id, reason: 'cannot delete founder' }); continue; }
        const rev = delRecord(coll, id); afterDelete(coll, id); applied.push({ coll, id, rev }); audit(req, 'delete', coll, id);
      } else {
        if (typeof op.data !== 'object' || op.data === null) { rejected.push({ coll, id, reason: 'bad data' }); continue; }
        op.data = cleanVal(op.data, null);
        const pw = op.pw && !pwProblem(op.pw, null) && coll !== 'perms' ? String(op.pw) : null;
        const rev = putRecord(coll, opId, op.data); afterWrite(coll, opId, op.data, pw); applied.push({ coll, id: opId, rev });
        try { notifyHooks(coll, existing, op.data); } catch (e) { console.error('notify', e.message); }
        audit(req, existing ? 'update' : 'create', coll, opId);
      }
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK'); console.error(e);
    return res.status(500).json({ success: false, message: 'Server error while saving' });
  }
  res.json({ success: true, cursor: curRev(), applied, rejected, remap });
});

const ROLE_KEYS = ['ceo', 'ops', 'finance', 'risk', 'biz', 'branch', 'tl', 're', 'tc', 'doc', 'ce', 'hr', 'sm', 'mis', 'rc'];   // staff roles (customer / partner / lender are separate account kinds)

app.get('/api/audit', auth, (req, res) => {
  if (!(req.auth.kind === 'staff' && hasAny(req.auth.role, ['view_audit']))) return res.status(403).json({ success: false });
  res.json({ success: true, data: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 500').all() });
});

// Admin backup (CEO only): downloads a consistent copy of the database
app.get('/api/admin/backup', auth, (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false });
  const out = path.join(path.dirname(DB_PATH), 'backup-' + Date.now() + '.db');
  db.exec(`VACUUM INTO '${out.replace(/'/g, "''")}'`);
  audit(req, 'backup');
  res.download(out, 'pratishtha-backup-' + new Date().toISOString().slice(0, 10) + '.db', () => fs.unlink(out, () => {}));
});

// ─── public verification (QR codes on certificates, ID cards, forms and bonds) ───
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false, message: 'Too many requests' });
const VERIFY = {   // type -> [collection, code field, label, name field]
  emp: ['users', 'employee_id', 'Employee ID Card', 'name'],
  partner: ['partners', 'partner_code', 'Partner / DSA Certificate', 'name'],
  cust: ['customers', 'customer_code', 'Customer Application Form', 'name'],
  rd: ['rds', 'rd_code', 'RD Bond Certificate', 'customer_name'],
  card: ['cards', 'card_no', 'PFS Virtual Card', 'customer_name'],
  ins: ['ins_policies', 'cert_no', 'Insurance Enrolment Certificate', 'customer_name'],
  retailer: ['retailers', 'retailer_code', 'PFS Partner Retailer', 'name'],
  lender: ['lenders', 'lender_code', 'PFS Lender Partner', 'name'],
  gold: ['gold_pledges', 'pledge_code', 'Gold Loan Pledge Receipt', 'customer_name'],
  bond: ['plan_accts', 'bond_no', 'PFS Bond Certificate', 'customer_name'],
};
const maskName = n => { const p = String(n || '').trim().split(/\s+/); return p.length < 2 ? (p[0] || '—') : p[0] + ' ' + p[p.length - 1][0] + '.'; };
function verifyLookup(type, code) {
  const def = VERIFY[type]; if (!def || !code || String(code).length > 40) return null;
  const row = db.prepare(`SELECT data FROM records WHERE coll=? AND deleted=0 AND json_extract(data, '$.${def[1]}') = ?`).get(def[0], String(code));
  const rec = row && parse(row.data); if (!rec) return null;
  const st = String(rec.status || 'active').toLowerCase();
  return { label: def[2], code: String(code), holder: maskName(rec[def[3]]), status: st, valid: st === 'active' || st === 'completed',
    extra: type === 'emp' ? (rec.role ? String(rec.role).toUpperCase() : '') : type === 'bond' ? ((rec.plan_name || '') + ' • ' + (rec.start_date || '—') + ' to ' + (rec.maturity_date || '—')) : type === 'rd' ? ('Started ' + (rec.start_date || '—')) : type === 'card' ? ({ emi: 'EMI Virtual Card', shopping: 'Shopping Card', privilege: 'Privilege Card' }[rec.type] || '') + (rec.valid_till ? ' • valid till ' + rec.valid_till : '') : '' };
}
const escH = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
app.get('/api/verify/:type/:code', verifyLimiter, (req, res) => {
  const r = verifyLookup(req.params.type, req.params.code);
  res.json(r ? { success: true, ...r } : { success: false, message: 'No matching record' });
});
app.get('/verify/:type/:code', verifyLimiter, (req, res) => {
  const r = verifyLookup(req.params.type, req.params.code);
  const ok = r && r.valid;
  res.status(r ? 200 : 404).type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Verification — Pratishtha Finance</title><style>
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0d2137;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.c{background:#fff;border-radius:18px;max-width:380px;width:100%;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.h{padding:26px 20px;text-align:center;color:#fff;background:${ok ? '#1a8a4e' : r ? '#b45309' : '#b91c1c'}}
.h .i{font-size:44px}.h h1{margin:6px 0 0;font-size:19px}
.b{padding:18px 22px}.row{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid #e2e8f0;font-size:13px}.row span{color:#64748b}.row b{color:#0f172a;text-align:right}
.f{padding:14px;text-align:center;font-size:11px;color:#94a3b8;background:#f8fafc}a{color:#1a8a4e;text-decoration:none;font-weight:700}
</style></head><body><div class="c"><div class="h"><div class="i">${ok ? '✔' : r ? '⚠' : '✖'}</div><h1>${ok ? 'Verified — Genuine Record' : r ? 'Record found — not active' : 'No matching record'}</h1></div>
<div class="b">${r ? `<div class="row"><span>Document</span><b>${escH(r.label)}</b></div><div class="row"><span>Reference</span><b>${escH(r.code)}</b></div><div class="row"><span>Holder</span><b>${escH(r.holder)}</b></div>${r.extra ? `<div class="row"><span>Details</span><b>${escH(r.extra)}</b></div>` : ''}<div class="row"><span>Status</span><b style="text-transform:capitalize">${escH(r.status)}</b></div>`
  : '<p style="font-size:13px;color:#475569;line-height:1.6">This code does not match any record of Pratishtha Finance Services. If you received this document from someone, please do not trust it and contact us.</p>'}</div>
<div class="f"><b>PRATISHTHA FINANCE SERVICES</b><br><a href="https://pratishtha.pro">pratishtha.pro</a> • 7233023547<br>Only limited details are shown for privacy.</div></div></body></html>`);
});

// Customer online payment request: recorded as PENDING — staff verify it against the bank/UPI statement before it is credited.
app.post('/api/customer/pay-request', auth, (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  const { ref_type, ref_id } = req.body || {};
  const amount = Math.round((+req.body?.amount || 0) * 100) / 100;
  if (!(amount > 0) || amount > 1000000) return res.status(400).json({ success: false, message: 'Invalid amount' });
  const mode = ['upi', 'card', 'netbanking', 'bank'].includes(req.body?.mode) ? req.body.mode : 'upi';
  const cid = String(req.auth.ref);
  const cust = getRecord('customers', cid);
  const target = ref_type === 'loan' ? getRecord('loans', ref_id) : ref_type === 'rd' ? getRecord('rds', ref_id) : null;
  if (!cust || !target || String(target.customer_id) !== cid) return res.status(404).json({ success: false, message: 'Account not found' });
  const rows = db.prepare("SELECT data FROM records WHERE coll='collections' AND deleted=0").all().map(r => parse(r.data)).filter(Boolean);
  if (rows.some(c => c.status === 'pending' && String(c.customer_id) === cid && c.ref_type === ref_type && String(c.ref_id) === String(ref_id)))
    return res.status(409).json({ success: false, message: 'A payment for this account is already awaiting verification' });
  const mx = db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='collections'").get().m || 0;
  const id = mx + 1;
  const rec = { id, collection_code: 'PFS-COL-' + String(id).padStart(4, '0'), customer_id: cust.id, customer_name: cust.name, amount, payment_mode: mode,
    collection_date: new Date().toISOString().slice(0, 10), ref_type, ref_id: target.id, ref_label: (ref_type === 'loan' ? 'Loan ' + target.loan_code : 'RD ' + target.rd_code),
    agent_name: 'Self (Online)', upi_ref: String(req.body?.upi_ref || '').slice(0, 40), status: 'pending' };
  putRecord('collections', id, rec); audit(req, 'pay-request', 'collections', id);
  notifyStaff('create_collections', '💳 Online payment to verify', 'A customer submitted a payment for verification.', 'collection');
  res.json({ success: true, record: rec });
});

app.post('/api/customer/card-request', auth, (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  const type = String(req.body?.type || '');
  if (!['emi', 'shopping', 'privilege'].includes(type)) return res.status(400).json({ success: false, message: 'Invalid card type' });
  const cid = String(req.auth.ref);
  const cust = getRecord('customers', cid);
  if (!cust) return res.status(404).json({ success: false, message: 'Customer not found' });
  const rows = db.prepare("SELECT data FROM records WHERE coll='cards' AND deleted=0").all().map(r => parse(r.data)).filter(Boolean);
  if (rows.some(c => String(c.customer_id) === cid && c.type === type && (c.status === 'requested' || c.status === 'active')))
    return res.status(409).json({ success: false, message: 'You already have an active or pending card of this type' });
  const mx = db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='cards'").get().m || 0;
  const id = mx + 1;
  const rec = { id, card_no: 'PFS-VC-' + String(id).padStart(4, '0'), type, customer_id: cust.id, customer_name: cust.name, status: 'requested',
    partner_name: '', limit: null, requested_date: new Date().toISOString().slice(0, 10), issued_date: '', valid_till: '', issued_by: '', remarks: '' };
  const ap = req.body?.application;
  if (ap && typeof ap === 'object') {
    const c = (v, n = 60) => String(v == null ? '' : v).replace(/[<>]/g, '').trim().slice(0, n);
    rec.application = { employment: c(ap.employment, 30), occupation: c(ap.occupation), monthly_income: Math.max(0, Math.min(10000000, +ap.monthly_income || 0)), residence: c(ap.residence, 30),
      purpose: c(ap.purpose, 80), nominee_name: c(ap.nominee_name), nominee_relation: c(ap.nominee_relation, 30), consent: !!ap.consent, insurance_plan_id: c(ap.insurance_plan_id, 20), applied_on: new Date().toISOString() };
    if (!rec.application.consent) return res.status(400).json({ success: false, message: 'Please accept the declaration to apply' });
  }
  putRecord('cards', id, rec); audit(req, 'card-request', 'cards', id);
  notifyStaff('manage_cards', '💳 New card request', 'A customer requested a PFS card.', 'system');
  res.json({ success: true, record: rec });
});

// ─── high-security card portal: step-up password check + customer-side freeze / lost report ───
const CARD_STEPUP = new Map();   // account id -> unlocked-until (ms)
const CARD_STEPUP_MS = 5 * 60 * 1000;
const stepupOk = aid => (CARD_STEPUP.get(aid) || 0) > Date.now();
app.post('/api/customer/card-unlock', auth, (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.auth.aid);
  if (acc.locked_until > Date.now()) return res.status(429).json({ success: false, message: 'Locked for a few minutes after repeated wrong passwords' });
  if (!checkPw(String(req.body?.password || ''), acc.pass_hash)) {
    const f = acc.failed + 1;
    db.prepare('UPDATE accounts SET failed=?, locked_until=? WHERE id=?').run(f >= 3 ? 0 : f, f >= 3 ? Date.now() + 10 * 60 * 1000 : 0, acc.id);
    audit(req, f >= 3 ? 'card_unlock_locked' : 'card_unlock_failed');
    return res.status(403).json({ success: false, message: f >= 3 ? 'Too many wrong attempts — locked for 10 minutes' : 'Wrong password (' + (3 - f) + ' attempt' + (3 - f === 1 ? '' : 's') + ' left)' });
  }
  db.prepare('UPDATE accounts SET failed=0, locked_until=0 WHERE id=?').run(acc.id);
  const until = Date.now() + CARD_STEPUP_MS; CARD_STEPUP.set(acc.id, until);
  audit(req, 'card_unlock');
  res.json({ success: true, until, ttl: CARD_STEPUP_MS });
});
app.post('/api/customer/card-lock', auth, (req, res) => { CARD_STEPUP.delete(req.auth.aid); res.json({ success: true }); });
app.post('/api/customer/card-action', auth, (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  if (!stepupOk(req.auth.aid)) return res.status(403).json({ success: false, relock: true, message: 'Please unlock your card with your password first' });
  const id = String(req.body?.id || ''), action = String(req.body?.action || '');
  const c = getRecord('cards', id);
  if (!c || String(c.customer_id) !== String(req.auth.ref)) return res.status(404).json({ success: false, message: 'Card not found' });
  if (action === 'freeze') {
    if (c.status !== 'active') return res.status(409).json({ success: false, message: 'Only an active card can be frozen' });
    c.status = 'blocked'; c.frozen_by = 'customer'; c.remarks = 'Frozen by customer on ' + new Date().toISOString().slice(0, 10);
  } else if (action === 'unfreeze') {
    if (c.status !== 'blocked' || c.frozen_by !== 'customer') return res.status(403).json({ success: false, message: 'This card was blocked by Pratishtha — please contact us to reactivate it' });
    c.status = 'active'; c.frozen_by = ''; c.remarks = '';
  } else if (action === 'lost') {
    if (!['active', 'blocked'].includes(c.status)) return res.status(409).json({ success: false, message: 'Card is not active' });
    c.status = 'blocked'; c.frozen_by = 'lost'; c.remarks = 'Reported lost / misused by customer on ' + new Date().toISOString().slice(0, 10);
  } else return res.status(400).json({ success: false, message: 'Invalid action' });
  putRecord('cards', id, c); audit(req, 'card_' + action, 'cards', id);
  res.json({ success: true, record: c });
});


// ─────────────────────────── Retailer partners, card purchases, emergency loan, insurance ───────────────────────────
const todayS = () => new Date().toISOString().slice(0, 10);
const polv = (k, d) => { const p = (getRecord('policy', '_') || {}).v || {}; const v = p[k]; return v == null || v === '' || isNaN(+v) ? d : +v; };
const allOf = coll => db.prepare('SELECT data FROM records WHERE coll=? AND deleted=0').all(coll).map(r => parse(r.data)).filter(Boolean);
const nextId = coll => (db.prepare('SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll=?').get(coll).m || 0) + 1;
const r2s = x => Math.round((+x || 0) * 100) / 100;
function emiCalc(P, rate, n) { P = +P; rate = +rate; n = Math.round(+n); if (!(P > 0) || !(n >= 1) || !(rate >= 0) || !Number.isFinite(P + rate + n)) return 0; const r = rate / 1200; return r2s(r === 0 ? P / n : P * r / (1 - Math.pow(1 + r, -n))); }
function cardUsed(cardId) {            // principal still owed on loans taken against this card
  let used = 0;
  for (const l of allOf('loans')) {
    if (String(l.card_id) !== String(cardId) || !['active', 'approved', 'pending', 'defaulted'].includes(l.status)) continue;
    const tot = (+l.emi_amount || +l.principal_amount) * (+l.tenure_months || 1);
    used += (+l.principal_amount || 0) * (1 - Math.min(1, (+l.paid_total || 0) / (tot || 1)));
  }
  return r2s(used);
}
function cardUsable(c) {
  if (!c) return 'Card not found';
  if (c.status !== 'active') return 'This card is not active';
  if (!['emi', 'shopping'].includes(c.type)) return 'This card type has no spending limit';
  if (c.valid_till && c.valid_till < todayS()) return 'This card has expired';
  if (!(+c.limit > 0)) return 'This card has no limit assigned';
  return '';
}
const cardAvail = c => Math.max(0, r2s((+c.limit || 0) - cardUsed(c.id)));
function custOK(cid) { const c = getRecord('customers', cid); return c && (c.status === 'active' || c.status == null) ? c : null; }
function expireTxns() {
  const now = Date.now();
  for (const t of allOf('card_txns')) if (t.status === 'pending' && t.expires_at && Date.parse(t.expires_at) < now) { t.status = 'expired'; putRecord('card_txns', t.id, t); }
}
const needCustomer = (req, res) => { if (req.auth.kind !== 'customer') { res.status(403).json({ success: false, message: 'Customers only' }); return false; } return true; };
const needStepup = (req, res) => { if (!stepupOk(req.auth.aid)) { res.status(403).json({ success: false, relock: true, message: 'Please confirm with your password first' }); return false; } return true; };

// Instant emergency loan against an active card (up to the policy cap, default ₹5,000)
app.post('/api/customer/emergency-loan', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const cust = custOK(req.auth.ref); if (!cust) return res.status(403).json({ success: false, message: 'Account not active' });
  const card = getRecord('cards', String(req.body?.card_id || ''));
  if (!card || String(card.customer_id) !== String(cust.id)) return res.status(404).json({ success: false, message: 'Card not found' });
  const bad = cardUsable(card); if (bad) return res.status(409).json({ success: false, message: bad });
  const cap = Math.min(polv('card_emerg_max', 5000), 25000), amount = Math.round(+req.body?.amount || 0);
  const avail = cardAvail(card), max = Math.min(cap, avail);
  if (!(amount >= 500)) return res.status(400).json({ success: false, message: 'Minimum emergency loan is ₹500' });
  if (amount > max) return res.status(400).json({ success: false, message: max <= 0 ? 'No card limit available right now' : 'You can take up to ₹' + max + ' right now' });
  const pc = proofCheck(req.body?.proof_photo, req.body?.proof_ts); if (typeof pc === 'string') return res.status(400).json({ success: false, message: pc, need_photo: true });
  const loans = allOf('loans').filter(l => String(l.customer_id) === String(cust.id));
  if (loans.some(l => l.status === 'defaulted')) return res.status(409).json({ success: false, message: 'Please clear your overdue loan first' });
  if (loans.some(l => l.source === 'card_emergency' && ['approved', 'pending', 'active'].includes(l.status))) return res.status(409).json({ success: false, message: 'You already have an emergency loan running — repay it to take another' });
  const n = Math.max(1, Math.min(6, Math.round(polv('card_emerg_tenure', 3)))), rate = polv('card_emerg_rate', 24);
  const id = nextId('loans');
  const rec = { id, loan_code: 'PFS-L-' + String(id).padStart(4, '0'), customer_id: cust.id, customer_name: cust.name, loan_type: 'emergency', source: 'card_emergency', card_id: card.id, card_no: card.card_no,
    principal_amount: amount, interest_rate: rate, tenure_months: n, emi_amount: emiCalc(amount, rate, n), outstanding_amount: amount, paid_emis: 0, status: 'approved', instant: true,
    applied_date: todayS(), sanctioned_date: todayS(), remarks: 'Instant emergency loan on ' + card.card_no };
  rec.proof_id = saveProof(req, { kind: 'cash', ref_id: id, customer_id: cust.id, photo: String(req.body.proof_photo), hash: pc.hash }); rec.has_proof = true;
  putRecord('loans', id, rec); audit(req, 'emergency_loan', 'loans', id);
  notify('customer', cust.id, '⚡ Emergency loan approved', inr(amount) + ' approved on ' + card.card_no + '. It will be released shortly.', 'loan');
  notifyStaff('disburse_loans', '⚡ Emergency loan to disburse', 'An emergency loan on a PFS card was approved and is waiting for disbursement.', 'loan');
  res.json({ success: true, record: rec });
});

app.get('/api/customer/card-terms', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  const cards = allOf('cards').filter(c => String(c.customer_id) === String(req.auth.ref) && !cardUsable(c)).map(c => ({ id: c.id, avail: cardAvail(c) }));
  res.json({ success: true, emerg_max: Math.min(polv('card_emerg_max', 5000), 25000), emerg_rate: polv('card_emerg_rate', 24),
    emerg_tenure: Math.max(1, Math.min(6, Math.round(polv('card_emerg_tenure', 3)))), purchase_rate: polv('card_purchase_rate', 18), cards });
});
// Goods returned / sale cancelled after approval (settle_retailers). Loan is closed only if the customer has not started repaying.
app.post('/api/retailers/txn-return', auth, (req, res) => {
  if (req.auth.kind !== 'staff' || !hasAny(req.auth.role, ['settle_retailers'])) return res.status(403).json({ success: false, message: 'Not allowed' });
  const t = getRecord('card_txns', String(req.body?.id || ''));
  if (!t || !['approved', 'settled'].includes(t.status)) return res.status(409).json({ success: false, message: 'Only paid card sales can be returned' });
  const reason = clean(req.body?.reason, 100); if (reason.length < 3) return res.status(400).json({ success: false, message: 'Enter the return reason' });
  const loan = getRecord('loans', String(t.loan_id));
  if (!loan || loan.status !== 'active') return res.status(409).json({ success: false, message: 'The linked loan is not active — handle this case manually' });
  if ((+loan.paid_total || 0) > 0) return res.status(409).json({ success: false, message: 'Customer has already paid EMIs on this loan — refund through finance manually' });
  const was = t.status;
  loan.status = 'closed'; loan.outstanding_amount = 0; loan.remarks = 'Closed — goods returned (' + t.txn_code + '): ' + reason; putRecord('loans', loan.id, loan);
  t.status = 'returned'; t.returned_from = was; t.return_reason = reason; t.returned_date = todayS(); putRecord('card_txns', t.id, t);
  audit(req, 'card_txn_return', 'card_txns', t.id);
  notify('customer', t.customer_id, '↩ Purchase returned', t.txn_code + ' was returned and your card loan is closed.', 'loan'); notify('retailer', t.retailer_id, '↩ Sale returned', t.txn_code + ' was returned: ' + reason, 'system');
  res.json({ success: true, record: t, loan, was_settled: was === 'settled' });
});


// ─────────────────────────── payout / settlement claims raised by partners & retailers ───────────────────────────
const payCode = id => 'PFS-PAY-' + String(id).padStart(5, '0');
app.post('/api/partner/payout-request', auth, (req, res) => {
  if (req.auth.kind !== 'partner') return res.status(403).json({ success: false, message: 'Partners only' });
  const p = getRecord('partners', req.auth.ref);
  if (!p || p.status !== 'active') return res.status(403).json({ success: false, message: 'Your partner account is not active' });
  const open = allOf('payouts').find(x => String(x.partner_id) === String(p.id) && x.status === 'pending');
  if (open) return res.status(409).json({ success: false, message: 'You already have a payout claim waiting for approval (' + open.payout_code + ')' });
  const pend = Math.round(((+p.commission || 0) - (+p.commission_paid || 0)) * 100) / 100;
  if (!(pend > 0)) return res.status(409).json({ success: false, message: 'No commission is pending for payout' });
  const amt = req.body?.amount == null || req.body.amount === '' ? pend : Math.round((+req.body.amount) * 100) / 100;
  if (!(amt >= 1) || amt > pend + 0.01) return res.status(400).json({ success: false, message: 'Enter an amount between ₹1 and ₹' + pend });
  const id = nextId('payouts');
  const rec = { id, payout_code: payCode(id), party: 'partner', partner_id: p.id, partner_name: p.name, amount: amt, date: todayS(), requested_at: new Date().toISOString(), status: 'pending', note: String(req.body?.note || '').slice(0, 100) };
  putRecord('payouts', id, rec); audit(req, 'payout_claim', 'payouts', id);
  notify('partner', p.id, '💸 Payout claim sent', inr(amt) + ' claim ' + rec.payout_code + ' is with the accounts team.', 'system');
  notifyStaff('manage_commission', '💸 Partner payout claim', p.name + ' claimed ' + inr(amt) + ' (' + rec.payout_code + ').', 'system');
  res.json({ success: true, record: rec });
});
app.post('/api/retailer/settlement-request', auth, (req, res) => {
  if (req.auth.kind !== 'retailer') return res.status(403).json({ success: false, message: 'Partner retailers only' });
  const r = getRecord('retailers', req.auth.ref);
  if (!r || r.status !== 'active') return res.status(403).json({ success: false, message: 'Retailer account is not active' });
  const open = allOf('payouts').find(x => String(x.retailer_id) === String(r.id) && x.status === 'pending');
  if (open) return res.status(409).json({ success: false, message: 'You already have a settlement claim waiting (' + open.payout_code + ')' });
  const due = allOf('card_txns').filter(t => String(t.retailer_id) === String(r.id) && t.status === 'approved' && t.proof_id);   // only sales with a live proof photo can be claimed
  const net = Math.round(due.reduce((a, t) => a + (+t.amount || 0) * (1 - (+t.commission_pct || 0) / 100), 0) * 100) / 100;
  if (!due.length || !(net > 0)) return res.status(409).json({ success: false, message: 'No sales are awaiting settlement' });
  const id = nextId('payouts');
  const rec = { id, payout_code: payCode(id), party: 'retailer', retailer_id: r.id, partner_name: r.name, amount: net, sales: due.length, date: todayS(), requested_at: new Date().toISOString(), status: 'pending' };
  putRecord('payouts', id, rec); audit(req, 'settlement_claim', 'payouts', id);
  notify('retailer', r.id, '💸 Settlement claim sent', inr(net) + ' for ' + due.length + ' sale(s) — claim ' + rec.payout_code + '.', 'system');
  notifyStaff('settle_retailers', '💸 Retailer settlement claim', r.name + ' claimed ' + inr(net) + ' (' + rec.payout_code + ').', 'system');
  res.json({ success: true, record: rec });
});

// ─────────────────────────── in-app notifications (each person sees only their own) ───────────────────────────
// ───────── Identity validators (format / checksum level — NOT a government database lookup) ─────────
const PAN_TYPES = { P: 'Individual', C: 'Company', H: 'HUF', F: 'Firm', A: 'AOP', T: 'Trust', B: 'BOI', L: 'Local authority', J: 'Artificial juridical person', G: 'Government' };
function panCheck(v, name) {
  if (typeof v !== 'string') return { ok: false, reason: 'PAN must be text' };
  const pan = v.trim().toUpperCase();
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan)) return { ok: false, reason: 'PAN must look like ABCPK1234F' };
  if (!PAN_TYPES[pan[3]]) return { ok: false, reason: 'PAN holder-type letter is not valid' };
  const out = { ok: true, pan, type: PAN_TYPES[pan[3]] };
  if (pan[3] === 'P' && typeof name === 'string' && name.trim()) { const last = name.trim().split(/\s+/).pop().toUpperCase(); out.name_hint = last[0] === pan[4] ? 'match' : 'mismatch'; }
  return out;
}
const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function aadhaarCheck(v) {
  if (typeof v !== 'string' && typeof v !== 'number') return { ok: false, reason: 'Aadhaar must be 12 digits' };
  const d = String(v).replace(/\s/g, '');
  if (!/^[2-9]\d{11}$/.test(d)) return { ok: false, reason: 'Aadhaar must be 12 digits and cannot start with 0 or 1' };
  let c = 0; d.split('').reverse().forEach((ch, i) => { c = VD[c][VP[i % 8][+ch]]; });
  if (c !== 0) return { ok: false, reason: 'Aadhaar checksum does not match — check for a typing mistake' };
  return { ok: true, aadhaar: d, masked: 'XXXX XXXX ' + d.slice(8) };
}
function ifscCheck(v) { if (typeof v !== 'string') return { ok: false }; const i = v.trim().toUpperCase(); return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(i) ? { ok: true, ifsc: i } : { ok: false }; }
function acctCheck(v) { if (typeof v !== 'string' && typeof v !== 'number') return { ok: false }; const a = String(v).replace(/\s/g, ''); return /^\d{9,18}$/.test(a) && !/^0+$/.test(a) ? { ok: true, acct: a } : { ok: false }; }
function gatewaySigOk(raw, sig, secret) {
  if (!secret || typeof secret !== 'string' || typeof sig !== 'string' || !Buffer.isBuffer(raw)) return false;
  const want = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  if (sig.length !== want.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(want, 'utf8')); } catch { return false; }
}

// ───────── SMS alerts: queue → provider (SMS_URL) with retry; dry-run when no provider is configured ─────────
const SMS_DAILY_CAP = 8;
const maskMobile = m => String(m).slice(0, 2) + '*'.repeat(Math.max(0, String(m).length - 4)) + String(m).slice(-2);
function smsText(title, body) {
  const t = ('Pratishtha Finance: ' + String(title || '').replace(/[^\x20-\x7E₹]/g, '').trim() + ' ' + String(body || '').replace(/[^\x20-\x7E₹]/g, '').trim()).replace(/₹/g, 'Rs.').replace(/\s+/g, ' ').trim();
  return t.length > 160 ? t.slice(0, 157) + '...' : t;
}
function smsEnqueue(mobile, text, kind) {
  mobile = String(mobile || '').replace(/\D/g, '').slice(-10);
  if (!/^[6-9]\d{9}$/.test(mobile)) return false;
  const now = Date.now();
  if (db.prepare('SELECT COUNT(*) n FROM sms_queue WHERE mobile=? AND created_at>?').get(mobile, now - 864e5).n >= SMS_DAILY_CAP) return false;
  if (db.prepare('SELECT 1 FROM sms_queue WHERE mobile=? AND text=? AND created_at>?').get(mobile, text, now - 10 * 60 * 1000)) return false;
  db.prepare('INSERT INTO sms_queue(mobile,text,kind,created_at) VALUES(?,?,?,?)').run(mobile, text, kind || 'alert', now);
  return true;
}
let smsBusy = false;
async function smsFlush(force) {
  if (smsBusy) return 0; smsBusy = true; let n = 0;
  try {
    const rows = db.prepare("SELECT * FROM sms_queue WHERE status='queued' AND (next_at<=? OR ?) ORDER BY id LIMIT 20").all(Date.now(), force ? 1 : 0);
    for (const r of rows) {
      if (!process.env.SMS_URL) { db.prepare("UPDATE sms_queue SET status='logged' WHERE id=?").run(r.id); n++; continue; }
      const headers = { 'content-type': 'application/json' };
      const au = String(process.env.SMS_AUTH || ''), ix = au.indexOf(':'); if (ix > 0) headers[au.slice(0, ix).trim().toLowerCase()] = au.slice(ix + 1).trim();
      let err = '';
      try {
        const resp = await fetch(process.env.SMS_URL, { method: 'POST', headers, body: JSON.stringify({ to: r.mobile, message: r.text, sender: process.env.SMS_SENDER || 'PRATFN' }), signal: AbortSignal.timeout(8000) });
        if (!resp.ok) err = 'HTTP ' + resp.status;
      } catch (e) { err = String(e.message || e).slice(0, 80); }
      const tries = r.tries + 1;
      if (!err) db.prepare("UPDATE sms_queue SET status='sent', tries=?, sent_at=?, error=NULL WHERE id=?").run(tries, Date.now(), r.id);
      else if (tries >= 3) db.prepare("UPDATE sms_queue SET status='failed', tries=?, error=? WHERE id=?").run(tries, err, r.id);
      else db.prepare('UPDATE sms_queue SET tries=?, error=?, next_at=? WHERE id=?').run(tries, err, Date.now() + Math.pow(2, tries) * 30000, r.id);
      n++;
    }
  } finally { smsBusy = false; }
  return n;
}
function notify(kind, ref, title, body, type) {
  if (!kind || ref == null) return;
  const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='notifs'").get().m || 0) + 1;
  putRecord('notifs', id, { id, title: String(title).slice(0, 80), body: String(body).slice(0, 200), type: type || 'system', is_read: 0, created_at: new Date().toISOString(), for_kind: kind, for_id: +ref });
  if (kind === 'customer') { try { const c = getRecord('customers', String(ref)); if (c && c.sms_opt !== false && c.mobile) smsEnqueue(c.mobile, smsText(title, body), 'alert'); } catch { /* SMS must never break the business flow */ } }
}
function notifyStaff(perm, title, body, type) {
  const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='notifs'").get().m || 0) + 1;
  putRecord('notifs', id, { id, title: String(title).slice(0, 80), body: String(body).slice(0, 200), type: type || 'system', is_read: 0, created_at: new Date().toISOString(), for_kind: 'staff', for_perm: perm });
}
const RULE_BASIS = { loan_pct: '% of every disbursed loan', lead_flat: '₹ per converted lead', sale_pct: '% commission on card sales', monthly_fixed: '₹ fixed per month', custom: 'Custom arrangement' };
const inr = n => '₹' + Math.round(+n || 0).toLocaleString('en-IN');
function notifyHooks(coll, ex, d) {
  if (!d) return;
  if (coll === 'collections' && (!ex || ex.status === 'pending') && d.customer_id && !['pending', 'rejected'].includes(d.status)) notify('customer', d.customer_id, '💰 Payment received', inr(d.amount) + ' received for ' + (d.ref_label || 'your account') + '. Thank you!', 'collection');
  if (coll === 'collections' && ex && ex.status === 'pending' && d.status === 'rejected' && d.customer_id) notify('customer', d.customer_id, '⚠️ Payment not credited', inr(d.amount) + ' for ' + (d.ref_label || 'your account') + ' could not be verified. Please contact us or try again.', 'collection');
  if (coll === 'loans' && d.customer_id && ex && ex.status !== d.status) {
    if (d.status === 'approved') notify('customer', d.customer_id, '✅ Loan approved', 'Your loan ' + d.loan_code + ' of ' + inr(d.principal_amount) + ' is approved.', 'loan');
    if (d.status === 'active' && ex.status === 'approved') notify('customer', d.customer_id, '💸 Loan disbursed', inr(d.net_disbursed || d.principal_amount) + ' disbursed for ' + d.loan_code + '. First EMI ' + inr(d.emi_amount) + '.', 'loan');
    if (d.status === 'closed') notify('customer', d.customer_id, '🎉 Loan closed', 'Your loan ' + d.loan_code + ' is fully repaid.', 'loan');
  }
  if (coll === 'cards' && ex && ex.status !== d.status && d.customer_id) {
    const m = { active: ['💳 Card activated', 'Your ' + d.card_no + ' is now active.'], approved: ['💳 Card approved', 'Your card request was approved by the lender.'], rejected: ['💳 Card request declined', d.remarks || 'Please contact us for details.'], blocked: ['⛔ Card blocked', d.remarks || 'Your card was blocked.'] }[d.status];
    if (m) notify('customer', d.customer_id, m[0], m[1], 'system');
  }
  if (coll === 'ins_policies' && ex && ex.status !== d.status && d.status === 'active') notify('customer', d.customer_id, '🛡️ Insurance active', d.plan_name + ' is active till ' + d.end_date + '. Certificate: ' + d.cert_no, 'system');
  if (coll === 'ins_claims' && ex && ex.status !== d.status) notify('customer', d.customer_id, '📝 Claim update', d.claim_no + ': ' + String(d.status).replace('_', ' ') + (d.approved_amount && ['approved', 'settled'].includes(d.status) ? ' — ' + inr(d.approved_amount) : ''), 'system');
  if (coll === 'mandates' && ex && ex.status !== d.status && d.customer_id) notify('customer', d.customer_id, '🏦 Auto-debit ' + d.status, 'Your auto-debit request for ' + (d.loan_code || 'your loan') + ' is ' + d.status + '.', 'system');
  if (coll === 'loans' && !ex && d.status === 'pending') notifyStaff('approve_loans', '📄 New loan application', (d.customer_name || 'Customer') + ' — ' + inr(d.principal_amount) + ' (' + (d.loan_code || '') + ')', 'loan');
  if (coll === 'loans' && ex && ex.status !== 'approved' && d.status === 'approved') notifyStaff('disburse_loans', '✅ Loan approved — disburse', (d.customer_name || 'Customer') + ' — ' + inr(d.principal_amount) + ' (' + (d.loan_code || '') + ')', 'loan');
  if (coll === 'cards' && d.lender_id && d.status === 'lender_review' && (!ex || ex.status !== 'lender_review')) notify('lender', d.lender_id, '💳 New card request', (d.customer_name || 'A customer') + ' — ' + (d.card_no || '') + ' is waiting for your decision.', 'system');
  if (coll === 'payout_rules' && d) {
    const k = d.partner_id ? ['partner', d.partner_id] : d.retailer_id ? ['retailer', d.retailer_id] : d.lender_id ? ['lender', d.lender_id] : null;
    if (k && (!ex || ex.rate !== d.rate || ex.basis !== d.basis || ex.status !== d.status)) notify(k[0], k[1], '💎 Payout terms updated', (RULE_BASIS[d.basis] || d.basis) + ' ' + (d.rate != null ? d.rate : '') + (/pct/.test(d.basis) ? '%' : '') + ' — ' + String(d.reason || '').slice(0, 90), 'system');
  }
  if (coll === 'payouts' && !ex && d.kind === 'award') {
    const k = d.partner_id ? ['partner', d.partner_id] : d.retailer_id ? ['retailer', d.retailer_id] : ['lender', d.lender_id];
    notify(k[0], k[1], '🎁 Payout awarded', inr(d.amount) + ' — ' + String(d.reason || '').slice(0, 100), 'system');
  }
  if (coll === 'payouts' && ex && ex.status !== d.status) {
    const k = d.retailer_id ? ['retailer', d.retailer_id] : ['partner', d.partner_id];
    notify(k[0], k[1], d.status === 'paid' ? '✅ Payout paid' : '❌ Payout claim declined', d.payout_code + ': ' + inr(d.amount) + (d.status === 'paid' ? ' has been paid.' : ' was declined' + (d.reject_reason ? ' — ' + d.reject_reason : '.')), 'system');
  }
  if (coll === 'card_txns' && ex && ex.status !== d.status && d.status === 'settled') notify('retailer', d.retailer_id, '💸 Settlement paid', inr(d.net || d.amount) + ' for ' + d.txn_code + ' paid. Ref ' + (d.settle_ref || '—'), 'collection');
}
app.post('/api/notifs/read', auth, (req, res) => {
  if (req.auth.kind === 'staff') return res.json({ success: true, handled_by: 'sync' });
  const rows = db.prepare("SELECT id, data FROM records WHERE coll='notifs' AND deleted=0").all();
  for (const r of rows) { const n = parse(r.data); if (n && n.for_kind === req.auth.kind && String(n.for_id) === String(req.auth.ref) && !n.is_read) { n.is_read = 1; putRecord('notifs', r.id, n); } }
  res.json({ success: true });
});

// ─────────────────────────── e-sign (loan agreement), auto-debit mandates, backup ───────────────────────────
app.post('/api/customer/esign', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const loan = getRecord('loans', String(req.body?.loan_id || ''));
  if (!loan || String(loan.customer_id) !== String(req.auth.ref)) return res.status(404).json({ success: false, message: 'Loan not found' });
  if (!['approved', 'active'].includes(loan.status)) return res.status(409).json({ success: false, message: 'Only an approved or active loan can be signed' });
  const sig = String(req.body?.signature || '');
  if (!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(sig) || sig.length > 60000 || sig.length < 400) return res.status(400).json({ success: false, message: 'Please draw your signature' });
  if (allOf('esigns').some(e => String(e.ref_id) === String(loan.id) && e.doc_type === 'loan_agreement')) return res.status(409).json({ success: false, message: 'This agreement is already signed' });
  const cust = getRecord('customers', req.auth.ref) || {};
  const hash = crypto.createHash('sha256').update([loan.loan_code, loan.customer_id, loan.principal_amount, loan.interest_rate, loan.tenure_months, loan.emi_amount].join('|')).digest('hex');
  const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='esigns'").get().m || 0) + 1;
  const rec = { id, doc_type: 'loan_agreement', ref_id: loan.id, ref_code: loan.loan_code, customer_id: loan.customer_id, customer_name: cust.name || loan.customer_name, signature: sig, hash, signed_at: new Date().toISOString(), device: String(req.headers['user-agent'] || '').slice(0, 80), ip: String(req.ip || '').slice(0, 45) };
  putRecord('esigns', id, rec); audit(req, 'esign', 'esigns', id);
  notify('customer', loan.customer_id, '✍️ Agreement signed', 'You signed the loan agreement ' + loan.loan_code + '.', 'loan');
  res.json({ success: true, record: rec });
});

// ─────────────────────────── Partner / Lender / Retailer agreements: admin-customisable templates + e-sign ───────────────────────────
const AGR_DEFAULTS = JSON.parse(fs.readFileSync(path.join(__dirname, 'agreement-defaults.json'), 'utf8'));
const AGR_KIND = { partner: { tpl: 'dsa', coll: 'partners', perm: 'manage_partners', idf: 'partner_id', code: 'partner_code', label: 'DSA / Channel Partner' }, lender: { tpl: 'lender', coll: 'lenders', perm: 'manage_lenders', idf: 'lender_id', code: 'lender_code', label: 'Lending Partner' }, retailer: { tpl: 'retailer', coll: 'retailers', perm: 'manage_retailers', idf: 'retailer_id', code: 'retailer_code', label: 'Retail Partner' } };
const agrTpl = id => { const t = getRecord('agr_templates', id); return t && Array.isArray(t.clauses) ? t : Object.assign({ version: 0 }, AGR_DEFAULTS[id]); };
const agrEff = p => { const a = String(p.agreement_date || '').slice(0, 10), t = new Date().toISOString().slice(0, 10); return a && a > t ? a : t; };
const agrDate = d => { const x = new Date(d); return isNaN(x) ? '—' : x.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }); };
function agrVars(kind, p, t) {
  const cname = 'Pratishtha Finance Services';
  const v = { company: cname, party_name: p.name, party_code: p[AGR_KIND[kind].code] || '', contact: p.contact_person || p.owner || p.name, city: p.city || '', address: p.address || '', effective_date: agrDate(agrEff(p)), term_months: t.term_months, notice_days: t.notice_days, settlement_days: t.settlement_days };
  v.address_line = [p.address, p.city].filter(Boolean).join(', ') || 'India';
  if (kind === 'partner') v.commission = p.commission_rate;
  if (kind === 'retailer') v.commission = p.commission_pct;
  if (kind === 'lender') { v.party_type = p.type || 'Lender'; v.reg_line = p.reg_no ? ', Reg. / Licence No. ' + p.reg_no : ''; v.pool_limit = inr(p.pool_limit); v.max_card_limit = inr(p.max_card_limit); v.programmes = (p.programmes || []).join(', ') || 'as agreed'; }
  return v;
}
const agrRender = (str, v) => String(str || '').replace(/\{\{(\w+)\}\}/g, (m, k) => (v[k] === undefined || v[k] === null || v[k] === '') ? '—' : String(v[k]));
function agrSnapshot(kind, p) {
  const t = agrTpl(AGR_KIND[kind].tpl), v = agrVars(kind, p, t);
  return { title: t.title, version: t.version || 0, term_months: t.term_months, notice_days: t.notice_days, intro: agrRender(t.intro, v), recital: agrRender(t.recital, v), clauses: t.clauses.map(c => ({ t: c.t, b: agrRender(c.b, v) })) };
}
const agrCanEdit = req => req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_agreements']));
app.post('/api/staff/agreement-template', auth, (req, res) => {
  if (!agrCanEdit(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can change agreement templates' });
  const id = String(req.body?.id || ''); if (!AGR_DEFAULTS[id]) return res.status(400).json({ success: false, message: 'Unknown agreement type' });
  const b = req.body || {};
  if (b.reset) { const cur = getRecord('agr_templates', id); if (cur) { putRecord('agr_templates', id, Object.assign({}, AGR_DEFAULTS[id], { version: (cur.version || 0) + 1, updated_at: new Date().toISOString(), updated_by: String(req.auth.name || req.auth.role || 'Admin'), reset: true })); } audit(req, 'agreement_template_reset', 'agr_templates', id); return res.json({ success: true, record: getRecord('agr_templates', id) || Object.assign({ version: 0 }, AGR_DEFAULTS[id]) }); }
  const title = clean(b.title, 90), intro = clean(b.intro, 1200), recital = clean(b.recital, 1200);
  if (!title || !intro) return res.status(400).json({ success: false, message: 'Title and opening paragraph are required' });
  if (!Array.isArray(b.clauses) || b.clauses.length < 3 || b.clauses.length > 40) return res.status(400).json({ success: false, message: 'Keep between 3 and 40 clauses' });
  const clauses = b.clauses.map(c => ({ t: clean(c?.t, 80), b: clean(c?.b, 1500) }));
  if (clauses.some(c => !c.t || !c.b)) return res.status(400).json({ success: false, message: 'Every clause needs a heading and text' });
  const num = (x, lo, hi) => { const n = Math.round(+x); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
  const term_months = num(b.term_months, 1, 120), notice_days = num(b.notice_days, 0, 365), settlement_days = num(b.settlement_days, 0, 60);
  if (term_months === null || notice_days === null || settlement_days === null) return res.status(400).json({ success: false, message: 'Term (1–120 months), notice (0–365 days) and settlement days (0–60) must be valid numbers' });
  const known = new Set(['company', 'party_name', 'party_code', 'contact', 'city', 'address', 'address_line', 'effective_date', 'term_months', 'notice_days', 'settlement_days', 'commission', 'party_type', 'reg_line', 'pool_limit', 'max_card_limit', 'programmes', 'party_mobile', 'party_id', 'party_address', 'role_title', 'territory', 'fee_text', 'amount_text']);
  const bad = new Set(); [intro, recital, ...clauses.map(c => c.b)].forEach(x => String(x).replace(/\{\{(\w+)\}\}/g, (m, k) => { if (!known.has(k)) bad.add(m); }));
  if (bad.size) return res.status(400).json({ success: false, message: 'Unknown placeholder: ' + [...bad].join(', ') });
  const cur = getRecord('agr_templates', id), rec = { id, title, intro, recital, clauses, term_months, notice_days, settlement_days, version: ((cur && cur.version) || 0) + 1, updated_at: new Date().toISOString(), updated_by: String(req.auth.name || req.auth.role || 'Admin') };
  putRecord('agr_templates', id, rec); audit(req, 'agreement_template', 'agr_templates', id);
  res.json({ success: true, record: rec });
});
function partyEsign(req, res) {
  const kind = req.auth.kind, K = AGR_KIND[kind];
  if (!K) return res.status(403).json({ success: false, message: 'Partners, lenders and retailers only' });
  const acc = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.auth.aid);
  if (acc.locked_until > Date.now()) return res.status(429).json({ success: false, message: 'Locked for a few minutes after repeated wrong passwords' });
  if (!checkPw(String(req.body?.password || ''), acc.pass_hash)) {
    const f = acc.failed + 1;
    db.prepare('UPDATE accounts SET failed=?, locked_until=? WHERE id=?').run(f >= 3 ? 0 : f, f >= 3 ? Date.now() + 10 * 60 * 1000 : 0, acc.id);
    audit(req, 'party_esign_pw_failed');
    return res.status(403).json({ success: false, message: f >= 3 ? 'Too many wrong attempts — locked for 10 minutes' : 'Wrong password (' + (3 - f) + ' attempt' + (3 - f === 1 ? '' : 's') + ' left)' });
  }
  db.prepare('UPDATE accounts SET failed=0, locked_until=0 WHERE id=?').run(acc.id);
  const p = getRecord(K.coll, req.auth.ref);
  if (!p) return res.status(404).json({ success: false, message: 'Record not found' });
  if (p.status !== 'active') return res.status(409).json({ success: false, message: 'Your account is not active yet' });
  const sig = String(req.body?.signature || '');
  if (!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(sig) || sig.length > 60000 || sig.length < 400) return res.status(400).json({ success: false, message: 'Please draw your signature' });
  const dt = kind + '_agreement';
  if (allOf('esigns').some(e => e.doc_type === dt && String(e.ref_id) === String(p.id) && e.status !== 'void')) return res.status(409).json({ success: false, message: 'This agreement is already signed' });
  const snap = agrSnapshot(kind, p), hash = crypto.createHash('sha256').update(JSON.stringify([kind, p[K.code], snap])).digest('hex');
  const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='esigns'").get().m || 0) + 1;
  const rec = { id, doc_type: dt, party_kind: kind, ref_id: p.id, ref_code: p[K.code], [K.idf]: p.id, party_name: p.name, signer: p.contact_person || p.owner || p.name, signature: sig, hash, snapshot: snap, tpl_version: snap.version, effective_date: agrEff(p), signed_at: new Date().toISOString(), device: String(req.headers['user-agent'] || '').slice(0, 80), ip: String(req.ip || '').slice(0, 45) };
  putRecord('esigns', id, rec); audit(req, 'party_esign', 'esigns', id);
  p.agreement_signed_at = rec.signed_at; if (!p.agreement_date) p.agreement_date = rec.effective_date; if (kind !== 'partner') p.stages = Object.assign({}, p.stages, { agreement: true }); putRecord(K.coll, p.id, p);
  notify(kind, p.id, '✍️ Agreement signed', 'You signed the ' + K.label + ' agreement. A copy is available in My Agreement.', 'system');
  notifyStaff(K.perm, '✍️ ' + K.label + ' signed agreement', p.name + ' signed the ' + K.label + ' agreement.', 'system');
  res.json({ success: true, record: rec });
}
app.post('/api/party/esign', auth, partyEsign);
app.post('/api/partner/esign', auth, partyEsign);
function agrRequest(req, res) {
  const kind = String(req.body?.kind || 'partner'), K = AGR_KIND[kind];
  if (!K) return res.status(400).json({ success: false, message: 'Unknown party type' });
  if (!(req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, [K.perm])))) return res.status(403).json({ success: false, message: 'You do not have access to manage this' });
  const p = getRecord(K.coll, String(req.body?.id || req.body?.partner_id || ''));
  if (!p) return res.status(404).json({ success: false, message: 'Not found' });
  if (p.status !== 'active') return res.status(409).json({ success: false, message: 'Only active parties can be asked to sign' });
  if (allOf('esigns').some(e => e.doc_type === kind + '_agreement' && String(e.ref_id) === String(p.id) && e.status !== 'void')) return res.status(409).json({ success: false, message: 'Agreement is already signed' });
  p.agreement_requested_at = new Date().toISOString(); putRecord(K.coll, p.id, p); audit(req, 'agreement_request', K.coll, p.id);
  notify(kind, p.id, '📄 Please sign your agreement', 'Open My Agreement, read the terms and sign digitally.', 'system');
  res.json({ success: true, requested_at: p.agreement_requested_at });
}

app.post('/api/staff/agreement-void', auth, (req, res) => {
  const kind = String(req.body?.kind || ''), K = AGR_KIND[kind];
  if (!K) return res.status(400).json({ success: false, message: 'Unknown party type' });
  if (!(req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_agreements'])))) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can void a signed agreement' });
  const reason = clean(req.body?.reason, 160); if (reason.length < 5) return res.status(400).json({ success: false, message: 'Write the reason (at least 5 characters)' });
  const p = getRecord(K.coll, String(req.body?.id || '')); if (!p) return res.status(404).json({ success: false, message: 'Not found' });
  const e = allOf('esigns').find(x => x.doc_type === kind + '_agreement' && String(x.ref_id) === String(p.id) && x.status !== 'void');
  if (!e) return res.status(409).json({ success: false, message: 'There is no signed agreement to void' });
  e.status = 'void'; e.void_reason = reason; e.voided_at = new Date().toISOString(); e.voided_by = String(req.auth.name || req.auth.role);
  putRecord('esigns', e.id, e);
  p.agreement_signed_at = ''; p.agreement_requested_at = new Date().toISOString(); putRecord(K.coll, p.id, p);
  audit(req, 'agreement_void', 'esigns', e.id);
  notify(kind, p.id, '📄 Please sign the updated agreement', 'Your earlier agreement was replaced (' + reason + '). Open My Agreement and sign the new one.', 'system');
  res.json({ success: true, requested_at: p.agreement_requested_at });
});
app.post('/api/staff/agreement-request-all', auth, (req, res) => {
  const kind = String(req.body?.kind || ''), K = AGR_KIND[kind];
  if (!K) return res.status(400).json({ success: false, message: 'Unknown party type' });
  if (!(req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, [K.perm])))) return res.status(403).json({ success: false, message: 'You do not have access to manage this' });
  const signed = new Set(allOf('esigns').filter(e => e.doc_type === kind + '_agreement' && e.status !== 'void').map(e => String(e.ref_id)));
  let n = 0;
  for (const p of allOf(K.coll)) { if (p.status !== 'active' || signed.has(String(p.id)) || p.agreement_requested_at) continue; p.agreement_requested_at = new Date().toISOString(); putRecord(K.coll, p.id, p); notify(kind, p.id, '📄 Please sign your agreement', 'Open My Agreement, read the terms and sign digitally.', 'system'); n++; }
  audit(req, 'agreement_request_all', K.coll, String(n));
  res.json({ success: true, count: n });
});
app.post('/api/staff/agreement-request', auth, agrRequest);
app.post('/api/staff/partner-agreement-request', auth, agrRequest);
app.post('/api/customer/mandate-request', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const loan = getRecord('loans', String(req.body?.loan_id || ''));
  if (!loan || String(loan.customer_id) !== String(req.auth.ref) || !['approved', 'active'].includes(loan.status)) return res.status(404).json({ success: false, message: 'Active loan not found' });
  const acc = String(req.body?.account_no || '').replace(/\s/g, ''), ifsc = String(req.body?.ifsc || '').toUpperCase().trim(), holder = clean(req.body?.holder_name, 60), bank = clean(req.body?.bank_name, 60);
  if (!/^\d{9,18}$/.test(acc)) return res.status(400).json({ success: false, message: 'Enter a valid bank account number' });
  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) return res.status(400).json({ success: false, message: 'Enter a valid IFSC' });
  if (holder.length < 3 || bank.length < 2) return res.status(400).json({ success: false, message: 'Enter the account holder and bank name' });
  if (!req.body?.consent) return res.status(400).json({ success: false, message: 'Please accept the auto-debit consent' });
  const emi = +loan.emi_amount || 0, max = Math.round(+req.body?.max_amount || emi);
  if (max < emi || max > emi * 3) return res.status(400).json({ success: false, message: 'Maximum debit must be between one and three EMIs (₹' + Math.round(emi) + ' – ₹' + Math.round(emi * 3) + ')' });
  if (allOf('mandates').some(m => String(m.loan_id) === String(loan.id) && ['requested', 'active'].includes(m.status))) return res.status(409).json({ success: false, message: 'An auto-debit request already exists for this loan' });
  const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='mandates'").get().m || 0) + 1;
  const rec = { id, mandate_code: 'PFS-NACH-' + String(id).padStart(5, '0'), customer_id: loan.customer_id, customer_name: loan.customer_name, loan_id: loan.id, loan_code: loan.loan_code, holder_name: holder, bank_name: bank, account_no: acc, ifsc, max_amount: max, emi: emi, status: 'requested', umrn: '', requested_date: todayS(), consent_at: new Date().toISOString() };
  putRecord('mandates', id, rec); audit(req, 'mandate_request', 'mandates', id);
  notifyStaff('manage_autodebit', '🏦 Auto-debit request', 'A customer requested auto-debit — enter the UMRN to activate.', 'system');
  res.json({ success: true, record: rec });
});
app.post('/api/customer/mandate-cancel', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const m = getRecord('mandates', String(req.body?.id || ''));
  if (!m || String(m.customer_id) !== String(req.auth.ref) || !['requested', 'active'].includes(m.status)) return res.status(404).json({ success: false, message: 'Mandate not found' });
  m.status = 'cancelled'; m.cancelled_date = todayS(); putRecord('mandates', m.id, m); audit(req, 'mandate_cancel', 'mandates', m.id);
  res.json({ success: true, record: m });
});
function backupDir() { const d = path.join(path.dirname(DB_PATH), 'backups'); fs.mkdirSync(d, { recursive: true }); return d; }
const ceoOnly = (req, res) => { if (req.auth.kind !== 'staff' || req.auth.role !== 'ceo') { res.status(403).json({ success: false, message: 'CEO only' }); return false; } return true; };
app.get('/api/admin/backups', auth, (req, res) => {
  if (!ceoOnly(req, res)) return;
  res.json({ success: true, rows: fs.readdirSync(backupDir()).filter(x => x.endsWith('.db')).sort().reverse().map(f => ({ name: f, size: fs.statSync(path.join(backupDir(), f)).size })) });
});
app.post('/api/admin/backup-now', auth, (req, res) => {
  if (!ceoOnly(req, res)) return;
  const f = path.join(backupDir(), 'manual-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.db');
  db.exec(`VACUUM INTO '${f.replace(/'/g, "''")}'`);
  fs.readdirSync(backupDir()).filter(x => x.startsWith('manual-')).sort().slice(0, -10).forEach(x => fs.unlinkSync(path.join(backupDir(), x)));
  audit(req, 'backup_now'); res.json({ success: true, name: path.basename(f) });
});
app.get('/api/admin/export', auth, (req, res) => {          // full JSON export of business data (no passwords / accounts)
  if (!ceoOnly(req, res)) return;
  const out = { exported_at: new Date().toISOString(), collections: {} };
  for (const c of Object.keys(COLL)) out.collections[c] = db.prepare('SELECT data FROM records WHERE coll=? AND deleted=0').all(c).map(r => parse(r.data)).filter(Boolean);
  audit(req, 'export_all');
  res.setHeader('Content-Disposition', 'attachment; filename="pratishtha-export-' + todayS() + '.json"');
  res.json(out);
});

// Partner retailers a card can be used at (public-safe fields only)
app.get('/api/customer/retailers', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  res.json({ success: true, rows: allOf('retailers').filter(r => r.status === 'active').map(r => ({ name: r.name, category: r.category || '', city: r.city || '', address: r.address || '' })) });
});

// Retailer: ask for a card payment (the customer approves it in their own app)
// ── live proof photos (customer + product + bill / cash-loan selfie): live camera only, fresh, unique, stored server-side ──
const JPEG_RE = /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/;
function proofCheck(photo, ts) {
  photo = String(photo || '');
  if (!JPEG_RE.test(photo)) return 'A live camera photo is required';
  if (photo.length < 9000 || photo.length > 450000) return 'The photo is unclear or too large — take it again with the live camera';
  const head = Buffer.from(photo.slice(23, 60), 'base64'); if (!(head[0] === 0xFF && head[1] === 0xD8 && head[2] === 0xFF)) return 'Invalid photo';
  const t = Date.parse(ts); if (!t || Math.abs(Date.now() - t) > 5 * 60 * 1000) return 'The photo is not fresh — please take a new live photo';
  const h = crypto.createHash('sha256').update(photo).digest('hex');
  if (allOf('proofs').some(p => p.hash === h)) return 'This photo was already used — take a new live photo';
  return { hash: h };
}
function saveProof(req, o) {
  const id = nextId('proofs');
  const g0 = o.geo !== undefined ? o.geo : req.body?.proof_geo, ts0 = o.ts || req.body.proof_ts;
  const geo = g0 && isFinite(+g0.lat) && isFinite(+g0.lng) ? { lat: +(+g0.lat).toFixed(5), lng: +(+g0.lng).toFixed(5) } : null;
  putRecord('proofs', id, { id, kind: o.kind, ref_id: o.ref_id, customer_id: o.customer_id, retailer_id: o.retailer_id || null, image: o.photo, hash: o.hash, captured_at: new Date(ts0).toISOString(), saved_at: new Date().toISOString(), geo, by: req.auth.kind + ':' + req.auth.ref });
  return id;
}
app.post('/api/retailer/charge', auth, (req, res) => {
  if (req.auth.kind !== 'retailer') return res.status(403).json({ success: false, message: 'Partner retailers only' });
  const ret = getRecord('retailers', req.auth.ref);
  if (!ret || ret.status !== 'active') return res.status(403).json({ success: false, message: 'Retailer account is not active' });
  expireTxns();
  const card = allOf('cards').find(c => c.card_no === String(req.body?.card_no || '').trim().toUpperCase());
  if (!card) return res.status(404).json({ success: false, message: 'Card not found — check the card number' });
  const bad = cardUsable(card); if (bad) return res.status(409).json({ success: false, message: bad });
  const cust = custOK(card.customer_id); if (!cust) return res.status(409).json({ success: false, message: 'Card holder account is not active' });
  const amount = Math.round(+req.body?.amount || 0), cap = polv('card_txn_max', 50000), avail = cardAvail(card);
  if (!(amount >= 100)) return res.status(400).json({ success: false, message: 'Minimum purchase is ₹100' });
  if (amount > cap) return res.status(400).json({ success: false, message: 'Single payment limit is ₹' + cap });
  if (amount > avail) return res.status(409).json({ success: false, message: 'Amount is above the card’s available limit' });
  if (allOf('card_txns').some(t => t.status === 'pending' && String(t.card_id) === String(card.id))) return res.status(409).json({ success: false, message: 'A payment is already waiting for approval on this card' });
  const bill = clean(req.body?.bill_no, 30), item = clean(req.body?.item, 60);
  if (bill.length < 2) return res.status(400).json({ success: false, message: 'Enter the bill / invoice number' });
  if (item.length < 2) return res.status(400).json({ success: false, message: 'Enter the product name' });
  const pc = proofCheck(req.body?.proof_photo, req.body?.proof_ts); if (typeof pc === 'string') return res.status(400).json({ success: false, message: pc, need_photo: true });
  const id = nextId('card_txns'), now = Date.now();
  const rec = { id, txn_code: 'PFS-TX-' + String(id).padStart(5, '0'), retailer_id: ret.id, retailer_name: ret.name, card_id: card.id, card_no: card.card_no, customer_id: cust.id, customer_name: maskName(cust.name),
    amount, bill_no: bill, item, commission_pct: +ret.commission_pct || polv('card_merchant_pct', 2),
    status: 'pending', created_at: new Date(now).toISOString(), expires_at: new Date(now + 10 * 60 * 1000).toISOString() };
  rec.proof_id = saveProof(req, { kind: 'purchase', ref_id: id, customer_id: cust.id, retailer_id: ret.id, photo: String(req.body.proof_photo), hash: pc.hash }); rec.has_proof = true;
  putRecord('card_txns', id, rec); audit(req, 'card_charge', 'card_txns', id);
  notify('customer', cust.id, '💳 Payment request', ret.name + ' is asking ' + inr(amount) + ' on ' + card.card_no + '. Open the app to approve.', 'reminder');
  res.json({ success: true, record: rec });
});
app.get('/api/retailer/txn/:id', auth, (req, res) => {
  if (req.auth.kind !== 'retailer') return res.status(403).json({ success: false, message: 'Partner retailers only' });
  expireTxns();
  const t = getRecord('card_txns', req.params.id);
  if (!t || String(t.retailer_id) !== String(req.auth.ref)) return res.status(404).json({ success: false, message: 'Not found' });
  res.json({ success: true, record: t });
});
app.post('/api/retailer/cancel', auth, (req, res) => {
  if (req.auth.kind !== 'retailer') return res.status(403).json({ success: false, message: 'Partner retailers only' });
  const t = getRecord('card_txns', String(req.body?.id || ''));
  if (!t || String(t.retailer_id) !== String(req.auth.ref) || t.status !== 'pending') return res.status(404).json({ success: false, message: 'No pending payment to cancel' });
  t.status = 'cancelled'; putRecord('card_txns', t.id, t); res.json({ success: true, record: t });
});

// Customer: payments waiting for approval, and approve / decline (password step-up)
app.get('/api/customer/pending-pay', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  expireTxns();
  res.json({ success: true, rows: allOf('card_txns').filter(t => t.status === 'pending' && String(t.customer_id) === String(req.auth.ref)).map(t => Object.assign({}, t, { proof_photo: (getRecord('proofs', String(t.proof_id)) || {}).image || '' })),
    rate: polv('card_purchase_rate', 18), tenures: [3, 6, 9, 12], bill_ok: true });
});
app.post('/api/customer/card-pay', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  expireTxns();
  const t = getRecord('card_txns', String(req.body?.id || ''));
  if (!t || String(t.customer_id) !== String(req.auth.ref)) return res.status(404).json({ success: false, message: 'Payment not found' });
  if (t.status !== 'pending') return res.status(409).json({ success: false, message: 'This payment is no longer pending (' + t.status + ')' });
  if (req.body?.action === 'decline') { t.status = 'declined'; putRecord('card_txns', t.id, t); audit(req, 'card_pay_decline', 'card_txns', t.id); return res.json({ success: true, record: t }); }
  const card = getRecord('cards', t.card_id), bad = cardUsable(card);
  if (bad) return res.status(409).json({ success: false, message: bad });
  if (t.amount > cardAvail(card)) return res.status(409).json({ success: false, message: 'Not enough card limit for this payment' });
  const bill = +req.body?.tenure === 0;                 // "pay later": 30-day bill, no interest — can be converted to EMI or paid off from the card dashboard
  const n = bill ? 1 : ([3, 6, 9, 12].includes(+req.body?.tenure) ? +req.body.tenure : 6), rate = bill ? 0 : polv('card_purchase_rate', 18);
  const id = nextId('loans'), cust = getRecord('customers', t.customer_id);
  const loan = { id, loan_code: 'PFS-L-' + String(id).padStart(4, '0'), customer_id: t.customer_id, customer_name: cust?.name || '', loan_type: 'card_purchase', source: 'card_purchase', card_id: card.id, card_no: card.card_no,
    retailer_id: t.retailer_id, txn_id: t.id, principal_amount: t.amount, interest_rate: rate, tenure_months: n, emi_amount: emiCalc(t.amount, rate, n), outstanding_amount: t.amount, paid_emis: 0,
    status: 'active', disbursement_date: todayS(), applied_date: todayS(), sanctioned_date: todayS(), paid_total: 0, penalty_paid: 0, net_disbursed: t.amount, bill_mode: bill, remarks: 'Card purchase at ' + t.retailer_name };
  putRecord('loans', id, loan);
  t.status = 'approved'; t.loan_id = id; t.loan_code = loan.loan_code; t.tenure = bill ? 0 : n; t.emi = loan.emi_amount; t.approved_at = new Date().toISOString();
  putRecord('card_txns', t.id, t); audit(req, 'card_pay_approve', 'card_txns', t.id);
  res.json({ success: true, record: t, loan });
});

// Card dues: convert a card bill / unpaid card EMI loan to a fresh EMI plan, or request pay-off (verified by staff like any online payment)
app.post('/api/customer/card-convert', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const loan = getRecord('loans', String(req.body?.loan_id || ''));
  if (!loan || String(loan.customer_id) !== String(req.auth.ref) || loan.source !== 'card_purchase') return res.status(404).json({ success: false, message: 'Card purchase not found' });
  if (loan.status !== 'active') return res.status(409).json({ success: false, message: 'This purchase is not active' });
  if ((+loan.paid_total || 0) > 0) return res.status(409).json({ success: false, message: 'EMI plan cannot be changed after a payment has been made' });
  if (allOf('collections').some(c => c.status === 'pending' && c.ref_type === 'loan' && String(c.ref_id) === String(loan.id))) return res.status(409).json({ success: false, message: 'A payment for this purchase is awaiting verification' });
  const n = +req.body?.tenure; if (![3, 6, 9, 12].includes(n)) return res.status(400).json({ success: false, message: 'Choose 3, 6, 9 or 12 months' });
  const rate = polv('card_purchase_rate', 18), was = loan.bill_mode ? 'bill' : (loan.tenure_months + 'm EMI');
  loan.bill_mode = false; loan.interest_rate = rate; loan.tenure_months = n; loan.emi_amount = emiCalc(+loan.principal_amount, rate, n);
  loan.disbursement_date = todayS(); loan.converted_at = new Date().toISOString(); loan.remarks = (loan.remarks || '') + ' | converted from ' + was + ' to ' + n + 'm EMI on ' + todayS();
  putRecord('loans', loan.id, loan);
  const t = loan.txn_id ? getRecord('card_txns', String(loan.txn_id)) : null; if (t) { t.tenure = n; t.emi = loan.emi_amount; putRecord('card_txns', t.id, t); }
  audit(req, 'card_convert_emi', 'loans', loan.id);
  notify('customer', loan.customer_id, '🔁 Converted to EMI', inr(loan.principal_amount) + ' on ' + loan.card_no + ' is now ' + n + ' EMIs of ' + inr(loan.emi_amount) + '.', 'loan');
  res.json({ success: true, loan, txn: t });
});
app.post('/api/customer/card-payoff', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  const cid = String(req.auth.ref), loan = getRecord('loans', String(req.body?.loan_id || ''));
  if (!loan || String(loan.customer_id) !== cid || !loan.card_id) return res.status(404).json({ success: false, message: 'Card loan not found' });
  if (loan.status !== 'active') return res.status(409).json({ success: false, message: 'This loan is not active' });
  const amount = Math.round((+req.body?.amount || 0) * 100) / 100;
  if (!(amount >= 1) || amount > 1000000) return res.status(400).json({ success: false, message: 'Invalid amount' });
  if (allOf('collections').some(c => c.status === 'pending' && String(c.customer_id) === cid && c.ref_type === 'loan' && String(c.ref_id) === String(loan.id))) return res.status(409).json({ success: false, message: 'A payment for this loan is already awaiting verification' });
  const mode = ['upi', 'card', 'netbanking', 'bank'].includes(req.body?.mode) ? req.body.mode : 'upi', full = !!req.body?.foreclosure;
  const cust = getRecord('customers', cid), id = nextId('collections');
  const rec = { id, collection_code: 'PFS-COL-' + String(id).padStart(4, '0'), customer_id: cust.id, customer_name: cust.name, amount, payment_mode: mode, collection_date: todayS(),
    ref_type: 'loan', ref_id: loan.id, ref_label: (full ? 'Card payoff ' : 'Card dues ') + loan.loan_code, agent_name: 'Self (Online)', upi_ref: clean(req.body?.upi_ref, 40), status: 'pending', foreclosure: full || undefined };
  putRecord('collections', id, rec); audit(req, full ? 'card_payoff_request' : 'card_dues_request', 'collections', id);
  notifyStaff('create_collections', '💳 Card dues payment to verify', cust.name + ' submitted ' + inr(amount) + (full ? ' to close a card loan' : '') + ' for verification.', 'collection');
  res.json({ success: true, record: rec });
});


// ─────────────────────────── Gold loans: appraisal → vault → loan → release (all value maths done here, never trusted from the browser) ───────────────────────────
const GOLD_KARATS = [18, 20, 22, 24], goldRate = () => polv('gold_rate_22k', 7500), goldLtv = () => Math.max(10, Math.min(75, polv('gold_ltv_pct', 75)));
const goldCan = req => req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_gold']));
const goldCode = id => 'PFS-GL-' + String(id).padStart(4, '0');
function goldItems(raw) {
  if (!Array.isArray(raw) || !raw.length || raw.length > 12) return 'Add 1 to 12 gold items';
  const rate = goldRate(), items = []; let gross = 0, net = 0, val = 0;
  for (const r of raw) {
    const g = +r.gross_g, st = +r.stone_g || 0, k = +r.purity_k, d = clean(r.desc, 40);
    if (!(g > 0 && g <= 2000) || !(st >= 0 && st < g)) return 'Check the weights (stone weight must be less than gross weight)';
    if (!GOLD_KARATS.includes(k)) return 'Purity must be 18, 20, 22 or 24 karat';
    if (d.length < 2) return 'Describe each item (ring, chain, bangle…)';
    const n = r2s(g - st), v = r2s(n * rate * k / 22);
    items.push({ desc: d, gross_g: r2s(g), stone_g: r2s(st), net_g: n, purity_k: k, value: v }); gross += g; net += n; val += v;
  }
  return { items, gross: r2s(gross), net: r2s(net), value: r2s(val) };
}
function goldOwed(l) {
  if (!l || !['active', 'approved', 'pending', 'defaulted'].includes(l.status)) return 0;
  const tot = (+l.emi_amount || +l.principal_amount) * (+l.tenure_months || 1);
  return r2s((+l.principal_amount || 0) * (1 - Math.min(1, (+l.paid_total || 0) / (tot || 1))));
}
app.post('/api/staff/gold-appraise', auth, (req, res) => {
  if (!goldCan(req)) return res.status(403).json({ success: false, message: 'You do not have gold-loan access' });
  const cust = custOK(req.body?.customer_id); if (!cust) return res.status(404).json({ success: false, message: 'Customer not found or not active' });
  const gi = goldItems(req.body?.items); if (typeof gi === 'string') return res.status(400).json({ success: false, message: gi });
  const ltv = goldLtv(), maxLoan = Math.floor(gi.value * ltv / 100), amount = Math.round(+req.body?.amount || 0), tenure = +req.body?.tenure;
  if (![3, 6, 9, 12].includes(tenure)) return res.status(400).json({ success: false, message: 'Choose 3, 6, 9 or 12 months' });
  const cap = polv('gold_max_loan', 1000000);
  if (!(amount >= 1000)) return res.status(400).json({ success: false, message: 'Minimum gold loan is ₹1,000' });
  if (amount > maxLoan) return res.status(400).json({ success: false, message: 'Maximum for this gold is ₹' + maxLoan + ' (' + ltv + '% of ₹' + gi.value + ')' });
  if (amount > cap) return res.status(400).json({ success: false, message: 'Single gold loan limit is ₹' + cap });
  const method = ['acid', 'touchstone', 'xrf'].includes(req.body?.test_method) ? req.body.test_method : '';
  if (!method) return res.status(400).json({ success: false, message: 'Select the purity test method' });
  const loans = allOf('loans').filter(l => String(l.customer_id) === String(cust.id));
  if (loans.some(l => l.status === 'defaulted')) return res.status(409).json({ success: false, message: 'This customer has a defaulted loan' });
  const p1 = proofCheck(req.body?.proof_items, req.body?.proof_items_ts); if (typeof p1 === 'string') return res.status(400).json({ success: false, message: 'Gold photo: ' + p1, need_photo: true });
  const p2 = proofCheck(req.body?.proof_cust, req.body?.proof_cust_ts); if (typeof p2 === 'string') return res.status(400).json({ success: false, message: 'Customer photo: ' + p2, need_photo: true });
  if (req.body.proof_items === req.body.proof_cust) return res.status(400).json({ success: false, message: 'Take two different photos (gold items, and customer with the gold)', need_photo: true });
  let pl = null; const rid = req.body?.request_id;
  if (rid) { pl = getRecord('gold_pledges', String(rid)); if (!pl || pl.status !== 'requested' || String(pl.customer_id) !== String(cust.id)) return res.status(409).json({ success: false, message: 'That request is not open for this customer' }); }
  const pid = pl ? pl.id : nextId('gold_pledges'), lid = nextId('loans'), rate = polv('gold_rate_pct', 18);
  const loan = { id: lid, loan_code: 'PFS-L-' + String(lid).padStart(4, '0'), customer_id: cust.id, customer_name: cust.name, loan_type: 'gold', source: 'gold', gold_id: pid, principal_amount: amount, interest_rate: rate, tenure_months: tenure,
    emi_amount: emiCalc(amount, rate, tenure), outstanding_amount: amount, paid_emis: 0, paid_total: 0, penalty_paid: 0, status: 'pending', applied_date: todayS(), purpose: 'Gold loan against ' + gi.net + ' g', remarks: 'Pledge ' + goldCode(pid) };
  const rec = Object.assign(pl || {}, { id: pid, pledge_code: goldCode(pid), customer_id: cust.id, customer_name: cust.name, items: gi.items, total_gross_g: gi.gross, total_net_g: gi.net, rate_22k: goldRate(), ltv_pct: ltv, market_value: gi.value, max_loan: maxLoan,
    loan_amount: amount, tenure_months: tenure, interest_rate: rate, loan_id: lid, loan_code: loan.loan_code, hallmark: !!req.body?.hallmark, test_method: method, status: 'appraised', appraised_by: String(req.auth.name || req.auth.role), appraised_by_id: req.auth.aid, appraised_at: new Date().toISOString() });
  putRecord('loans', lid, loan);
  rec.proof_items_id = saveProof(req, { kind: 'gold_items', ref_id: pid, customer_id: cust.id, photo: String(req.body.proof_items), hash: p1.hash, ts: req.body.proof_items_ts, geo: req.body.proof_geo });
  rec.proof_cust_id = saveProof(req, { kind: 'gold_customer', ref_id: pid, customer_id: cust.id, photo: String(req.body.proof_cust), hash: p2.hash, ts: req.body.proof_cust_ts, geo: req.body.proof_geo });
  putRecord('gold_pledges', pid, rec); audit(req, 'gold_appraise', 'gold_pledges', pid);
  notify('customer', cust.id, '🪙 Gold appraised', 'Your ' + gi.net + ' g gold is valued at ' + inr(gi.value) + '. Loan ' + inr(amount) + ' (' + loan.loan_code + ') is waiting for approval.', 'loan');
  res.json({ success: true, pledge: rec, loan });
});
app.post('/api/staff/gold-vault', auth, (req, res) => {
  if (!goldCan(req)) return res.status(403).json({ success: false, message: 'You do not have gold-loan access' });
  const pl = getRecord('gold_pledges', String(req.body?.pledge_id || ''));
  if (!pl || pl.status !== 'appraised') return res.status(409).json({ success: false, message: 'Only an appraised pledge can be sealed in the vault' });
  if (req.auth.role !== 'ceo' && String(pl.appraised_by_id) === String(req.auth.aid)) return res.status(403).json({ success: false, message: 'Dual control: a different staff member must seal and vault the gold' });
  const pk = clean(req.body?.packet_no, 30).toUpperCase(), loc = clean(req.body?.vault_loc, 40);
  if (pk.length < 3 || loc.length < 2) return res.status(400).json({ success: false, message: 'Enter the sealed packet number and the vault / locker location' });
  if (allOf('gold_pledges').some(x => x.packet_no === pk)) return res.status(409).json({ success: false, message: 'This packet number is already used' });
  const pc = proofCheck(req.body?.proof, req.body?.proof_ts); if (typeof pc === 'string') return res.status(400).json({ success: false, message: 'Sealed-packet photo: ' + pc, need_photo: true });
  pl.proof_vault_id = saveProof(req, { kind: 'gold_vault', ref_id: pl.id, customer_id: pl.customer_id, photo: String(req.body.proof), hash: pc.hash, ts: req.body.proof_ts, geo: req.body.proof_geo });
  pl.packet_no = pk; pl.vault_loc = loc; pl.vaulted_by = String(req.auth.name || req.auth.role); pl.vaulted_at = new Date().toISOString(); pl.status = 'vaulted';
  putRecord('gold_pledges', pl.id, pl); audit(req, 'gold_vault', 'gold_pledges', pl.id);
  notify('customer', pl.customer_id, '🔐 Gold sealed in vault', 'Your gold (packet ' + pk + ') is safely sealed. Loan ' + pl.loan_code + ' can now be disbursed.', 'loan');
  notifyStaff('disburse_loans', '🪙 Gold vaulted — ready to disburse', pl.customer_name + ' — ' + pl.loan_code + ' (' + inr(pl.loan_amount) + ')', 'loan');
  res.json({ success: true, pledge: pl });
});
app.post('/api/staff/gold-release', auth, (req, res) => {
  if (!goldCan(req)) return res.status(403).json({ success: false, message: 'You do not have gold-loan access' });
  const pl = getRecord('gold_pledges', String(req.body?.pledge_id || '')), loan = pl && getRecord('loans', String(pl.loan_id));
  if (!pl) return res.status(404).json({ success: false, message: 'Pledge not found' });
  if (!pl || pl.status !== 'vaulted') return res.status(409).json({ success: false, message: 'This gold is not in the vault' });
  if (!loan || loan.status !== 'closed') return res.status(409).json({ success: false, message: 'Gold can be released only after the loan is fully repaid and closed' });
  const pc = proofCheck(req.body?.proof, req.body?.proof_ts); if (typeof pc === 'string') return res.status(400).json({ success: false, message: 'Release photo: ' + pc, need_photo: true });
  pl.proof_release_id = saveProof(req, { kind: 'gold_release', ref_id: pl.id, customer_id: pl.customer_id, photo: String(req.body.proof), hash: pc.hash, ts: req.body.proof_ts, geo: req.body.proof_geo });
  pl.status = 'release_pending'; pl.release_by = String(req.auth.name || req.auth.role); pl.release_at = new Date().toISOString();
  putRecord('gold_pledges', pl.id, pl); audit(req, 'gold_release_start', 'gold_pledges', pl.id);
  notify('customer', pl.customer_id, '🪙 Collect your gold', 'Your loan is closed. Collect packet ' + pl.packet_no + ' and confirm receipt in the app (Gold Loan page).', 'loan');
  res.json({ success: true, pledge: pl });
});
app.post('/api/customer/gold-release-confirm', auth, (req, res) => {
  if (!needCustomer(req, res) || !needStepup(req, res)) return;
  const pl = getRecord('gold_pledges', String(req.body?.pledge_id || ''));
  if (!pl || String(pl.customer_id) !== String(req.auth.ref) || pl.status !== 'release_pending') return res.status(404).json({ success: false, message: 'No gold waiting for your confirmation' });
  pl.status = 'released'; pl.released_at = new Date().toISOString(); putRecord('gold_pledges', pl.id, pl); audit(req, 'gold_release_confirm', 'gold_pledges', pl.id);
  notifyStaff('manage_gold', '🪙 Gold released', pl.customer_name + ' confirmed receipt of ' + pl.pledge_code + '.', 'loan');
  res.json({ success: true, pledge: pl });
});
app.post('/api/customer/gold-request', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  const cust = custOK(req.auth.ref); if (!cust) return res.status(403).json({ success: false, message: 'Account not active' });
  if (allOf('gold_pledges').some(p => String(p.customer_id) === String(cust.id) && p.status === 'requested')) return res.status(409).json({ success: false, message: 'You already have an appraisal request open' });
  const w = +req.body?.approx_g, d = clean(req.body?.desc, 80);
  if (!(w > 0 && w <= 2000) || d.length < 3) return res.status(400).json({ success: false, message: 'Enter the approximate weight and what the gold is (ring, chain…)' });
  const id = nextId('gold_pledges');
  const rec = { id, pledge_code: goldCode(id), customer_id: cust.id, customer_name: cust.name, status: 'requested', req_desc: d, req_approx_g: r2s(w), req_note: clean(req.body?.note, 100), requested_at: new Date().toISOString() };
  putRecord('gold_pledges', id, rec); audit(req, 'gold_request', 'gold_pledges', id);
  notifyStaff('manage_gold', '🪙 Gold appraisal request', cust.name + ' wants a gold loan (~' + w + ' g).', 'loan');
  notify('customer', cust.id, '🪙 Request received', 'Bring your gold (and ID) to the branch for appraisal. Your request is ' + rec.pledge_code + '.', 'loan');
  res.json({ success: true, pledge: rec });
});
app.post('/api/staff/gold-auction', auth, (req, res) => {
  if (req.auth.kind !== 'staff' || req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can start or complete a gold auction' });
  const pl = getRecord('gold_pledges', String(req.body?.pledge_id || '')), loan = pl && getRecord('loans', String(pl.loan_id));
  const reason = clean(req.body?.reason, 120); if (reason.length < 5) return res.status(400).json({ success: false, message: 'Enter the reason' });
  if (!pl || !loan) return res.status(404).json({ success: false, message: 'Pledge not found' });
  if (req.body?.action === 'notice') {
    if (pl.status !== 'vaulted') return res.status(409).json({ success: false, message: 'Only vaulted gold can get an auction notice' });
    if (loan.status !== 'defaulted' && !(loan.status === 'active' && pl.margin_flag)) return res.status(409).json({ success: false, message: 'A notice needs a defaulted loan or an unresolved margin call' });
    pl.status = 'auction_notice'; pl.notice_date = todayS(); pl.notice_reason = reason; putRecord('gold_pledges', pl.id, pl); audit(req, 'gold_auction_notice', 'gold_pledges', pl.id);
    notify('customer', pl.customer_id, '⚠️ Gold auction notice', 'Your gold ' + pl.pledge_code + ' will be auctioned after 30 days (' + pl.notice_date + ') unless the loan is cleared. ' + reason, 'loan');
    return res.json({ success: true, pledge: pl });
  }
  if (req.body?.action === 'auction') {
    if (pl.status !== 'auction_notice') return res.status(409).json({ success: false, message: 'Send the notice first' });
    if (Date.parse(todayS()) - Date.parse(pl.notice_date) < 30 * 86400000) return res.status(409).json({ success: false, message: 'The 30-day notice period has not ended (notice sent ' + pl.notice_date + ')' });
    const amt = r2s(req.body?.amount); if (!(amt > 0)) return res.status(400).json({ success: false, message: 'Enter the auction amount' });
    pl.status = 'auctioned'; pl.auction_date = todayS(); pl.auction_amount = amt; pl.auction_reason = reason; putRecord('gold_pledges', pl.id, pl); audit(req, 'gold_auction', 'gold_pledges', pl.id);
    notify('customer', pl.customer_id, '🪙 Gold auctioned', 'Your gold ' + pl.pledge_code + ' was auctioned for ' + inr(amt) + '. Any surplus after clearing dues will be returned.', 'loan');
    return res.json({ success: true, pledge: pl });
  }
  res.status(400).json({ success: false, message: 'Unknown action' });
});
app.get('/api/gold/rate', auth, (req, res) => {
  const pol = (getRecord('policy', '_') || {}).v || {};
  res.json({ success: true, rate_22k: goldRate(), date: pol.gold_rate_date || '', ltv_pct: goldLtv(), interest_pa: polv('gold_rate_pct', 18), max_loan: polv('gold_max_loan', 1000000), tenures: [3, 6, 9, 12] });
});
app.post('/api/staff/gold-rate', auth, (req, res) => {
  if (!goldCan(req)) return res.status(403).json({ success: false, message: 'You do not have gold-loan access' });
  const r = r2s(req.body?.rate_22k); if (!(r >= 1000 && r <= 30000)) return res.status(400).json({ success: false, message: 'Enter the 22K rate per gram (₹1,000 – ₹30,000)' });
  const cur = goldRate(); if (Math.abs(r - cur) / cur > 0.15 && req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'A change of more than 15% needs the CEO' });
  const pol = getRecord('policy', '_') || { v: {} }; pol.v = Object.assign({}, pol.v, { gold_rate_22k: r, gold_rate_date: todayS() });
  putRecord('policy', '_', pol); audit(req, 'gold_rate', 'policy', '_');
  res.json({ success: true, rate_22k: r, date: todayS(), policy: pol.v });
});
app.post('/api/staff/gold-margin-scan', auth, (req, res) => {
  if (!goldCan(req)) return res.status(403).json({ success: false, message: 'You do not have gold-loan access' });
  const rate = goldRate(), out = []; let notified = 0;
  for (const pl of allOf('gold_pledges')) {
    if (pl.status !== 'vaulted') continue;
    const loan = getRecord('loans', String(pl.loan_id)); if (!loan || !['active', 'defaulted'].includes(loan.status)) continue;
    const value = (pl.items || []).reduce((a, it) => a + it.net_g * rate * it.purity_k / 22, 0), owed = goldOwed(loan), cur = value > 0 ? r2s(owed / value * 100) : 999;
    const flag = cur >= 85; out.push({ pledge_id: pl.id, code: pl.pledge_code, customer: pl.customer_name, ltv_now: cur, flag });
    if (flag !== !!pl.margin_flag) { pl.margin_flag = flag; pl.margin_ltv = cur; putRecord('gold_pledges', pl.id, pl); }
    if (flag && pl.margin_notified !== todayS()) { notify('customer', pl.customer_id, '⚠️ Gold loan margin alert', 'Gold price has fallen: your loan is now ' + cur + '% of your gold value. Please pay part of the loan or add gold to avoid auction.', 'loan'); pl.margin_notified = todayS(); putRecord('gold_pledges', pl.id, pl); notified++; }
  }
  res.json({ success: true, rate, rows: out, notified });
});

// Insurance — enrolment, claims (customer side). Plans / activation / claim handling are staff-side via sync.
const clean = (v, n = 80) => String(v == null ? '' : v).replace(/[<>]/g, '').trim().slice(0, n);
app.post('/api/customer/insurance-enroll', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  const cust = custOK(req.auth.ref); if (!cust) return res.status(403).json({ success: false, message: 'Account not active' });
  const plan = getRecord('ins_plans', String(req.body?.plan_id || ''));
  if (!plan || plan.active === false) return res.status(404).json({ success: false, message: 'Plan not available' });
  if (!req.body?.consent) return res.status(400).json({ success: false, message: 'Please accept the consent to continue' });
  const nominee = clean(req.body?.nominee_name, 60), rel = clean(req.body?.nominee_relation, 30);
  if (nominee.length < 2 || rel.length < 2) return res.status(400).json({ success: false, message: 'Nominee name and relationship are required' });
  let rt = ['loan', 'card', 'rd', 'service'].includes(req.body?.ref_type) ? req.body.ref_type : 'service', rid = req.body?.ref_id != null ? String(req.body.ref_id) : '', base = 0, label = 'Standalone';
  if (rt === 'loan' || rt === 'card' || rt === 'rd') {
    const rec = getRecord({ loan: 'loans', card: 'cards', rd: 'rds' }[rt], rid);
    if (!rec || String(rec.customer_id) !== String(cust.id)) return res.status(404).json({ success: false, message: 'Linked product not found' });
    base = rt === 'loan' ? +rec.principal_amount : rt === 'card' ? +rec.limit : (+rec.monthly_amount || +rec.amount || 0) * (+rec.tenure_months || 12);
    label = rt === 'loan' ? 'Loan ' + rec.loan_code : rt === 'card' ? 'Card ' + rec.card_no : 'RD ' + rec.rd_code;
  } else rid = '';
  const pols = allOf('ins_policies');
  if (pols.some(p => String(p.customer_id) === String(cust.id) && String(p.plan_id) === String(plan.id) && String(p.ref_id || '') === rid && p.ref_type === rt && ['requested', 'active'].includes(p.status)))
    return res.status(409).json({ success: false, message: 'You already have this plan for this product' });
  const premium = r2s(plan.premium_basis === 'pct' ? base * (+plan.premium_pct || 0) / 100 : +plan.premium || 0);
  const cover = plan.cover_basis === 'ref' && base ? Math.round(base) : +plan.sum_insured || 0;
  if (!(premium > 0)) return res.status(400).json({ success: false, message: 'This plan needs a linked loan, card or RD to calculate the premium' });
  const id = nextId('ins_policies');
  const rec = { id, policy_ref: 'PFS-INS-' + String(id).padStart(5, '0'), cert_no: '', plan_id: plan.id, plan_name: plan.name, insurer: plan.insurer || '', customer_id: cust.id, customer_name: cust.name,
    ref_type: rt, ref_id: rid, ref_label: label, sum_insured: cover, premium, term_months: +plan.term_months || 12, nominee_name: nominee, nominee_relation: rel, nominee_dob: clean(req.body?.nominee_dob, 10),
    status: 'requested', requested_date: todayS(), start_date: '', end_date: '', premium_paid: false };
  putRecord('ins_policies', id, rec); audit(req, 'insurance_enroll', 'ins_policies', id);
  res.json({ success: true, record: rec });
});
app.post('/api/customer/insurance-claim', auth, (req, res) => {
  if (!needCustomer(req, res)) return;
  const pol = getRecord('ins_policies', String(req.body?.policy_id || ''));
  if (!pol || String(pol.customer_id) !== String(req.auth.ref)) return res.status(404).json({ success: false, message: 'Policy not found' });
  if (pol.status !== 'active') return res.status(409).json({ success: false, message: 'Only an active policy can be claimed' });
  if (pol.end_date && pol.end_date < todayS()) return res.status(409).json({ success: false, message: 'This policy has expired' });
  const desc = clean(req.body?.description, 400), date = clean(req.body?.event_date, 10), ev = clean(req.body?.event_type, 30);
  if (desc.length < 10 || !/^\d{4}-\d\d-\d\d$/.test(date) || date > todayS() || !ev) return res.status(400).json({ success: false, message: 'Event type, a valid past date and a short description are required' });
  if (allOf('ins_claims').some(c => String(c.policy_id) === String(pol.id) && !['settled', 'rejected', 'closed'].includes(c.status))) return res.status(409).json({ success: false, message: 'A claim is already open on this policy' });
  const plan = getRecord('ins_plans', pol.plan_id) || {};
  const id = nextId('ins_claims'), now = new Date().toISOString();
  const rec = { id, claim_no: 'PFS-CL-' + String(id).padStart(5, '0'), policy_id: pol.id, policy_ref: pol.policy_ref, cert_no: pol.cert_no, customer_id: pol.customer_id, customer_name: pol.customer_name, plan_name: pol.plan_name,
    event_type: ev, event_date: date, description: desc, contact: clean(req.body?.contact, 15), docs_required: plan.claim_docs || [], status: 'submitted', filed_date: todayS(), claim_amount: Math.min(+req.body?.claim_amount || 0, +pol.sum_insured || 0),
    timeline: [{ ts: now, status: 'submitted', note: 'Claim submitted by customer' }] };
  putRecord('ins_claims', id, rec); audit(req, 'insurance_claim', 'ins_claims', id);
  notify('customer', pol.customer_id, '📝 Claim submitted', rec.claim_no + ' received. We will update you here.', 'system');
  notifyStaff('manage_insurance', '📝 New insurance claim', 'A customer filed an insurance claim.', 'system');
  res.json({ success: true, record: rec });
});

// Legacy per-entity calls the older frontend makes — data now travels through /api/sync

// ─────────────────────────── automatic reminders (agreements, cards, RD, insurance) ───────────────────────────
function remindOnce(key) { if (getRecord('remind_log', key)) return false; putRecord('remind_log', key, { id: key, at: new Date().toISOString() }); return true; }
const remDays = (k, d) => Math.max(1, Math.min(120, Math.round(polv(k, d))));
function runReminders() {
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const dd = d => { const x = new Date(String(d).slice(0, 10)); return isNaN(x) ? null : Math.ceil((x - today) / 86400000); };
  const out = { agreements: 0, cards: 0, rds: 0, insurance: 0, plans: 0, complaints: 0 };
  const esigns = allOf('esigns').filter(e => e.status !== 'void' && /_agreement$/.test(e.doc_type || ''));
  for (const e of esigns) {
    const kind = e.party_kind, K = AGR_KIND[kind]; if (!K) continue;
    const p = getRecord(K.coll, String(e.ref_id)); if (!p || p.status !== 'active') continue;
    const st = new Date(e.effective_date || e.signed_at); if (isNaN(st)) continue;
    const end = new Date(st); end.setMonth(end.getMonth() + ((e.snapshot && e.snapshot.term_months) || 12));
    const left = Math.ceil((end - today) / 86400000); if (left > remDays('remind_agr_days', 30)) continue;
    const wk = Math.floor(Date.now() / (7 * 86400000));
    if (remindOnce('agr:' + e.id + ':' + wk)) {
      notify(kind, p.id, left < 0 ? '⌛ Agreement expired' : '⏳ Agreement expires in ' + left + ' day(s)', 'Please contact Pratishtha to renew your ' + K.label + ' agreement.', 'system');
      notifyStaff(K.perm, left < 0 ? '⌛ Agreement expired' : '⏳ Agreement expiring', p.name + ' (' + K.label + ') — ' + (left < 0 ? 'expired' : left + ' day(s) left') + '. Void & request a new signature to renew.', 'system'); out.agreements++;
    }
  }
  for (const c of allOf('cards')) {
    if (c.status !== 'active' || !c.valid_till) continue; const left = dd(c.valid_till);
    if (left === null || left < 0 || left > remDays('remind_card_days', 15)) continue;
    if (remindOnce('card:' + c.id + ':' + c.valid_till)) { notify('customer', c.customer_id, '💳 Card expiring soon', 'Your ' + (c.card_no || 'PFS card') + ' is valid till ' + agrDate(c.valid_till) + '. Ask us to renew it.', 'system'); out.cards++; }
  }
  for (const r of allOf('rds')) {
    if (r.status !== 'active' || !r.maturity_date) continue; const left = dd(r.maturity_date);
    if (left === null || left > remDays('remind_rd_days', 7)) continue;
    if (remindOnce('rd:' + r.id + ':' + r.maturity_date)) { notify('customer', r.customer_id, left < 0 ? '🏁 RD matured' : '🏁 RD maturing soon', (r.rd_code || 'Your RD') + (left < 0 ? ' has matured.' : ' matures in ' + left + ' day(s).') + ' Contact us to collect the maturity amount.', 'system'); out.rds++; }
  }
  for (const p of allOf('ins_policies')) {
    if (p.status !== 'active' || !p.end_date) continue; const left = dd(p.end_date);
    if (left === null || left < 0 || left > remDays('remind_ins_days', 15)) continue;
    if (remindOnce('ins:' + p.id + ':' + p.end_date)) { notify('customer', p.customer_id, '🛡️ Insurance ending soon', (p.plan_name || 'Your policy') + ' ends on ' + agrDate(p.end_date) + '. Renew to stay covered.', 'system'); out.insurance++; }
  }
  for (const a of allOf('plan_accts')) {
    if (a.status !== 'active' || !a.maturity_date) continue; const left = dd(a.maturity_date);
    if (left !== null && left <= remDays('remind_rd_days', 7) && remindOnce('plan:' + a.id + ':' + a.maturity_date)) {
      notify('customer', a.customer_id, left < 0 ? '🏁 Plan matured' : '🏁 Plan maturing soon', (a.plan_name || 'Your plan') + (left < 0 ? ' has matured.' : ' matures in ' + left + ' day(s).') + ' Contact us to collect the maturity amount.', 'system');
      notifyStaff('manage_plans', '🏁 Plan maturity', (a.plan_name || 'Plan') + ' #' + a.id + (left < 0 ? ' matured' : ' matures in ' + left + ' day(s)'), 'system'); out.plans++;
    }
    if (a.kind === 'recurring' && a.start_date && a.units_paid < a.units_total) {
      const ym = today.toISOString().slice(0, 7), sd = new Date(String(a.start_date).slice(0, 10));
      const monthsIn = isNaN(sd) ? 0 : (today.getFullYear() - sd.getFullYear()) * 12 + today.getMonth() - sd.getMonth();
      if (monthsIn >= 1 && a.unit !== 'day' && a.units_paid <= monthsIn && remindOnce('planins:' + a.id + ':' + ym)) {
        notify('customer', a.customer_id, '📅 Instalment due', 'Your ' + (a.plan_name || 'plan') + ' instalment of ₹' + a.amount + ' is due this month. Please pay to keep the plan on track.', 'system'); out.plans++;
      }
    }
  }
  for (const c of allOf('complaints')) {
    if (c.status !== 'open' && c.status !== 'in_progress') continue; const left = dd(c.due_date);
    if (left === null || left >= 0) continue;
    if (remindOnce('cmp:' + c.id + ':' + Math.floor(Date.now() / (7 * 86400000)))) { notifyStaff('manage_plans', '⚠️ Complaint overdue', (c.number || c.id) + ' is past its ' + (c.due_date || '').slice(0, 10) + ' deadline. Please resolve it.', 'system'); out.complaints++; }
  }
  return out;
}
app.post('/api/staff/run-reminders', auth, (req, res) => {
  if (!(req.auth.kind === 'staff' && req.auth.role === 'ceo')) return res.status(403).json({ success: false, message: 'Only the CEO can run reminders' });
  const r = runReminders(); audit(req, 'run_reminders'); res.json({ success: true, sent: r });
});
setInterval(() => { try { runReminders(); } catch (e) { console.error('reminders failed', e.message); } }, 6 * 60 * 60 * 1000).unref();



// ─────────────────────────── PFS Savings Plans (catalogue + accounts + Bond Certificate) ───────────────────────────
// The CEO (or anyone given "manage_plans") customises the catalogue; customers request a plan, staff confirm the money and the
// server issues a numbered Bond Certificate. Accounts/bonds are written ONLY by the endpoints below (never by raw sync).
const PLAN_DEFAULTS = JSON.parse(fs.readFileSync(path.join(__dirname, 'plan-defaults.json'), 'utf8'));
const PLAN_KINDS = ['recurring', 'income', 'certificate'];
function planCalc(p, amount, months) {
  amount = +amount; months = +months;
  if (!p || !(amount > 0) || !Number.isInteger(months) || !(months >= 1) || months > 1200 || !Number.isFinite(amount) || amount > 1e9) return null;
  const rate = Math.max(0, +p.rate || 0), i = rate / 1200;
  if (p.kind === 'income') { const payout = r2s(amount * i); return { deposit: r2s(amount), maturity: r2s(amount), benefit: r2s(payout * months), monthly_payout: payout, units: months, per_unit: r2s(amount) }; }
  if (p.kind === 'certificate') { const fv = amount * Math.pow(1 + rate / 400, 4 * months / 12); return { deposit: r2s(amount), maturity: r2s(fv), benefit: r2s(fv - amount), units: 1, per_unit: r2s(amount) }; }
  const perMonth = p.unit === 'day' ? amount * 365 / 12 : amount, dep = perMonth * months;
  const fv = i === 0 ? dep : perMonth * ((Math.pow(1 + i, months) - 1) / i) * (1 + i);
  return { deposit: r2s(dep), maturity: r2s(fv), benefit: r2s(fv - dep), units: p.unit === 'day' ? Math.round(months * 365 / 12) : months, per_unit: r2s(amount) };
}
// Effective rate = tenure-slab base + senior-citizen + women + renewal extras (only when the plan defines them and the customer qualifies)
function planRateFor(p, months, cust, renewal) {
  const base0 = Math.max(0, +(p && p.rate) || 0); months = +months;
  let base = base0; if (p && Array.isArray(p.slabs) && p.slabs.length) { for (const sl of p.slabs.slice().sort((a, b) => a.from - b.from)) if (months >= sl.from) base = +sl.rate; }
  let senior = 0, women = 0, renewal_ = 0;
  if (cust && typeof cust === 'object') {
    const dob = new Date(String(cust.dob || '')), age = isNaN(dob) ? -1 : (Date.now() - dob.getTime()) / (365.25 * 864e5);
    if (+(p && p.senior_bonus) > 0 && age >= (+p.senior_age || 60)) senior = +p.senior_bonus;
    if (+(p && p.women_bonus) > 0 && /^(female|woman|f)$/i.test(String(cust.gender || '').trim())) women = +p.women_bonus;
  }
  if (renewal && +(p && p.renewal_bonus) > 0) renewal_ = +p.renewal_bonus;
  const r = x => Math.round(x * 100) / 100;
  return { base: r(base), senior: r(senior), women: r(women), renewal: r(renewal_), total: r(base + senior + women + renewal_) };
}
// A renewal bonus needs a matured deposit of the same plan, owned by this customer, not already renewed
function planRenewalCheck(custId, planId, prevId) {
  const prev = getRecord('plan_accts', String(prevId || ''));
  if (!prev || String(prev.customer_id) !== String(custId) || prev.plan_id !== planId || prev.status !== 'matured') return 'Renewal bonus needs a matured deposit of this same plan';
  if (allOf('plan_accts').some(x => String(x.renewal_of) === String(prev.id) && ['requested', 'active', 'matured', 'closed'].includes(x.status))) return 'This deposit has already been renewed';
  return '';
}
function planCheck(p, amount, months) {
  if (!p) return 'Unknown plan'; if (p.enabled === false) return 'This plan is not open right now';
  amount = Number(amount); months = Number(months);
  if (!Number.isFinite(amount) || amount < p.min || amount > p.max) return 'Amount must be between ₹' + p.min + ' and ₹' + p.max;
  if (!Number.isInteger(months) || months < p.min_months || months > p.max_months) return 'Tenure must be between ' + p.min_months + ' and ' + p.max_months + ' months';
  if (Array.isArray(p.tenure_list) && p.tenure_list.length && !p.tenure_list.includes(months)) return 'Choose one of the allowed tenures: ' + p.tenure_list.join(', ') + ' months';
  if (p.kind === 'recurring' && p.unit === 'day' && months % 1) return 'Invalid tenure';
  return '';
}
function planNorm(b) {
  b = b && typeof b === 'object' ? b : {};
  const id = String(b.id || ''); if (!/^[a-z][a-z0-9_]{1,23}$/.test(id) || ['constructor', 'prototype', 'hasownproperty', 'tostring', 'valueof'].includes(id.toLowerCase())) return { error: 'Plan code: 2–24 letters/numbers/underscore, starting with a letter (lower case)' };
  const name = clean(b.name, 60); if (name.length < 3) return { error: 'Give the plan a name' };
  if (!PLAN_KINDS.includes(b.kind)) return { error: 'Choose a plan type' };
  const num = (x, lo, hi) => { const n = Number(x); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
  const min = num(b.min, 1, 1e7), max = num(b.max, 1, 1e8), mn = num(b.min_months, 1, 240), mx = num(b.max_months, 1, 240), rate = num(b.rate, 0, 30);
  if (min === null || max === null || max < min) return { error: 'Minimum / maximum amount are not valid' };
  if (mn === null || mx === null || !Number.isInteger(mn) || !Number.isInteger(mx) || mx < mn) return { error: 'Tenure (1–240 months) is not valid' };
  if (rate === null) return { error: 'Interest rate must be 0–30% p.a.' };
  let tl = []; if (b.tenure_list != null && b.tenure_list !== '') { if (!Array.isArray(b.tenure_list) || b.tenure_list.length > 12) return { error: 'Tenure list is not valid' }; tl = b.tenure_list.map(Number); if (tl.some(x => !Number.isInteger(x) || x < mn || x > mx)) return { error: 'Every fixed tenure must be within the tenure range' }; tl = [...new Set(tl)].sort((a, c) => a - c); }
  let slabs = [];
  if (b.slabs != null && b.slabs !== '') {
    if (!Array.isArray(b.slabs) || b.slabs.length > 10) return { error: 'Rate slabs are not valid' };
    for (const sl of b.slabs) { const f = num(sl && sl.from, 1, 240), r = num(sl && sl.rate, 0, 30); if (f === null || r === null || !Number.isInteger(f)) return { error: 'Rate slabs: tenure 1–240 months and rate 0–30%' }; slabs.push({ from: f, rate: r }); }
    slabs.sort((a, b2) => a.from - b2.from);
  }
  const ex = k => { if (b[k] == null || b[k] === '') return 0; return num(b[k], 0, 5); };
  const sb = ex('senior_bonus'), wb = ex('women_bonus'), rb = ex('renewal_bonus');
  if (sb === null || wb === null || rb === null) return { error: 'Extra interest (senior / women / renewal) must be 0–5% p.a.' };
  const sage = b.senior_age == null || b.senior_age === '' ? 60 : num(b.senior_age, 50, 80); if (sage === null) return { error: 'Senior citizen age must be 50–80' };
  const unit = b.kind === 'recurring' && b.unit === 'day' ? 'day' : 'month';
  return { plan: { id, name, name_hi: clean(b.name_hi, 60), kind: b.kind, unit, min, max, min_months: mn, max_months: mx, tenure_list: tl, rate, slabs, senior_bonus: sb, women_bonus: wb, renewal_bonus: rb, senior_age: sage, bond: b.bond !== false, enabled: b.enabled !== false, icon: clean(b.icon, 4) || '💰', note: clean(b.note, 200), note_hi: clean(b.note_hi, 200) } };
}
const planCatalog = () => { const out = JSON.parse(JSON.stringify(PLAN_DEFAULTS)); for (const r of allOf('plan_catalog')) { if (r.removed) delete out[r.id]; else if (r.id) out[r.id] = r; } return out; };
const planGet = id => { const c = planCatalog(), k = String(id); return Object.prototype.hasOwnProperty.call(c, k) ? c[k] : null; };
const planCanManage = req => req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['manage_plans']));
const addMonthsS = (d, n) => { const x = new Date(d + 'T00:00:00Z'); const day = x.getUTCDate(); x.setUTCMonth(x.getUTCMonth() + n); if (x.getUTCDate() !== day) x.setUTCDate(0); return x.toISOString().slice(0, 10); };
const planAcctNo = id => 'PFS-PL-' + String(id).padStart(5, '0'), bondNo = id => 'PFS-BND-' + String(id).padStart(6, '0');

app.post('/api/staff/plan-catalog', auth, (req, res) => {
  if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can customise plans' });
  const b = req.body || {}, id = String(b.id || '');
  if (b.reset_all) { for (const r of allOf('plan_catalog')) delRecord('plan_catalog', r.id); audit(req, 'plan_reset_all', 'plan_catalog', '*'); return res.json({ success: true, catalog: planCatalog() }); }
  if (b.reset) { if (!Object.prototype.hasOwnProperty.call(PLAN_DEFAULTS, id)) return res.status(400).json({ success: false, message: 'Only the standard plans can be reset' }); delRecord('plan_catalog', id); audit(req, 'plan_reset', 'plan_catalog', id); return res.json({ success: true, plan: planGet(id) }); }
  if (b.remove) {
    if (Object.prototype.hasOwnProperty.call(PLAN_DEFAULTS, id)) return res.status(400).json({ success: false, message: 'Standard plans cannot be deleted — switch them off instead' });
    if (allOf('plan_accts').some(a => a.plan_id === id && ['requested', 'active'].includes(a.status))) return res.status(409).json({ success: false, message: 'This plan has running accounts — switch it off instead' });
    delRecord('plan_catalog', id); audit(req, 'plan_remove', 'plan_catalog', id); return res.json({ success: true });
  }
  const n = planNorm(b); if (n.error) return res.status(400).json({ success: false, message: n.error });
  const cur = planCatalog()[n.plan.id], prevVer = (cur && cur.version) || 0;
  const rec = Object.assign({}, n.plan, { version: prevVer + 1, updated_at: new Date().toISOString(), updated_by: String(req.auth.name || req.auth.role || 'Admin') });
  putRecord('plan_catalog', rec.id, rec); audit(req, 'plan_save', 'plan_catalog', rec.id);
  res.json({ success: true, plan: rec });
});

function planRequest(req, res, who) {   // who: 'customer' | 'staff'
  const b = req.body || {}, plan = planGet(b.plan_id); const amount = Number(b.amount), months = Number(b.months);
  const bad = planCheck(plan, amount, months); if (bad) return res.status(400).json({ success: false, message: bad });
  const custId = who === 'customer' ? req.auth.ref : b.customer_id; const cust = getRecord('customers', String(custId || ''));
  if (!cust) return res.status(404).json({ success: false, message: 'Customer not found' });
  if (b.consent !== true) return res.status(400).json({ success: false, message: 'Please accept the scheme terms' });
  const nominee = clean(b.nominee_name, 60), rel = clean(b.nominee_relation, 30);
  if (nominee.length < 2 || rel.length < 2) return res.status(400).json({ success: false, message: 'Nominee name and relation are required' });
  const open = allOf('plan_accts').filter(a => String(a.customer_id) === String(cust.id) && ['requested', 'active'].includes(a.status));
  if (open.filter(a => a.status === 'requested').length >= 3) return res.status(409).json({ success: false, message: 'You already have 3 plan requests waiting — they must be confirmed first' });
  if (open.length >= 20) return res.status(409).json({ success: false, message: 'Maximum number of open plans reached' });
  let renewalOf = null; if (b.renewal_of != null && b.renewal_of !== '' || b.renewal === true) { const why = planRenewalCheck(cust.id, plan.id, b.renewal_of); if (why) return res.status(400).json({ success: false, message: why }); renewalOf = String(b.renewal_of); }
  const rt = planRateFor(plan, months, cust, !!renewalOf), c = planCalc({ ...plan, rate: rt.total }, amount, months), id = nextId('plan_accts');
  const rec = { id, acct_no: planAcctNo(id), plan_id: plan.id, plan_name: plan.name, plan_name_hi: plan.name_hi || '', kind: plan.kind, unit: plan.unit, customer_id: cust.id, customer_name: cust.name, customer_mobile: cust.mobile || '',
    amount, months, rate: rt.total, rate_base: rt.base, rate_senior: rt.senior, rate_women: rt.women, rate_renewal: rt.renewal, renewal_of: renewalOf, deposit_total: c.deposit, maturity_value: c.maturity, total_benefit: c.benefit, monthly_payout: c.monthly_payout || 0, units_total: c.units, units_paid: 0, total_deposited: 0,
    nominee_name: nominee, nominee_relation: rel, status: 'requested', requested_at: new Date().toISOString(), requested_by: who, bond_wanted: plan.bond !== false };
  putRecord('plan_accts', id, rec); audit(req, 'plan_request', 'plan_accts', id);
  notifyStaff('manage_plans', '📈 New savings plan request', cust.name + ' — ' + plan.name + ' ' + inr(amount), 'system');
  if (who === 'staff') notify('customer', cust.id, '📈 Plan request received', 'Your ' + plan.name + ' request is recorded. Deposit the first amount with PFS to start it.', 'system');
  res.json({ success: true, record: rec, calc: c });
}
app.post('/api/customer/plan-open', auth, (req, res) => { if (!needCustomer(req, res) || !needStepup(req, res)) return; planRequest(req, res, 'customer'); });
app.post('/api/staff/plan-open', auth, (req, res) => { if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage plans' }); planRequest(req, res, 'staff'); });


// Edit a plan account: amount/tenure/nominee while it is still waiting; only the nominee after it started (the bond is sealed)
function planEditAcct(req, res, who) {
  const b = req.body || {}, a = getRecord('plan_accts', String(b.id || ''));
  if (!a || (who === 'customer' && String(a.customer_id) !== String(req.auth.ref))) return res.status(404).json({ success: false, message: 'Plan account not found' });
  if (!['requested', 'active'].includes(a.status)) return res.status(409).json({ success: false, message: 'This plan is closed and cannot be edited' });
  const nominee = b.nominee_name === undefined ? a.nominee_name : clean(b.nominee_name, 60), rel = b.nominee_relation === undefined ? a.nominee_relation : clean(b.nominee_relation, 30);
  if (nominee.length < 2 || rel.length < 2) return res.status(400).json({ success: false, message: 'Nominee name and relation are required' });
  if (a.status === 'active') {
    if (who === 'customer') return res.status(403).json({ success: false, message: 'Ask PFS staff to change the nominee of a running plan' });
    if ((b.amount !== undefined && Number(b.amount) !== a.amount) || (b.months !== undefined && Number(b.months) !== a.months)) return res.status(409).json({ success: false, message: 'Amount and tenure cannot change after the plan has started' });
    a.nominee_name = nominee; a.nominee_relation = rel; a.nominee_changed_at = new Date().toISOString();
  } else {
    const plan = planGet(a.plan_id), amount = b.amount === undefined ? a.amount : Number(b.amount), months = b.months === undefined ? a.months : Number(b.months);
    const bad = planCheck(plan, amount, months); if (bad) return res.status(400).json({ success: false, message: bad });
    const rt = planRateFor(plan, months, getRecord('customers', String(a.customer_id)), !!a.renewal_of), c = planCalc({ ...plan, rate: rt.total }, amount, months);
    Object.assign(a, { amount, months, rate: rt.total, rate_base: rt.base, rate_senior: rt.senior, rate_women: rt.women, rate_renewal: rt.renewal, deposit_total: c.deposit, maturity_value: c.maturity, total_benefit: c.benefit, monthly_payout: c.monthly_payout || 0, units_total: c.units, nominee_name: nominee, nominee_relation: rel, edited_at: new Date().toISOString() });
  }
  putRecord('plan_accts', a.id, a); audit(req, 'plan_edit', 'plan_accts', a.id);
  res.json({ success: true, record: a });
}
app.post('/api/customer/plan-edit', auth, (req, res) => { if (!needCustomer(req, res) || !needStepup(req, res)) return; planEditAcct(req, res, 'customer'); });
app.post('/api/staff/plan-edit', auth, (req, res) => { if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage plans' }); planEditAcct(req, res, 'staff'); });


app.post('/api/staff/plan-activate', auth, (req, res) => {
  if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage plans' });
  const a = getRecord('plan_accts', String(req.body?.id || '')); if (!a) return res.status(404).json({ success: false, message: 'Plan account not found' });
  if (a.status !== 'requested') return res.status(409).json({ success: false, message: 'Only a waiting request can be started' });
  const first = a.amount, received = Number(req.body?.received);
  if (!Number.isFinite(received) || received < first - 0.001 || received > a.deposit_total + 0.01) return res.status(400).json({ success: false, message: 'Enter the amount actually received (at least ₹' + first + ')' });
  if (a.kind === 'recurring' && Math.abs(received / a.amount - Math.round(received / a.amount)) > 0.001) return res.status(400).json({ success: false, message: 'Amount must be a whole number of instalments of ₹' + a.amount });
  const ref = clean(req.body?.ref, 40); if (!ref) return res.status(400).json({ success: false, message: 'Enter the receipt / payment reference' });
  const plan = planGet(a.plan_id) || {}; const today = todayS();
  const units = a.kind === 'recurring' ? Math.max(1, Math.min(a.units_total, Math.round(received / a.amount))) : 1;
  Object.assign(a, { status: 'active', start_date: today, maturity_date: addMonthsS(today, a.months), total_deposited: r2s(a.kind === 'recurring' ? units * a.amount : received), units_paid: a.kind === 'recurring' ? units : 1, first_ref: ref, activated_by: String(req.auth.name || req.auth.role), activated_at: new Date().toISOString() });
  if (a.bond_wanted && plan.bond !== false) {
    const bn = bondNo(a.id); a.bond_no = bn; a.bond_issued_at = new Date().toISOString();
    a.bond_hash = crypto.createHash('sha256').update(JSON.stringify([bn, a.customer_id, a.plan_id, a.amount, a.months, a.rate, a.start_date, a.maturity_date, a.maturity_value])).digest('hex');
  }
  putRecord('plan_accts', a.id, a); audit(req, 'plan_activate', 'plan_accts', a.id);
  notify('customer', a.customer_id, '📜 Your plan is active', a.plan_name + ' started' + (a.bond_no ? ' — Bond Certificate ' + a.bond_no + ' is ready in My Plans.' : '.'), 'system');
  res.json({ success: true, record: a });
});

app.post('/api/staff/plan-deposit', auth, (req, res) => {
  if (!(planCanManage(req) || (req.auth.kind === 'staff' && hasAny(req.auth.role, ['create_collections'])))) return res.status(403).json({ success: false, message: 'You do not have access to manage plans' });
  const a = getRecord('plan_accts', String(req.body?.id || '')); if (!a) return res.status(404).json({ success: false, message: 'Plan account not found' });
  if (a.status !== 'active' || a.kind !== 'recurring') return res.status(409).json({ success: false, message: 'Deposits can be added only to an active recurring plan' });
  const n = Number(req.body?.units == null || req.body.units === '' ? 1 : req.body.units);
  if (!Number.isInteger(n) || n < 1 || n > a.units_total - a.units_paid) return res.status(400).json({ success: false, message: 'Instalments left: ' + (a.units_total - a.units_paid) });
  const ref = clean(req.body?.ref, 40); if (!ref) return res.status(400).json({ success: false, message: 'Enter the receipt reference' });
  a.units_paid += n; a.total_deposited = r2s(a.units_paid * a.amount); a.last_deposit_at = new Date().toISOString(); a.last_ref = ref;
  putRecord('plan_accts', a.id, a); audit(req, 'plan_deposit', 'plan_accts', a.id);
  notify('customer', a.customer_id, '💰 Deposit received', inr(n * a.amount) + ' received in ' + a.plan_name + ' (' + a.acct_no + ').', 'system');
  res.json({ success: true, record: a });
});

app.post('/api/staff/plan-close', auth, (req, res) => {
  if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage plans' });
  const a = getRecord('plan_accts', String(req.body?.id || '')); if (!a) return res.status(404).json({ success: false, message: 'Plan account not found' });
  const today = todayS();
  if (a.status === 'requested') { if (!req.body?.cancel) return res.status(409).json({ success: false, message: 'This request has not started — cancel it instead' }); a.status = 'cancelled'; a.closed_at = new Date().toISOString(); putRecord('plan_accts', a.id, a); audit(req, 'plan_cancel', 'plan_accts', a.id); return res.json({ success: true, record: a }); }
  if (a.status !== 'active') return res.status(409).json({ success: false, message: 'This plan is already closed' });
  const matured = today >= a.maturity_date, premature = !matured;
  if (premature) { const why = clean(req.body?.reason, 160); if (req.auth.role !== 'ceo' || why.length < 5) return res.status(403).json({ success: false, message: 'Before maturity only the CEO can close a plan, with a written reason' }); a.close_reason = why; }
  let payout;
  const frac = a.kind === 'recurring' ? a.units_paid / a.units_total : 1;
  if (matured) payout = a.kind === 'recurring' ? a.maturity_value * frac : a.maturity_value;   // income plan pays the monthly income separately; certificate/recurring pay the maturity value
  else {
    const elapsedM = Math.max(0, Math.floor((new Date(today) - new Date(a.start_date)) / (30.4375 * 864e5))), pr = Math.max(0, (+a.rate || 0) - 2);
    payout = a.total_deposited + (a.kind === 'recurring' ? a.total_deposited * pr / 100 * (elapsedM / 12) / 2 : a.total_deposited * pr / 100 * (elapsedM / 12));
  }
  a.payout_amount = r2s(payout); a.status = matured ? 'matured' : 'closed'; a.closed_at = new Date().toISOString(); a.closed_by = String(req.auth.name || req.auth.role); a.premature = premature;
  putRecord('plan_accts', a.id, a); audit(req, 'plan_close', 'plan_accts', a.id);
  notify('customer', a.customer_id, premature ? '🔒 Plan closed' : '🎉 Plan matured', a.plan_name + ' (' + a.acct_no + '): ' + inr(a.payout_amount) + ' payable to you.', 'system');
  res.json({ success: true, record: a });
});


// ─────────────────────────── Plan documents (editable templates) + Complaint Register ───────────────────────────
const PLAN_DOC_DEFAULTS = JSON.parse(fs.readFileSync(path.join(__dirname, 'plan-doc-defaults.json'), 'utf8'));
const DOC_VARS = new Set(['company', 'address', 'phone', 'web', 'customer_name', 'customer_mobile', 'customer_address', 'customer_code', 'plan_name', 'acct_no', 'amount', 'tenure', 'rate', 'maturity_value', 'deposit_total', 'nominee', 'date', 'grievance_days', 'grievance_officer', 'party_name', 'party_role', 'party_city', 'commission']);
function planDocNorm(b) {
  b = b && typeof b === 'object' ? b : {};
  const id = String(b.id || ''); if (!Object.prototype.hasOwnProperty.call(PLAN_DOC_DEFAULTS, id)) return { error: 'Unknown document' };
  const title = clean(b.title, 90), intro = clean(b.intro, 1500); if (title.length < 3 || intro.length < 3) return { error: 'Title and opening paragraph are required' };
  if (!Array.isArray(b.clauses) || b.clauses.length < 1 || b.clauses.length > 40) return { error: 'Keep between 1 and 40 clauses' };
  const clauses = b.clauses.map(c => ({ t: clean(c && c.t, 80), b: clean(c && c.b, 2000) })); if (clauses.some(c => !c.t || !c.b)) return { error: 'Every clause needs a heading and text' };
  const bad = new Set(); [intro, ...clauses.map(c => c.b), ...clauses.map(c => c.t)].forEach(x => String(x).replace(/\{\{(\w+)\}\}/g, (m, k) => { if (!DOC_VARS.has(k)) bad.add(m); }));
  if (bad.size) return { error: 'Unknown placeholder: ' + [...bad].join(', ') };
  const d = PLAN_DOC_DEFAULTS[id];
  return { doc: { id, title, intro, clauses, sign: d.sign, form: d.form } };
}
const planDocs = () => { const out = JSON.parse(JSON.stringify(PLAN_DOC_DEFAULTS)); for (const r of allOf('plan_doc_tpl')) if (r && Object.prototype.hasOwnProperty.call(out, r.id) && Array.isArray(r.clauses)) out[r.id] = Object.assign({}, out[r.id], r); return out; };
app.post('/api/staff/plan-doc-template', auth, (req, res) => {
  if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can change documents' });
  const b = req.body || {}, id = String(b.id || ''); if (!Object.prototype.hasOwnProperty.call(PLAN_DOC_DEFAULTS, id)) return res.status(400).json({ success: false, message: 'Unknown document' });
  if (b.reset) { delRecord('plan_doc_tpl', id); audit(req, 'plan_doc_reset', 'plan_doc_tpl', id); return res.json({ success: true, doc: PLAN_DOC_DEFAULTS[id] }); }
  const n = planDocNorm(b); if (n.error) return res.status(400).json({ success: false, message: n.error });
  const cur = getRecord('plan_doc_tpl', id), rec = Object.assign({}, n.doc, { version: ((cur && cur.version) || 0) + 1, updated_at: new Date().toISOString(), updated_by: String(req.auth.name || req.auth.role || 'Admin') });
  putRecord('plan_doc_tpl', id, rec); audit(req, 'plan_doc_save', 'plan_doc_tpl', id); res.json({ success: true, doc: rec });
});

const CMP_CATS = ['Plan / account', 'Deposit or receipt', 'Maturity or payout', 'Staff or agent conduct', 'Privacy / data', 'App or technical', 'Other'];
const CMP_FLOW = { open: ['in_progress', 'resolved', 'rejected'], in_progress: ['resolved', 'rejected'] };
const cmpNo = id => 'PFS-CMP-' + String(id).padStart(5, '0');
function cmpCreate(req, res, who) {
  const b = req.body || {}, cust = getRecord('customers', String(who === 'customer' ? req.auth.ref : b.customer_id || ''));
  if (!cust) return res.status(404).json({ success: false, message: 'Customer not found' });
  const subject = clean(b.subject, 100), details = clean(b.details, 1500), cat = CMP_CATS.includes(b.category) ? b.category : 'Other';
  if (subject.length < 4 || details.length < 10) return res.status(400).json({ success: false, message: 'Write a short subject and at least 10 characters of detail' });
  if (allOf('complaints').filter(c => String(c.customer_id) === String(cust.id) && ['open', 'in_progress'].includes(c.status)).length >= 5) return res.status(409).json({ success: false, message: 'You already have 5 open complaints — they must be resolved first' });
  const id = nextId('complaints'), days = Math.max(1, Math.min(90, polv('grievance_days', 30))), now = new Date();
  const rec = { id, complaint_no: cmpNo(id), customer_id: cust.id, customer_name: cust.name, customer_mobile: cust.mobile || '', category: cat, acct_no: clean(b.acct_no, 30), subject, details, channel: who === 'customer' ? 'App' : clean(b.channel, 20) || 'Branch',
    status: 'open', created_at: now.toISOString(), due_date: new Date(now.getTime() + days * 864e5).toISOString().slice(0, 10), resolution: '', timeline: [{ at: now.toISOString(), by: who === 'customer' ? 'Customer' : String(req.auth.name || req.auth.role), status: 'open', note: 'Complaint registered' }] };
  putRecord('complaints', id, rec); audit(req, 'complaint_new', 'complaints', id);
  notify('customer', cust.id, '📝 Complaint registered', 'Your complaint ' + rec.complaint_no + ' is registered. We will resolve it by ' + rec.due_date + '.', 'system');
  notifyStaff('manage_plans', '📝 New customer complaint', cust.name + ' — ' + subject, 'system');
  res.json({ success: true, record: rec });
}
app.post('/api/customer/complaint', auth, (req, res) => { if (!needCustomer(req, res)) return; cmpCreate(req, res, 'customer'); });
app.post('/api/staff/complaint-add', auth, (req, res) => { if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage complaints' }); cmpCreate(req, res, 'staff'); });
app.post('/api/staff/complaint-update', auth, (req, res) => {
  if (!planCanManage(req)) return res.status(403).json({ success: false, message: 'You do not have access to manage complaints' });
  const c = getRecord('complaints', String(req.body?.id || '')); if (!c) return res.status(404).json({ success: false, message: 'Complaint not found' });
  const to = String(req.body?.status || ''), note = clean(req.body?.note, 500);
  if (!(CMP_FLOW[c.status] || []).includes(to)) return res.status(409).json({ success: false, message: 'A ' + c.status.replace('_', ' ') + ' complaint cannot move to "' + to + '"' });
  if (['resolved', 'rejected'].includes(to)) { if (note.length < 5) return res.status(400).json({ success: false, message: 'Write the resolution / reason (at least 5 characters)' }); c.resolution = note; c.closed_at = new Date().toISOString(); c.within_tat = todayS() <= c.due_date; }
  c.status = to; c.timeline = (c.timeline || []).concat([{ at: new Date().toISOString(), by: String(req.auth.name || req.auth.role), status: to, note }]).slice(-50);
  putRecord('complaints', c.id, c); audit(req, 'complaint_update', 'complaints', c.id);
  notify('customer', c.customer_id, '📝 Complaint update', c.complaint_no + ' is now ' + to.replace('_', ' ') + (note ? ': ' + note.slice(0, 120) : '.'), 'system');
  res.json({ success: true, record: c });
});


// ───────── SMS admin + customer preference ─────────
app.get('/api/staff/sms-log', auth, (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can view the SMS log' });
  const rows = db.prepare('SELECT id, mobile, text, kind, status, tries, created_at, sent_at, error FROM sms_queue ORDER BY id DESC LIMIT 200').all().map(r => ({ ...r, mobile: maskMobile(r.mobile) }));
  res.json({ success: true, configured: !!process.env.SMS_URL, rows });
});
app.post('/api/staff/sms-flush', auth, async (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can do this' });
  res.json({ success: true, processed: await smsFlush(!!req.body?.force) });
});
app.post('/api/staff/sms-test', auth, async (req, res) => {
  if (req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can do this' });
  const m = String(req.body?.mobile || '').replace(/\D/g, '').slice(-10);
  if (!/^[6-9]\d{9}$/.test(m)) return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number' });
  smsEnqueue(m, smsText('Test message', 'SMS alerts are working. ' + new Date().toLocaleTimeString('en-IN')), 'test'); await smsFlush(true);
  audit(req, 'sms-test', 'sms_queue', 0); res.json({ success: true, configured: !!process.env.SMS_URL });
});
app.post('/api/customer/sms-pref', auth, (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  const c = getRecord('customers', String(req.auth.ref)); if (!c) return res.status(404).json({ success: false, message: 'Not found' });
  c.sms_opt = req.body?.enabled !== false; putRecord('customers', c.id, c); res.json({ success: true, enabled: c.sms_opt });
});

// ───────── Online payments (Razorpay-style): order → checkout → signed webhook → verified pending payment → staff confirm ─────────
const gwEnabled = () => !!process.env.GATEWAY_WEBHOOK_SECRET;
app.get('/api/pay/gateway/config', auth, (req, res) => res.json({ success: true, enabled: gwEnabled(), checkout: !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET), key_id: process.env.RAZORPAY_KEY_ID || null }));
app.post('/api/customer/gateway-order', auth, async (req, res) => {
  if (req.auth.kind !== 'customer') return res.status(403).json({ success: false, message: 'Customers only' });
  const { ref_type, ref_id } = req.body || {}, amount = Math.round((+req.body?.amount || 0) * 100) / 100;
  if (!(amount >= 1) || amount > 1000000) return res.status(400).json({ success: false, message: 'Invalid amount' });
  const cid = String(req.auth.ref), target = ref_type === 'loan' ? getRecord('loans', ref_id) : ref_type === 'rd' ? getRecord('rds', ref_id) : null;
  if (!target || String(target.customer_id) !== cid) return res.status(404).json({ success: false, message: 'Account not found' });
  if (!gwEnabled() || !process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) return res.status(503).json({ success: false, message: 'Online payment is not switched on yet' });
  try {
    const r = await fetch((process.env.GATEWAY_API_BASE || 'https://api.razorpay.com') + '/v1/orders', { method: 'POST', signal: AbortSignal.timeout(8000),
      headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from(process.env.RAZORPAY_KEY_ID + ':' + process.env.RAZORPAY_KEY_SECRET).toString('base64') },
      body: JSON.stringify({ amount: Math.round(amount * 100), currency: 'INR', receipt: ('pfs-' + ref_type + target.id + '-' + Date.now()).slice(0, 40), notes: { customer_id: cid, ref_type, ref_id: String(target.id) } }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.id) return res.status(502).json({ success: false, message: 'The payment gateway could not create the order' });
    audit(req, 'gateway-order', ref_type, target.id);
    res.json({ success: true, order_id: j.id, amount: j.amount, currency: j.currency || 'INR', key_id: process.env.RAZORPAY_KEY_ID });
  } catch { res.status(502).json({ success: false, message: 'The payment gateway did not respond' }); }
});
app.post('/api/pay/webhook', (req, res) => {
  if (!gwEnabled()) return res.status(503).json({ success: false, message: 'Not enabled' });
  if (!gatewaySigOk(req.rawBody, req.get('x-razorpay-signature'), process.env.GATEWAY_WEBHOOK_SECRET)) return res.status(401).json({ success: false, message: 'Bad signature' });
  const b = req.body || {};
  if (b.event !== 'payment.captured') return res.json({ success: true, ignored: true });
  const e = b.payload?.payment?.entity || {}, pid = String(e.id || ''), notes = e.notes && typeof e.notes === 'object' ? e.notes : {};
  const bad = r => res.json({ success: true, ignored: true, reason: r });
  if (!/^[A-Za-z0-9_]{4,40}$/.test(pid)) return bad('payment id');
  if (e.currency !== 'INR' || e.status !== 'captured' || !Number.isInteger(e.amount) || e.amount < 100 || e.amount > 1e9) return bad('amount/status');
  const amount = e.amount / 100, cid = String(notes.customer_id || ''), rt = notes.ref_type === 'loan' ? 'loan' : notes.ref_type === 'rd' ? 'rd' : '';
  const cust = getRecord('customers', cid), target = rt === 'loan' ? getRecord('loans', String(notes.ref_id || '')) : rt === 'rd' ? getRecord('rds', String(notes.ref_id || '')) : null;
  if (!cust || !target || String(target.customer_id) !== cid) { notifyStaff('create_collections', '⚠️ Unmatched online payment', 'Gateway payment ' + pid + ' of ' + inr(amount) + ' could not be matched to an account. Check the gateway dashboard.', 'collection'); return bad('no matching account'); }
  if (db.prepare('INSERT OR IGNORE INTO gateway_events(pid, at) VALUES(?,?)').run(pid, Date.now()).changes === 0) return res.json({ success: true, duplicate: true });
  const rows = allOf('collections'), same = rows.find(c => c.status === 'pending' && String(c.customer_id) === cid && c.ref_type === rt && String(c.ref_id) === String(target.id) && Math.abs(+c.amount - amount) < 0.005 && !c.gateway_payment_id);
  if (same) { Object.assign(same, { gateway_payment_id: pid, gateway_verified: true, upi_ref: same.upi_ref || pid }); putRecord('collections', same.id, same); }
  else {
    const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='collections'").get().m || 0) + 1;
    putRecord('collections', id, { id, collection_code: 'PFS-COL-' + String(id).padStart(4, '0'), customer_id: cust.id, customer_name: cust.name, amount, payment_mode: 'upi', collection_date: new Date().toISOString().slice(0, 10),
      ref_type: rt, ref_id: target.id, ref_label: rt === 'loan' ? 'Loan ' + target.loan_code : 'RD ' + target.rd_code, agent_name: 'Self (Online)', upi_ref: pid, gateway_payment_id: pid, gateway_verified: true, status: 'pending' });
  }
  notifyStaff('create_collections', '💳 Online payment received', inr(amount) + ' paid online by ' + cust.name + ' — gateway verified, please confirm.', 'collection');
  res.json({ success: true });
});


// ───────── Master data (CEO-managed pick-lists) ─────────
const MASTER_DEFAULTS = JSON.parse(fs.readFileSync(path.join(__dirname, 'masters-defaults.json'), 'utf8'));
const mastersNow = () => { const out = {}; for (const k of Object.keys(MASTER_DEFAULTS)) { const r = getRecord('masters', k); out[k] = r && Array.isArray(r.items) ? { items: r.items, custom: true } : { items: MASTER_DEFAULTS[k], custom: false }; } return out; };
app.get('/api/staff/masters', auth, (req, res) => {
  if (req.auth.kind !== 'staff') return res.status(403).json({ success: false, message: 'Staff only' });
  res.json({ success: true, masters: mastersNow() });
});
app.post('/api/staff/master', auth, (req, res) => {
  if (req.auth.kind !== 'staff' || req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can change master data' });
  const key = String(req.body?.key || ''); if (!Object.prototype.hasOwnProperty.call(MASTER_DEFAULTS, key)) return res.status(400).json({ success: false, message: 'Unknown list' });
  if (req.body?.reset) { delRecord('masters', key); audit(req, 'master_reset', 'masters', key); return res.json({ success: true, masters: mastersNow() }); }
  const raw = req.body?.items; if (!Array.isArray(raw) || raw.length < 1 || raw.length > 60) return res.status(400).json({ success: false, message: 'A list needs 1 to 60 items' });
  const seen = new Set(), items = [];
  for (const it of raw) { if (typeof it !== 'string') return res.status(400).json({ success: false, message: 'Every item must be text' }); const v = cleanStr(it.trim().replace(/\s+/g, ' ')); if (v.length < 1 || v.length > 40) return res.status(400).json({ success: false, message: 'Each item must be 1–40 characters' }); if (!seen.has(v.toLowerCase())) { seen.add(v.toLowerCase()); items.push(v); } }
  putRecord('masters', key, { id: key, items }); audit(req, 'master_set', 'masters', key);
  res.json({ success: true, masters: mastersNow() });
});

// ───────── Savings accounts (demand deposit): server-authoritative balance + running-balance statement ─────────
const SAV = { min_open: 500, min_bal: 500, rate: 3.5, staff_limit: 20000, day_limit: 50000, max_txn: 1000000 };
const savCan = req => req.auth.kind === 'staff' && (req.auth.role === 'ceo' || hasAny(req.auth.role, ['create_collections', 'manage_plans']));
const savAcctNo = id => 'PFS-SA-' + String(id).padStart(6, '0');
function savTxn(a, type, amount, ref, by, note) {
  a.balance = r2s(a.balance + (['withdraw', 'close'].includes(type) ? -amount : amount));
  const id = nextId('sav_txns'); putRecord('sav_txns', id, { id, acct_id: a.id, customer_id: a.customer_id, type, amount: r2s(amount), balance_after: a.balance, ref: ref || '', date: new Date().toISOString().slice(0, 10), at: new Date().toISOString(), by: String(by || ''), note: note || '' });
  putRecord('sav_accts', a.id, a);
}
const savAmt = v => (typeof v === 'number' || (typeof v === 'string' && /^\d+(\.\d{1,2})?$/.test(v.trim()))) && Number.isFinite(+v) ? r2s(+v) : NaN;
const savGet = (req, res) => { const a = getRecord('sav_accts', String(req.body?.id || '')); if (!a) { res.status(404).json({ success: false, message: 'Savings account not found' }); return null; } return a; };
app.post('/api/staff/sav-open', auth, (req, res) => {
  if (!savCan(req)) return res.status(403).json({ success: false, message: 'You do not have access to savings accounts' });
  const cust = getRecord('customers', String(req.body?.customer_id || '')); if (!cust || cust.status === 'deleted') return res.status(404).json({ success: false, message: 'Customer not found' });
  const opening = savAmt(req.body?.opening), ref = clean(req.body?.ref, 40);
  if (!(opening >= SAV.min_open) || opening > SAV.max_txn) return res.status(400).json({ success: false, message: 'Opening deposit must be ₹' + SAV.min_open + ' to ₹' + SAV.max_txn });
  if (!ref) return res.status(400).json({ success: false, message: 'Enter the receipt / payment reference' });
  if (allOf('sav_accts').some(a => String(a.customer_id) === String(cust.id) && a.status === 'active')) return res.status(409).json({ success: false, message: 'This customer already has a savings account' });
  const id = nextId('sav_accts'), a = { id, acct_no: savAcctNo(id), customer_id: cust.id, customer_name: cust.name, balance: 0, rate: +polv('sav_rate', SAV.rate) || SAV.rate, status: 'active', opened_at: new Date().toISOString().slice(0, 10), nominee_name: clean(req.body?.nominee_name, 60), last_interest_ym: '' };
  savTxn(a, 'open', opening, ref, req.auth.name || req.auth.role); audit(req, 'sav_open', 'sav_accts', id);
  notify('customer', cust.id, '🏦 Savings account opened', a.acct_no + ' opened with ' + inr(opening) + '.', 'system');
  res.json({ success: true, record: a });
});
app.post('/api/staff/sav-deposit', auth, (req, res) => {
  if (!savCan(req)) return res.status(403).json({ success: false, message: 'You do not have access to savings accounts' });
  const a = savGet(req, res); if (!a) return; if (a.status !== 'active') return res.status(409).json({ success: false, message: 'This account is closed' });
  const amt = savAmt(req.body?.amount), ref = clean(req.body?.ref, 40);
  if (!(amt >= 1) || amt > SAV.max_txn) return res.status(400).json({ success: false, message: 'Amount must be ₹1 to ₹' + SAV.max_txn });
  if (!ref) return res.status(400).json({ success: false, message: 'Enter the receipt / payment reference' });
  savTxn(a, 'deposit', amt, ref, req.auth.name || req.auth.role); audit(req, 'sav_deposit', 'sav_accts', a.id);
  notify('customer', a.customer_id, '💰 Deposit received', inr(amt) + ' credited to ' + a.acct_no + '. Balance ' + inr(a.balance) + '.', 'system');
  res.json({ success: true, record: a });
});
app.post('/api/staff/sav-withdraw', auth, (req, res) => {
  if (!savCan(req)) return res.status(403).json({ success: false, message: 'You do not have access to savings accounts' });
  const a = savGet(req, res); if (!a) return; if (a.status !== 'active') return res.status(409).json({ success: false, message: 'This account is closed' });
  const amt = savAmt(req.body?.amount), ref = clean(req.body?.ref, 40);
  if (!(amt >= 1) || amt > SAV.max_txn) return res.status(400).json({ success: false, message: 'Amount must be ₹1 to ₹' + SAV.max_txn });
  if (!ref) return res.status(400).json({ success: false, message: 'Enter the voucher / payment reference' });
  if (amt > SAV.staff_limit && req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Withdrawals above ₹' + SAV.staff_limit + ' need the CEO' });
  if (r2s(a.balance - amt) < SAV.min_bal) return res.status(409).json({ success: false, message: 'Balance cannot go below the minimum of ₹' + SAV.min_bal + ' (available ₹' + Math.max(0, r2s(a.balance - SAV.min_bal)) + ')' });
  const today = new Date().toISOString().slice(0, 10), done = allOf('sav_txns').filter(t => t.acct_id === a.id && t.type === 'withdraw' && t.date === today).reduce((x, t) => x + t.amount, 0);
  if (r2s(done + amt) > SAV.day_limit) return res.status(409).json({ success: false, message: 'Daily withdrawal limit of ₹' + SAV.day_limit + ' reached' });
  savTxn(a, 'withdraw', amt, ref, req.auth.name || req.auth.role); audit(req, 'sav_withdraw', 'sav_accts', a.id);
  notify('customer', a.customer_id, '💸 Withdrawal', inr(amt) + ' withdrawn from ' + a.acct_no + '. Balance ' + inr(a.balance) + '.', 'system');
  res.json({ success: true, record: a });
});
app.post('/api/staff/sav-close', auth, (req, res) => {
  if (req.auth.kind !== 'staff' || req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can close a savings account' });
  const a = savGet(req, res); if (!a) return; if (a.status !== 'active') return res.status(409).json({ success: false, message: 'Already closed' });
  const why = clean(req.body?.reason, 120); if (why.length < 5) return res.status(400).json({ success: false, message: 'Write the reason for closing' });
  const pay = a.balance; savTxn(a, 'close', pay, 'CLOSE', req.auth.name || 'CEO', why); a.status = 'closed'; a.closed_at = new Date().toISOString(); putRecord('sav_accts', a.id, a); audit(req, 'sav_close', 'sav_accts', a.id);
  notify('customer', a.customer_id, '🔒 Savings account closed', a.acct_no + ' closed. ' + inr(pay) + ' paid to you.', 'system');
  res.json({ success: true, record: a, payout: pay });
});
app.post('/api/staff/sav-interest-run', auth, (req, res) => {
  if (req.auth.kind !== 'staff' || req.auth.role !== 'ceo') return res.status(403).json({ success: false, message: 'Only the CEO can credit interest' });
  const nowYm = new Date().toISOString().slice(0, 7), ym = String(req.body?.month || nowYm);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(ym) || ym > nowYm) return res.status(400).json({ success: false, message: 'Choose a month up to the current month (YYYY-MM)' });
  let credited = 0, total = 0;
  for (const a of allOf('sav_accts')) {
    if (a.status !== 'active' || a.last_interest_ym >= ym) continue;
    const i = r2s(a.balance * (+a.rate || SAV.rate) / 1200); a.last_interest_ym = ym; if (i > 0) { savTxn(a, 'interest', i, 'INT-' + ym, 'system', 'Interest for ' + ym); credited++; total += i; } else putRecord('sav_accts', a.id, a);
  }
  audit(req, 'sav_interest', 'sav_accts', ym); res.json({ success: true, month: ym, credited, total: r2s(total) });
});


// ───────── Agreement library: client / associate / employee-agent / franchise documents (issued, signed on paper or e-sign, voided) ─────────
const AGR_LIB = ['client', 'associate', 'employee', 'franchise'];
const agrValidDate = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(new Date(v)) && new Date(v).toISOString().slice(0, 10) === v;
app.post('/api/staff/agreement-doc', auth, (req, res) => {
  if (!agrCanEdit(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can issue agreements' });
  const b = req.body || {}, tpl = typeof b.tpl === 'string' ? b.tpl : ''; if (!AGR_LIB.includes(tpl)) return res.status(400).json({ success: false, message: 'Unknown agreement type' });
  const str = (v, max) => (typeof v === 'string' ? v.trim() : ''), tooLong = (v, max) => typeof v === 'string' && v.trim().length > max;
  for (const [k, max] of [['party_name', 80], ['address', 160], ['city', 40], ['party_id', 30], ['role_title', 60], ['territory', 80], ['fee_text', 100], ['amount_text', 40]]) if (b[k] != null && (typeof b[k] !== 'string' || tooLong(b[k], max))) return res.status(400).json({ success: false, message: 'Invalid ' + k.replace('_', ' ') });
  const name = clean(b.party_name, 80); if (name.length < 2) return res.status(400).json({ success: false, message: 'Enter the party name' });
  let mobile = ''; if (b.mobile != null && b.mobile !== '') { if (typeof b.mobile !== 'string' && typeof b.mobile !== 'number') return res.status(400).json({ success: false, message: 'Invalid mobile number' }); mobile = String(b.mobile).replace(/\D/g, '').slice(-10); if (!/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number' }); }
  if (!agrValidDate(b.effective_date)) return res.status(400).json({ success: false, message: 'Choose a valid effective date' });
  let cust = null; if (b.customer_id != null && b.customer_id !== '') { cust = getRecord('customers', String(b.customer_id)); if (!cust || cust.status === 'deleted') return res.status(400).json({ success: false, message: 'Customer not found' }); }
  const t = agrTpl(tpl), term = Number.isFinite(+b.term_months) && +b.term_months >= 1 && +b.term_months <= 120 ? Math.round(+b.term_months) : t.term_months;
  const v = { company: 'Pratishtha Finance Services', party_name: name, party_code: '', contact: name, city: clean(b.city, 40), address: clean(b.address, 160), party_address: [clean(b.address, 160), clean(b.city, 40)].filter(Boolean).join(', ') || 'India', address_line: [clean(b.address, 160), clean(b.city, 40)].filter(Boolean).join(', ') || 'India', party_mobile: mobile, party_id: clean(b.party_id, 30), role_title: clean(b.role_title, 60), territory: clean(b.territory, 80), fee_text: clean(b.fee_text, 100), amount_text: clean(b.amount_text, 40), effective_date: agrDate(b.effective_date), term_months: term, notice_days: t.notice_days, settlement_days: t.settlement_days };
  const id = nextId('agr_docs');
  const rec = { id, doc_no: 'AGD-' + String(id).padStart(5, '0'), tpl, tpl_version: t.version || 0, status: 'issued', party_name: name, mobile, customer_id: cust ? cust.id : null, effective_date: b.effective_date, term_months: term,
    snapshot: { title: t.title, intro: agrRender(t.intro, v), recital: agrRender(t.recital, v), term_months: term, notice_days: t.notice_days, clauses: t.clauses.map(c => ({ t: c.t, b: agrRender(c.b, v) })) },
    created_at: new Date().toISOString(), created_by: String(req.auth.name || req.auth.role || 'Admin') };
  putRecord('agr_docs', id, rec); audit(req, 'agreement_doc_issue', 'agr_docs', id);
  res.json({ success: true, record: rec });
});
app.post('/api/staff/agreement-doc-sign', auth, (req, res) => {
  if (!agrCanEdit(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can record a signature' });
  const d = getRecord('agr_docs', String(req.body?.id ?? '')); if (!d) return res.status(404).json({ success: false, message: 'Agreement not found' });
  if (d.status !== 'issued') return res.status(409).json({ success: false, message: 'Only an issued agreement can be marked signed' });
  const on = req.body?.signed_on, w = typeof req.body?.witness === 'string' ? clean(req.body.witness, 60) : '';
  if (!agrValidDate(on) || on > new Date().toISOString().slice(0, 10)) return res.status(400).json({ success: false, message: 'Signing date must be a valid date, not in the future' });
  if (w.length < 2) return res.status(400).json({ success: false, message: 'Enter the witness name' });
  Object.assign(d, { status: 'signed', signed_on: on, witness: w, signed_recorded_by: String(req.auth.name || req.auth.role || 'Admin'), signed_recorded_at: new Date().toISOString() });
  putRecord('agr_docs', d.id, d); audit(req, 'agreement_doc_sign', 'agr_docs', d.id); res.json({ success: true, record: d });
});
app.post('/api/staff/agreement-doc-void', auth, (req, res) => {
  if (!agrCanEdit(req)) return res.status(403).json({ success: false, message: 'Only the CEO / Admin can void an agreement' });
  const d = getRecord('agr_docs', String(req.body?.id ?? '')); if (!d) return res.status(404).json({ success: false, message: 'Agreement not found' });
  if (d.status === 'void') return res.status(409).json({ success: false, message: 'Already void' });
  const why = typeof req.body?.reason === 'string' ? clean(req.body.reason, 120) : ''; if (why.length < 5) return res.status(400).json({ success: false, message: 'Write the reason for voiding' });
  Object.assign(d, { status: 'void', void_reason: why, voided_at: new Date().toISOString() }); putRecord('agr_docs', d.id, d); audit(req, 'agreement_doc_void', 'agr_docs', d.id); res.json({ success: true, record: d });
});


// ───────── Front Desk (receptionist): visitor tokens, appointments, phone messages ─────────
const FD_PURPOSE = ['loan_enquiry', 'emi_payment', 'document_submission', 'complaint', 'meet_staff', 'savings_plan', 'other'];
const istDate = (off = 0) => new Date(Date.now() + 19800000 + off * 864e5).toISOString().slice(0, 10);
const fdCan = req => req.auth.kind === 'staff' && hasAny(req.auth.role, ['manage_frontdesk']);
const fdDeny = res => res.status(403).json({ success: false, message: 'Front desk access required' });
function fdCommon(b, res) {
  for (const [k, max] of [['name', 60], ['notes', 200], ['message', 300]]) if (b[k] != null && (typeof b[k] !== 'string' || b[k].trim().length > max)) { res.status(400).json({ success: false, message: 'Invalid ' + k }); return null; }
  const name = clean(b.name, 60); if (name.length < 2) { res.status(400).json({ success: false, message: 'Enter the visitor name' }); return null; }
  let mobile = ''; if (b.mobile != null && b.mobile !== '') { if (typeof b.mobile !== 'string' && typeof b.mobile !== 'number') { res.status(400).json({ success: false, message: 'Invalid mobile number' }); return null; } mobile = String(b.mobile).replace(/\D/g, '').slice(-10); if (!/^[6-9]\d{9}$/.test(mobile)) { res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number' }); return null; } }
  const staffId = k => { if (b[k] == null || b[k] === '') return { v: null }; const u = typeof b[k] === 'number' || /^\d+$/.test(String(b[k])) ? getRecord('users', String(b[k])) : null; return u && u.status !== 'inactive' && u.status !== 'deleted' ? { v: u } : { bad: true }; };
  const mu = staffId('meet_user_id'), wu = staffId('with_user_id'), fu = staffId('for_user_id'); if (mu.bad || wu.bad || fu.bad) { res.status(400).json({ success: false, message: 'Staff member not found' }); return null; }
  let cust = null; if (b.customer_id != null && b.customer_id !== '') { cust = getRecord('customers', String(b.customer_id)); if (!cust || cust.status === 'deleted') { res.status(400).json({ success: false, message: 'Customer not found' }); return null; } }
  return { name, mobile, notes: clean(b.notes || '', 200), staff: mu.v || wu.v || fu.v, cust };
}
function fdNotify(staff, title, body) {
  if (!staff) return; const id = (db.prepare("SELECT MAX(CAST(id AS INTEGER)) m FROM records WHERE coll='notifs'").get().m || 0) + 1;
  putRecord('notifs', id, { id, title: String(title).slice(0, 80), body: String(body).slice(0, 200), type: 'system', is_read: 0, created_at: new Date().toISOString(), for_kind: 'staff', for_user: +staff.id });
}
function fdNewVisitor(c, purpose, extra) {
  const today = istDate(), n = allOf('fd_entries').filter(e => e.kind === 'visitor' && e.date === today).length + 1, id = nextId('fd_entries');
  const rec = Object.assign({ id, kind: 'visitor', token: 'T-' + String(n).padStart(3, '0'), date: today, name: c.name, mobile: c.mobile, purpose, notes: c.notes, customer_id: c.cust ? c.cust.id : null, meet_user_id: c.staff ? c.staff.id : null, meet_user_name: c.staff ? c.staff.name : '', status: 'waiting', in_at: new Date().toISOString() }, extra || {});
  putRecord('fd_entries', id, rec); return rec;
}
app.post('/api/staff/fd-visitor', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const b = req.body || {};
  if (typeof b.purpose !== 'string' || !FD_PURPOSE.includes(b.purpose)) return res.status(400).json({ success: false, message: 'Choose a valid purpose' });
  const c = fdCommon(b, res); if (!c) return;
  const rec = fdNewVisitor(c, b.purpose); audit(req, 'fd_visitor', 'fd_entries', rec.id);
  fdNotify(c.staff, '🛎️ Visitor waiting: ' + rec.name, 'Token ' + rec.token + ' • ' + rec.purpose.replace(/_/g, ' ') + (rec.notes ? ' • ' + rec.notes : ''));
  res.json({ success: true, record: rec });
});
app.post('/api/staff/fd-appointment', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const b = req.body || {};
  if (typeof b.purpose !== 'string' || !FD_PURPOSE.includes(b.purpose)) return res.status(400).json({ success: false, message: 'Choose a valid purpose' });
  if (!agrValidDate(b.date) || b.date < istDate()) return res.status(400).json({ success: false, message: 'Choose today or a future date' });
  if (typeof b.time !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.time)) return res.status(400).json({ success: false, message: 'Enter the time as HH:MM' });
  const c = fdCommon(b, res); if (!c) return; const id = nextId('fd_entries');
  const rec = { id, kind: 'appointment', date: b.date, time: b.time, name: c.name, mobile: c.mobile, purpose: b.purpose, notes: c.notes, customer_id: c.cust ? c.cust.id : null, with_user_id: c.staff ? c.staff.id : null, with_user_name: c.staff ? c.staff.name : '', status: 'scheduled', created_at: new Date().toISOString() };
  putRecord('fd_entries', id, rec); audit(req, 'fd_appointment', 'fd_entries', id);
  fdNotify(c.staff, '📅 Appointment: ' + rec.name, rec.date + ' ' + rec.time + ' • ' + rec.purpose.replace(/_/g, ' ')); res.json({ success: true, record: rec });
});
app.post('/api/staff/fd-message', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const b = req.body || {};
  if (typeof b.message !== 'string' || b.message.trim().length < 2 || b.message.trim().length > 300) return res.status(400).json({ success: false, message: 'Write the message (up to 300 characters)' });
  const c = fdCommon(b, res); if (!c) return; const id = nextId('fd_entries');
  const rec = { id, kind: 'message', date: istDate(), name: c.name, mobile: c.mobile, message: clean(b.message, 300), for_user_id: c.staff ? c.staff.id : null, for_user_name: c.staff ? c.staff.name : '', callback: b.callback === true, status: 'open', created_at: new Date().toISOString() };
  putRecord('fd_entries', id, rec); audit(req, 'fd_message', 'fd_entries', id);
  fdNotify(c.staff, (rec.callback ? '📞 Call back: ' : '📝 Message: ') + rec.name, rec.message); res.json({ success: true, record: rec });
});
const FD_NEXT = { visitor: { waiting: ['with_staff', 'done', 'left'], with_staff: ['done'] }, appointment: { scheduled: ['arrived', 'cancelled', 'no_show'] }, message: { open: ['closed'] } };
app.post('/api/staff/fd-update', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const b = req.body || {}, e = getRecord('fd_entries', String(b.id ?? ''));
  if (!e) return res.status(404).json({ success: false, message: 'Entry not found' });
  const st = typeof b.status === 'string' ? b.status : ''; if (!Object.values(FD_NEXT).some(m => Object.values(m).some(l => l.includes(st)) || m[st])) return res.status(400).json({ success: false, message: 'Unknown status' });
  if (!(FD_NEXT[e.kind][e.status] || []).includes(st)) return res.status(409).json({ success: false, message: 'Cannot change from ' + e.status + ' to ' + st });
  const now = new Date().toISOString(); e.status = st; let visitor = null;
  if (e.kind === 'visitor') { if (st === 'with_staff') e.start_at = now; else { e.out_at = now; if (!e.start_at && st === 'done') e.start_at = now; } }
  if (e.kind === 'appointment' && st === 'arrived') { e.arrived_at = now; visitor = fdNewVisitor({ name: e.name, mobile: e.mobile, notes: e.notes, cust: e.customer_id ? getRecord('customers', String(e.customer_id)) : null, staff: e.with_user_id ? getRecord('users', String(e.with_user_id)) : null }, e.purpose, { appointment_id: e.id }); e.visitor_id = visitor.id; fdNotify(e.with_user_id ? getRecord('users', String(e.with_user_id)) : null, '🛎️ Appointment arrived: ' + e.name, 'Token ' + visitor.token); }
  if (e.kind === 'message' && st === 'closed') e.closed_at = now;
  putRecord('fd_entries', e.id, e); audit(req, 'fd_update', 'fd_entries', e.id); res.json({ success: true, record: e, visitor });
});
app.post('/api/staff/fd-lead', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const e = getRecord('fd_entries', String(req.body?.id ?? ''));
  if (!e) return res.status(404).json({ success: false, message: 'Entry not found' });
  if (e.kind !== 'visitor' && e.kind !== 'appointment') return res.status(400).json({ success: false, message: 'Only visitors and appointments can become leads' });
  if (e.lead_id) return res.status(409).json({ success: false, message: 'Already converted to a lead' });
  const id = nextId('leads');
  putRecord('leads', id, { id, name: e.name, mobile: e.mobile || '', amount: 0, source: 'Walk-in', priority: 'warm', status: 'new', created: istDate(), agent: String(req.auth.name || 'Front desk'), followup_note: String(e.notes || e.purpose || '').slice(0, 200) });
  e.lead_id = id; putRecord('fd_entries', e.id, e); audit(req, 'fd_lead', 'fd_entries', e.id); res.json({ success: true, lead_id: id });
});
app.get('/api/staff/fd-lookup', auth, (req, res) => {
  if (!fdCan(req)) return fdDeny(res); const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
  if (q.length < 3 || q.length > 40) return res.status(400).json({ success: false, message: 'Type at least 3 characters' });
  const loans = allOf('loans'), out = [];
  for (const c of allOf('customers')) { if (c.status === 'deleted') continue; if (!((c.name || '').toLowerCase().includes(q) || String(c.mobile || '').includes(q) || (c.customer_code || c.code || '').toLowerCase().includes(q))) continue;
    out.push({ id: c.id, name: String(c.name || ''), mobile: String(c.mobile || ''), code: String(c.customer_code || c.code || ''), city: String(c.district || c.city || ''), active_loan: loans.some(l => l.customer_id === c.id && l.status === 'active') }); if (out.length >= 10) break; }
  res.json({ success: true, customers: out });
});
app.get('/api/staff/directory', auth, (req, res) => {
  if (req.auth.kind !== 'staff') return res.status(403).json({ success: false, message: 'Staff only' });
  res.json({ success: true, users: allOf('users').filter(u => u.status !== 'inactive' && u.status !== 'deleted').map(u => ({ id: u.id, name: String(u.name || ''), role: String(u.role || '') })) });
});

app.use('/api', auth, (req, res) => res.json({ success: req.method !== 'GET', handled_by: 'sync' }));

// ─── web app ───
const PUB = path.join(__dirname, 'public');
if (fs.existsSync(PUB)) {
  // the page is served with a marker so it knows it is the live app: it then never shows (or falls back to) the built-in demo data
  let INDEX_CACHE = { m: 0, html: '' };
  const indexHtml = () => { const f = path.join(PUB, 'index.html'), m = fs.statSync(f).mtimeMs; if (m !== INDEX_CACHE.m) INDEX_CACHE = { m, html: fs.readFileSync(f, 'utf8').replace('<head>', '<head><meta name="pf-live" content="1">') }; return INDEX_CACHE.html; };
  const sendIndex = (req, res) => { res.set('Content-Type', 'text/html; charset=utf-8').set('Cache-Control', 'no-cache').send(indexHtml()); };
  app.get(['/', '/index.html'], sendIndex);
  app.use(express.static(PUB, { maxAge: 0, index: false }));
  // collection-QR deep link: opens the app, which asks staff to log in and then shows the account
  app.get('/c/:code', sendIndex);
}
app.use((err, req, res, next) => { if (err && err.type === 'entity.too.large') return res.status(413).json({ success: false, message: 'Request too large' }); if (err && (err.type === 'entity.parse.failed' || err.status === 400)) return res.status(400).json({ success: false, message: 'Bad request' }); console.error(err); res.status(500).json({ success: false, message: 'Server error' }); });

if (require.main === module) {
  const server = app.listen(PORT, () => console.log(`Pratishtha Finance running on http://localhost:${PORT}`));
  let closing = false;
  const shutdown = sig => {            // finish in-flight requests, fold the WAL into the main file, then exit cleanly
    if (closing) return; closing = true; console.log('[shutdown] ' + sig);
    setTimeout(() => process.exit(1), 4000).unref();
    server.close(() => { try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close(); } catch (e) { console.error('[shutdown] ' + e.message); } process.exit(0); });
    if (server.closeAllConnections) server.closeAllConnections();
  };
  setInterval(() => { smsFlush(false).catch(() => {}); }, 15000).unref();
  process.on('SIGTERM', () => shutdown('SIGTERM')); process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', e => console.error('[unhandledRejection]', e && e.message));
}


// automatic daily backup (keeps last 7)
setInterval(() => {
  try {
    const dir = path.join(path.dirname(DB_PATH), 'backups'); fs.mkdirSync(dir, { recursive: true });
    const f = path.join(dir, 'auto-' + new Date().toISOString().slice(0, 10) + '.db');
    if (!fs.existsSync(f)) db.exec(`VACUUM INTO '${f.replace(/'/g, "''")}'`);
    fs.readdirSync(dir).filter(x => x.startsWith('auto-')).sort().slice(0, -7).forEach(x => fs.unlinkSync(path.join(dir, x)));
  } catch (e) { console.error('backup failed', e.message); }
}, 6 * 60 * 60 * 1000).unref();

// Exposed only when required as a module (unit tests); `node server.js` is unaffected.
if (require.main !== module) module.exports = { panCheck, aadhaarCheck, ifscCheck, acctCheck, gatewaySigOk, smsFlush, smsEnqueue, planRateFor, planRenewalCheck, planDocNorm, PLAN_DOC_DEFAULTS, planCalc, planCheck, planNorm, PLAN_DEFAULTS, app, db, hashPw, checkPw, cleanStr, cleanVal, pwProblem, emiCalc, r2s, inr, maskName, escH, agrRender, agrVars, agrEff, agrDate, polv, hasAny, canRead, canWrite, putRecord, getRecord, allOf, proofCheck, goldItems, goldOwed, runReminders, remDays };
