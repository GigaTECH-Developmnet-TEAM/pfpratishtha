# Pratishtha Finance — Backend + Web App

One Node.js server that (1) serves the web app and (2) stores all data in a SQLite database
with real login, role-based permissions (CEO controls everything) and audit log.

## Run on your computer (test)
```
npm ci
SEED_DEMO=true npm start        # demo data, open http://localhost:5000
```
Windows (PowerShell): `$env:SEED_DEMO="true"; npm start`

Needs **Node.js 22.5 or newer**.

## Go LIVE (recommended: Render.com / Railway / any VPS)
1. Upload this folder to a GitHub repo (the `.gitignore` already skips `data` and `.env`).
2. **Render**: New → Blueprint → select the repo (`render.yaml` is included). Set `ADMIN_PASSWORD`. Done.
   **Docker / VPS**: `docker build -t pf . && docker run -d -p 80:5000 -v pf-data:/data -e ADMIN_PASSWORD=... -e JWT_SECRET=... pf`
3. IMPORTANT: the database lives in ONE file (`DB_PATH`). Keep it on a **persistent disk** — on hosts with
   temporary disks the data is lost on every deploy.
4. Open your URL → login as CEO with `ADMIN_MOBILE` / `ADMIN_PASSWORD` → add branches, users, partners.
5. Use HTTPS (Render/Railway give it free). Passwords travel on login, so never run live over plain http.

| Env variable | Meaning |
|---|---|
| `ADMIN_MOBILE`, `ADMIN_PASSWORD`, `ADMIN_NAME` | CEO (founder) login created on first start |
| `JWT_SECRET` | long random text; keeps sessions secure |
| `DB_PATH` | database file path (use the persistent disk) |
| `SEED_DEMO` | `false` = empty live system, `true` = demo data for a trial |
| `DEFAULT_STAFF_PASSWORD` | initial password for staff the CEO adds (they should change it) |
| `CORS_ORIGIN` | only needed if the web page is hosted on a different domain than the server |

## How logins work
- **Staff**: mobile + role + password. New staff get `DEFAULT_STAFF_PASSWORD` unless the CEO types one in *Add User*.
- **Customers / Partners**: created automatically when the record is added; first password = **last 6 digits of their mobile**.
  They can change it from *Profile → Change Password*. CEO/HR can reset staff passwords from *Users*.
- 5 wrong passwords = account locked for 10 minutes. Blocking a user kicks them out immediately.

## What the server enforces (not just the screen)
- Every role only receives and can only change the data its permissions allow; the CEO edits permissions in *Roles & Permissions*
  and the change reaches everyone within seconds.
- A customer only ever receives their own profile, loans, RD, passbook. A partner only their own leads/team/payouts.
- Only the CEO can change permissions, create/edit a CEO account, or download backups.
- Audit trail of logins and every create/update/delete (`GET /api/audit`, CEO / Audit role).

## Backups
- Automatic daily copy kept in `data/backups` (last 7).
- CEO can download a full backup: `GET /api/admin/backup` (with the CEO token). Also copy the disk regularly.

## Offline / demo mode
If the file `public/index.html` is opened directly (double-click) or the server is down, the app falls back to the old
built-in demo data; nothing is saved to the server in that mode.

## Notes / limits
- SMS/WhatsApp OTP is not configured (needs a provider such as MSG91/Twilio) — password login is used.
- Concurrency: records are saved per record (last save wins); two people editing the *same* record in the same few seconds can overwrite each other.
- SQLite comfortably serves a single-server finance company (many thousands of records, dozens of users). For much larger scale, move to PostgreSQL.

## Face / biometric login
Uses WebAuthn platform authenticators (Face ID, Android face/fingerprint unlock, Windows Hello). The CEO enables it (and picks the roles) in **Settings → Face / Biometric Login**; each user then registers their own device from **Profile**. The server stores only a public key. Requires **https** (localhost works for testing). Optional env: `FACE_RP_ID` (your domain) and `FACE_ORIGIN` if you run behind a proxy/custom domain.

## Security (v3)
- Passwords: scrypt hashes, min 8 chars with letters + numbers; **first login / admin-reset forces a new password** (API is blocked until changed). Account lockout after 5 failures, per-IP login and API rate limits, constant-time checks, same error for unknown user / wrong password.
- Sessions: JWT (HS256 pinned), 12h, revoked on logout / password change / role change; 30-minute idle auto-logout in the app.
- Stored-XSS defence: every record written is sanitised (`< > " ' \` \` characters neutralised, photos must be real base64 images); strict CSP, nosniff, frame-ancestors none, HSTS in production, `Cache-Control: no-store` on the API.
- Server enforces roles on every read/write, customer/partner data scoping, balanced + append-only ledger.
- Go-live checklist: set `ADMIN_PASSWORD`, `NODE_ENV=production`, serve over **https**, put the SQLite file on a persistent disk and use `/api/admin/backup`.

## Domain: pratishtha.pro
The web app and the API are served by the same server, so just point the domain at it:
1. In your host (e.g. Render → Settings → Custom Domains) add `pratishtha.pro` and `www.pratishtha.pro`.
2. At your domain registrar add the DNS records the host shows (usually an `A`/`ALIAS` record for `pratishtha.pro` and a `CNAME` for `www`). HTTPS certificates are issued automatically.
3. Set `FACE_RP_ID=pratishtha.pro` and `FACE_ORIGIN=https://pratishtha.pro` (already in `render.yaml` / `.env.example`) so Face Login works on the domain.
In production the server forces https and redirects `www.pratishtha.pro` → `https://pratishtha.pro`.

## QR verification
ID cards, partner certificates, RD bonds and customer forms carry a QR code that opens `https://pratishtha.pro/verify/<type>/<code>` (`emp`, `partner`, `cust`, `rd`). The page shows only limited, masked details (document, reference, holder's first name + initial, status) and is rate-limited.

## Retailer partners, card purchases, emergency cash, insurance
- Retailer Partner role (kind `retailer`): CEO/authorised staff onboard (KYC + agreement) → Go Live creates the login (password = last 6 digits of mobile, change forced).
- Card purchase: retailer `POST /api/retailer/charge` → customer approves with password (`/api/customer/card-pay`) → EMI loan created on the card. Staff settle the retailer (commission kept) from the Retailers page.
- Emergency cash: `POST /api/customer/emergency-loan` (policy keys `card_emerg_max` default 5000, `card_emerg_rate`, `card_emerg_tenure`), loan created as approved; staff disburse through the normal flow.
- Insurance (optional, insurer-backed): `ins_plans` (CEO-editable), `ins_policies`, `ins_claims`; premium posts to `ins_payable`, remitted to insurer less commission.
- New permissions: view_retailers, manage_retailers, view_insurance, manage_insurance.
- Retailer returns: `POST /api/retailers/txn-return` (permission `settle_retailers`). Settlement above policy `settle_cap` (default ₹50,000) needs the CEO.
- Card settings (CEO > Settings > Finance policy): emergency limit/rate/tenure, card purchase rate, max single payment, settlement cap.

## Ops upgrade (reminders, e-sign, auto-debit, credit, portfolio, backup, Hindi)
- **Reminders** (`send_reminders`): WhatsApp/SMS links with ready message for overdue / due-in-3-days / RD; each click logged (`comm_log`). Real bulk SMS/WhatsApp needs a provider API key (not bundled).
- **e-Sign** (customer): drawn signature + password step-up, SHA-256 of loan terms stored; shown on printed agreement. `POST /api/customer/esign`.
- **Auto-debit / eNACH-style** (`manage_autodebit`): customer requests mandate; staff enter bank UMRN to activate, download NACH-style CSV, mark Debited/Failed (posts collection). Live bank integration needs a NACH provider.
- **Credit profile**: internal 300–900 score + optional manual bureau score; suggested card limit. Guidance only.
- **Portfolio & NPA** (`view_portfolio`): ageing, PAR30, NPA, collection efficiency, monthly collection targets (CEO sets).
- **Export & Backup** (`export_data`): CSV per dataset; CEO full JSON export, backup-now, list. Auto backup every 6h (keeps 7).
- **Notifications**: server writes per-user notifs (payments, loan/card/claim/mandate status); non-staff only read their own.
- **Hindi/English toggle** for customer/partner/lender/retailer portals (default English).
- **Retailer statement**: monthly statement + commission invoice with GST split (print/PDF).

## Certificates & QR
- Professional landscape certificate for **every partner type**: DSA/Channel Partner, Lender Partner (empanelment) and Partner Retailer; each has seal, verify-QR, WhatsApp/Email share. Open from partner/lender/retailer detail (staff) or own Profile page.
- Verify QR now accepts all codes: emp, partner, cust, rd, card, ins, retailer, **lender** (`/verify/lender/LND-0001`), plus bare typed codes (EMP-, PFS-DSA-, PFS-C-, LND-, RTL-). Multi-scale photo decode; non-Pratishtha QR shows what was read.

## Add Customer: photo, documents, loan & card request
- New-customer form takes a real **photo**, **Aadhaar / PAN / address-proof photos** (stored in `kyc_docs`, images only, <400 KB), an optional **loan request** (amount/type/tenure/rate → pending application) and an optional **card request** (type + requested limit → `requested` card; lender decides the final limit).
- Loan section needs `create_loans`, card section needs `manage_cards`. Docs can be viewed/replaced later on the customer profile.

## Partner payout / settlement claims
- DSA partner: Commission tab → "Request payout" (amount ≤ pending; one open claim) → `POST /api/partner/payout-request`. Retailer: Settlements → "Request settlement" → `POST /api/retailer/settlement-request` (net of commission).
- Staff (`manage_commission` / `settle_retailers`): claims card on Commission / Retailers page → Approve & Pay (posts commission payout / settles sales) or Decline with reason. Claim status moves only pending → paid / rejected; claimant is notified.
- Lender / retailer / partner dashboards show their own Partner Certificate; avatar and profile now use the lender / retailer record (previously fell back to the CEO's).

## Payout rules & role-based notifications
- **Payout Rules** (`manage_payout_rules`, CEO by default): per partner / retailer / lender — basis (% of disbursed loan, ₹ per lead, % card-sale commission, fixed monthly, custom), rate, effective date and a mandatory **reason**. Changes keep history and notify the party. Admin can also **Award** one-off payouts (bonus / incentive / adjustment) with reason, then mark them paid (posts to books).
- **My Payout** page for partners, retailers, lenders: their terms, why, earned / paid / payable, claim button, awards and history.
- **Notifications are role-based**: staff see only items for their permission (e.g. payout claims → `manage_commission`, loan applications → `approve_loans`, card requests → `manage_cards`); lenders get new card requests; partners / retailers / customers see only their own. Enforced on the server.

## Profiles
- All role profiles (staff, customer, partner, lender, retailer) rebuilt: role-specific stats (only what the role may see), ID / details block, working Language row (Hindi/English for external roles), saved WhatsApp/SMS/GPS preferences, photo upload, certificate link (partners), export only with `export_data`.
- Fixed: profile photos of customers / partners / lenders / retailers were never saved to the server (lost on refresh) — now synced.

## Card dues (bill / EMI conversion / pay-off)
- Approving a card payment now offers **Pay later (30-day bill, 0% interest)** (`tenure: 0` on `/api/customer/card-pay`) besides 3/6/9/12-month EMI.
- `POST /api/customer/card-convert` {loan_id, tenure} — password step-up; converts a bill (or an EMI with no payment yet) to a fresh EMI plan at the policy purchase rate.
- `POST /api/customer/card-payoff` {loan_id, amount, mode, upi_ref, foreclosure?} — creates a pending collection; staff verify it in Collections. A `foreclosure` request posts a proper foreclosure (closes the loan) and is refused if the customer paid less than today's closing amount.
- Customer UI: dashboard "Card dues" strip + "Card Dues & Statement" on the card page.

## Live proof photos (compulsory)
- Shop purchase (`POST /api/retailer/charge`) needs `bill_no`, `item`, and a **live JPEG** `proof_photo` + `proof_ts` (customer + product + bill). Emergency cash (`POST /api/customer/emergency-loan`) needs a live selfie the same way.
- Server checks: JPEG signature and size, captured within 5 minutes, never-before-used (SHA-256), optional GPS. Photos live in the server-only `proofs` collection (`proof_id` on the txn / loan; nobody can edit or strip it via sync).
- Customers see the shop's photo in the approval popup; staff/retailer see "View proof photo". Settlement and cash-loan release need a proof (CEO override only for legacy records).
- The app captures through the live camera only (no gallery picker); the camera needs https.

## Gold loans
- Staff page **Gold Loans** (`view_gold` / `manage_gold`, CEO has both; ops & branch get `manage_gold`, finance/risk/MIS `view_gold`) and customer page **Gold Loan** (rate card, calculator, appraisal request, pledges, release confirmation).
- Flow: `POST /api/staff/gold-appraise` (weights × 22K rate × purity ÷ 22, loan ≤ LTV; **all maths on the server**; two live photos) → creates a pledge + a pending `gold` loan → normal approval → `POST /api/staff/gold-vault` (a *different* staff member seals it, packet no. + live photo; CEO exempt) → disbursal is refused until the pledge is `vaulted` → repayments as usual → `POST /api/staff/gold-release` (loan must be closed, live handover photo) → customer confirms with password (`/api/customer/gold-release-confirm`).
- Risk: `POST /api/staff/gold-margin-scan` flags pledges whose loan ≥ 85% of today's gold value and alerts the customer; `POST /api/staff/gold-auction` (CEO only): notice → auction only after 30 days.
- Rates/policy: `gold_rate_22k`, `gold_ltv_pct` (cap 75), `gold_rate_pct`, `gold_max_loan` (Settings → Finance policy); `POST /api/staff/gold-rate` lets `manage_gold` staff update the daily rate (>15% jump needs CEO); `GET /api/gold/rate` for customers.
- Pledge receipt prints with a QR (`/verify/gold/<PFS-GL-…>`). Existing databases: tick `view_gold` / `manage_gold` in Roles & Permissions.

## Document (PDF) polish
Loan agreement now has fee summary, policy-driven late-fee/foreclosure clauses, gold-pledge clause, masked account number and a full repayment schedule. Disbursement advice shows net amount after fees. RD NOC uses real payout figures and a DRAFT banner until settled. RD statement no longer invents weekly deposits (single "balance brought forward" row). Payslip rebuilt (dynamic month, earnings/deductions, net in words, signatures). Letters get an on-screen A4 layout.

## PFS Card front/back images and welcome letter
Card detail (staff) and My PFS Card (customer) now have "Front & Back" (SVG preview plus 2024x1276 PNG download for each side) and "Welcome Letter" (A4 letter with both card faces, details, usage steps and safety note). Available for issued (active/inactive) cards only; same permission rule as card print.

## Partner agreements section
- Staff (CEO / Biz / Sales Mgr / MIS): "Partner Agreements" page — counts, search, status filter (Signed / Awaiting / Not sent), View/Print PDF, "Request signature" (notifies the partner; needs manage_partners).
- Partner: "My Agreement" page — key terms, read/download PDF, draw-signature + password e-sign (`POST /api/partner/esign`), plus a reminder banner on the dashboard until signed.
- Signed records live in `esigns` (doc_type `partner_agreement`: signature, signer, time, IP, device, SHA-256 doc id). A partner can read only their own; one signature per partner (409 on repeat). The agreement PDF shows the signature and e-sign details.
- Staff endpoint: `POST /api/staff/partner-agreement-request {partner_id}`.

## Agreements: DSA, Lending Partner and Retail Partner (admin-customisable)
- Templates: `agreement-defaults.json` holds the standard wording (15 clauses each). The CEO (or anyone granted `manage_agreements`) edits title, opening paragraph, recital, term/notice/settlement days and clauses from Partner Agreements → Customize. Placeholders such as `{{party_name}}`, `{{commission}}`, `{{pool_limit}}` are filled per party; unknown placeholders are rejected. Saved to collection `agr_templates` through `POST /api/staff/agreement-template` (validated, versioned, audited); `{id, reset:true}` restores the standard text.
- E-sign: `POST /api/party/esign` (partner / lender / retailer logins; password + drawn signature). The signed record stores the exact rendered wording (`snapshot`) + SHA-256 doc id, so later template edits never change a signed copy. Each party can read only its own signature.
- Request: `POST /api/staff/agreement-request {kind,id}` (partner/lender/retailer; needs the matching manage_ permission) notifies the party.
- Pages: staff "Partner Agreements" (DSA / Lender / Retailer tabs); partners, lenders and retailers get "My Agreement" and a reminder banner on their dashboard until signed.

### Agreements — renewal, void and bulk request
- Signing now ticks the lender/retailer onboarding stage "agreement" automatically. The effective date is the later of the party's agreement date and the signing day; validity = effective date + template term. Staff see "Valid till", "expiring" (≤30 days) and "Expired" chips and a "Renewal due" filter.
- `POST /api/staff/agreement-void {kind,id,reason}` (CEO / manage_agreements): marks the signed record void (kept for history), notifies the party and asks for a fresh signature. A voided agreement no longer counts as signed.
- `POST /api/staff/agreement-request-all {kind}`: requests a signature from every active, unsigned party that has not been asked yet (needs the matching manage_ permission).

## Action Center and automatic reminders
- Staff dashboard (CEO, Ops, Finance, Risk, Biz, Branch, MIS, Sales Mgr) shows an "Action Center" listing what is waiting — card requests/activations, gold requests and release/auction notices, insurance enrolments and claims, partner payout claims, retailer sales awaiting settlement, lender/retailer applications, agreements awaiting signature or due for renewal, KYC pending, defaulters. Each row opens its page, and only pages in the role's own menu are listed.
- Server job `runReminders()` runs every 6 hours (and on demand via `POST /api/staff/run-reminders`, CEO only): agreements expiring within 30 days or expired (party + staff), cards valid-till within 15 days, RDs maturing within 7 days or already matured, insurance ending within 15 days. Each reminder is sent once (log in `remind_log`).

Reminder windows are CEO-controlled in Settings → Finance policy: `remind_agr_days` (30), `remind_card_days` (15), `remind_rd_days` (7), `remind_ins_days` (15); allowed 1–120. The Action Center has a "Run reminders" button for the CEO.


## Testing (unit, integration, security)
- `npm run test:unit` – server helpers (hashing, sanitising, EMI, permissions, agreements) + browser-side maths (Chromium via Playwright).
- `npm run test:integration` – real HTTP flows on a throw-away server/DB: auth, lockout, role-scoped sync, card flow, returns, agreements, reminders.
- `npm run test:security` – pen-test suite (SEC-01…SEC-34). Each test asserts the *secure* behaviour; a failure = vulnerability.
- `npm test` runs everything. TDD rule used: write the failing test first, then fix, then green.
- Fixed from pen-test: CEO could forge server-only records (e-sign/proofs/gold pledges/templates) through raw sync; object-typed login fields caused 500; oversize/bad JSON returned 500; loans accepted negative/absurd numbers via sync; tenure 0 made EMI = Infinity.

## e-Stamp (₹10) + net disbursement
- Policy `stamp_duty` (default ₹10, Settings → Policy; 0 = off) is deducted from the loan at disbursement together with processing fee + GST → **Net = Principal − Fee − GST − Stamp**. Posted to the ledger account *e-Stamp Duty Payable*.
- Disburse screen has optional e-Stamp certificate no./date/state. The Loan Agreement now opens with an "INDIA NON JUDICIAL — Government of India e-Stamp" particulars page, a deductions table and a stamp-duty clause; the Disbursement Advice shows the stamp line.
- The app does NOT generate the government certificate itself: buy the real e-Stamp from SHCIL / your state portal and enter its number (the page records its particulars; attach the original).

## Pen-test round 3 (SEC-35…SEC-44)
Fixed: loan money fields (`principal_amount`, `emi_amount`, `stamp_duty`, `net_disbursed`…) now range-checked server-side and net can't exceed principal; Settings values (stamp duty, fee %, GST…) range-checked; loan workflow enforced (only approve_loans can approve, only disburse_loans can disburse, nobody creates an "active" loan directly); lockout no longer reveals which mobiles exist; e-Stamp text fields length-capped; CSV exports neutralise spreadsheet formulas (`=`, `+`, `-`, `@`).
Known/accepted: CSP still allows `'unsafe-inline'` because the app is a single HTML file with inline handlers.

## Pen-test round 4 (SEC-45…SEC-56)
Fixed: passwords/secret-like keys sent through sync are dropped (they used to be stored in records and appeared in the export); production now refuses to start with `SEED_DEMO=true` (override only with `ALLOW_DEMO_IN_PROD=yes-i-understand`).
Verified safe: no self-promotion to CEO, no login created through sync, CEO password reset blocked for others, admin/backup/export/audit gated, logout revokes tokens, IDOR on e-sign/card-pay, partner payout abuse, retailer data scope, password policy.
Known test-data drift (not security): t50, t59, t66 Playwright scripts assume older seed dates/permissions.

## PFS Savings Plans + Bond Certificate
- 10 standard plans (`plan-defaults.json`): Model Savings, Daily Savings, Recurring, Fixed-Term Goal, Samriddh, Golden Anand, Aajeevan Anand, Bhavishya Anand, Monthly Income, Sukhkari Vikas Patra. CEO (or anyone given the **manage_plans** permission) edits amount range, tenure, fixed tenures, rate, Hindi name/description, bond on/off, on/off; can add own plans, reset, delete (custom only). Changes affect new requests only — issued bonds keep their terms (hash-sealed).
- Flow: customer requests (password confirm + nominee + consent) → staff confirms money received (+reference) → plan active, **PFS-BND-xxxxxx Bond Certificate** issued (PDF, QR → `/verify/bond/<no>`) → staff add instalments → close at maturity (CEO only before maturity, benefit at rate−2%).
- Maths: recurring = monthly compounding annuity-due (daily plans: per-day × 365/12 per month); income = monthly payout rate/12 on the deposit, deposit returned at end; certificate = quarterly compounding. Server and app use the same formulas; the server recomputes everything.
- Endpoints: `/api/staff/plan-catalog`, `/api/customer/plan-open`, `/api/staff/plan-open|plan-activate|plan-deposit|plan-close`. `plan_accts` / `plan_catalog` are server-only collections (raw sync cannot write them).
- Tests: `test/unit/plans.unit.test.js`, `test/integration/plans.integration.test.js`, `test/security/pentest5.test.js` (SEC-57…64).

## Plan documents + Complaint Register
- 9 editable documents (`plan-doc-defaults.json`): Customer Application Form, Consent Form, Privacy Policy, Terms & Conditions, Customer Service Agreement, Grievance Redressal Policy, Refund & Cancellation Policy, Employee/Agent Agreement, Business Partner Agreement. Edit in *Savings Plans → Docs* (CEO / `manage_plans`); placeholders such as `{{customer_name}}` are filled at print time; customers print their own set from *My Plans → Documents*.
- Customer Complaint Register (10th item): customers raise complaints (*Complaints* in their menu, max 5 open), staff can log walk-in/phone complaints, resolve or close with a written reason; due date = policy `grievance_days` (default 30, Settings); printable register with TAT summary. Collections `plan_doc_tpl` / `complaints` are server-only.
- Tests: `test/integration/docs.integration.test.js`, `test/security/pentest6.test.js` (SEC-65…69); browser test `t81.js`.

## Cross-check round (final)
- `plan-activate`: recurring plans now require the received amount to be a whole number of instalments (test added).
- `runReminders()` also covers plans (maturity, monthly instalment due) and overdue complaints (staff with `manage_plans`); result shape: `{agreements, cards, rds, insurance, plans, complaints}`; idempotent.
- UI: "New account" button only on the Accounts tab. Old browser tests (t50/t59/t66) corrected; full regression green.

## Round 7 — TDD / unit / integration / pen-test
- New: `test/integration/routes-coverage.integration.test.js` (every previously untested route: 401 / role gating / hostile bodies / IDOR) and `test/security/pentest7.test.js` (SEC-70…77).
- Fixed: non-CEO loan sync crashed with 500 (variable used before declaration); collections accepted negative/absurd amounts and posted ones were editable/deletable by non-CEO; journal accepted negative/both-sided/absurd lines and manual entries from non-accountants; change-password had no lockout; gold-release returned 409 for a missing pledge.

## Round 8 — production hardening
- Startup self-check refuses weak/default ADMIN_PASSWORD, JWT_SECRET, DEFAULT_STAFF_PASSWORD and non-https FACE_ORIGIN in production; umask 077 (private DB), graceful SIGTERM shutdown, non-root Docker + healthcheck, `.dockerignore`, `npm audit` fixed (0 vulnerabilities). See PRODUCTION.md. Tests: `test/security/production.test.js` (PROD-01…06).

## Fixed Deposit (FD) plan
- New standard plan `fd` (PFS Fixed Deposit): lump sum ₹10,000–₹50,00,000, tenure 12–60 months, quarterly compounding, Bond Certificate.
- Rate = tenure slab (12m 7.25 · 24m 7.60 · 36m 7.85 · 48m+ 8.05) + senior citizen (60+, +0.25) + women (+0.15) + renewal (+0.15, only for a matured FD of the same plan, once). Maximum advertised "up to 8.45%"; with renewal 8.60. Based on customer DOB / gender.
- Everything is editable by the CEO in Plans → Edit (slabs + extras). Tests: unit (planRateFor, planRenewalCheck, planNorm), integration, browser t85.

## Round 9 — features from the "Key Features" checklist (stage 1)
- **PAN / Aadhaar / IFSC / bank-account verification**: format + checksum (Verhoeff for Aadhaar) enforced on customer save; duplicates refused; server stamps `kyc_checks` (cannot be forged). Not a government lookup — needs a licensed API for that.
- **SMS alerts**: customer notifications are queued (`sms_queue`), sent to `SMS_URL` (JSON `{to,message,sender}`, header from `SMS_AUTH="Name: value"`), retried 3×, capped at 8/number/day, opt-out per customer, masked log (CEO: Settings). Dry-run (logged only) when no provider.
- **Online payment (Razorpay-style)**: `/api/customer/gateway-order` creates an order with server-set notes; `/api/pay/webhook` verifies the HMAC signature (`GATEWAY_WEBHOOK_SECRET`), is idempotent per payment id, and creates a gateway-verified pending payment for staff to confirm. Env: `GATEWAY_WEBHOOK_SECRET`, `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`.
- Tests: `identity.unit`, `features2.integration`, browser `t86`.

## Round 9 — stage 2 (Savings Accounts, Groups, Master Data, Credit Report)
- **Savings Accounts** (`/api/staff/sav-*`): open / deposit / withdraw / statement; balance is server-owned. Limits: min open ₹500, min balance ₹500, staff withdrawal ≤ ₹20,000 (above needs CEO), ₹50,000/day. CEO closes accounts and credits monthly interest (idempotent per month). Journal: Dr money / Cr *Savings Account Deposits*; interest Dr *Interest on Savings*.
- **Groups (JLG)**: 2–25 members, one active group per customer, leader must be a member; loans can carry `group_id`; group collection screen posts each member's EMI.
- **Master Data**: CEO-edited pick-lists (occupation, loan purpose, relation, designation, expense head, document type) feed the forms as suggestions.
- **Credit Report**: printable internal report (not a bureau report).

### Pen-test round 8 findings (all fixed, tests in `test/security/pentest8.test.js`)
1. **High** – staff could mark a collection `gateway_verified` through sync → now only the signed webhook can set gateway fields.
2. **Medium** – duplicate-Aadhaar check could be bypassed with dashes (`1234-5678-9012`) → all non-digits stripped before comparing.

## Agreements rewritten (Master Declaration merged)
DSA, Lender and Retailer agreement templates are now professional English and carry the Master Declaration & Terms of Service clauses (status of the Company, regulated products, deposits, handling of money, customer fees, privacy, RBI Digital Lending Directions 2025, brand use, assignment, suspension, grievance, governing law). Already-signed agreements keep their old signed text; new requests use the new text. CEO can still edit via Customize.

## Agreement Library (six agreement types)
Client Service, Retailer/Merchant, Service Partner (lender), Business Associate, Employee/Agent and Branch/Franchise agreements (plus the existing DSA/Channel Partner). Retailer, Service Partner and DSA keep their e-sign flow. Client, Associate, Employee/Agent and Franchise are issued from **Agreement Library** (CEO): `POST /api/staff/agreement-doc` → printable agreement with signature blocks → `agreement-doc-sign` (paper-signed copy + witness) → `agreement-doc-void`. Documents live in the server-only `agr_docs` collection. Wording is editable by the CEO per template.

## Back / close everywhere
Every popup now has a ✕ button, closes on tapping the dark area and on Esc; the phone/browser Back button closes the top popup, then the side menu, then goes back one page (it no longer throws the user out of the app). A unit test guards against duplicate function declarations.

## Receptionist & Front Desk; branded footer
- New role **Receptionist** (`rc`, demo login 9900112310): own dashboard (waiting queue, today's appointments, messages, workflow guide) and **Front Desk** page — visitor check-in with daily server tokens (T-001…), routing to a staff member (they get a notification), With staff → Done / Left, appointments (Arrived creates a token), phone messages with call-back flag, enquiry → Lead, and a limited customer lookup (name, mobile, code, city, "has active loan" — nothing else). No money, loans or customer-data access. Records are server-only (`fd_entries`); permission `manage_frontdesk` (CEO / Ops / Branch / Receptionist, editable by the CEO).
- Every printed statement/receipt/letter/certificate now ends with the Pratishtha Finance Services logo footer (ID cards excluded).
