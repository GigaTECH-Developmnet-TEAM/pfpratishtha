# Pratishtha Finance — Developer Hosting & Handover Guide

Audience: the developer / DevOps person who will host, run and maintain the app.
Language of the product UI: English. Time zone of the business: IST (Asia/Kolkata).

---

## 1. What you are hosting

| Item | Detail |
|---|---|
| Type | One Node.js process that serves the API **and** the web app (single-page `public/index.html`) |
| Runtime | Node.js **>= 22.5** (uses the built-in `node:sqlite`) |
| Framework | Express 5, helmet, express-rate-limit, jsonwebtoken, @simplewebauthn/server (face/biometric login) |
| Database | **SQLite**, a single file (`DB_PATH`), WAL mode. No separate DB server |
| Front end | One self-contained file `public/index.html` (vanilla JS). No build step |
| Port | `PORT` (default 5000) |
| Health check | `GET /api/health` |
| State | Everything lives in the DB file + `backups/` next to it. **The disk must be persistent** |

Because SQLite is a local file, run **exactly one instance** (no horizontal scaling, no multiple replicas writing to the same file). Scale vertically if needed.

## 2. Project layout

```
pf-backend/
  server.js                 API + static hosting + business rules
  public/index.html         the web app (also kept as ../app.html in the source tree)
  seed.json, make-seed.js   first-run seed data (CEO account, roles, masters)
  perms-default.json        default role -> permission map
  agreement-defaults.json   agreement templates (7 types)
  masters-defaults.json, plan-defaults.json, plan-doc-defaults.json
  Dockerfile, render.yaml   deployment descriptors
  PRODUCTION.md             short go-live checklist
  test/                     unit, integration, security (pen-test) tests
```

## 3. Environment variables

**Mandatory in production** (the server refuses to start if these are weak/missing):

| Variable | Rule |
|---|---|
| `NODE_ENV` | `production` |
| `ADMIN_PASSWORD` | 12+ chars, letters + digits, not a common word. Password of the CEO account |
| `JWT_SECRET` | 32+ random chars: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `DEFAULT_STAFF_PASSWORD` | 10+ chars. Initial password for newly created staff (they must change it at first login) |
| `SEED_DEMO` | `false` |
| `DB_PATH` | Path on the persistent disk, e.g. `/data/pratishtha.db` |
| `FACE_RP_ID` | Bare domain, e.g. `pratishtha.pro` |
| `FACE_ORIGIN` | Full origin, e.g. `https://pratishtha.pro` |

**Optional:**

| Variable | Purpose |
|---|---|
| `PORT` | Listen port (default 5000) |
| `ADMIN_MOBILE`, `ADMIN_NAME` | CEO login mobile / display name (render.yaml sets the mobile) |
| `TOKEN_TTL` | Login token lifetime (default `12h`) |
| `CORS_ORIGIN` | Comma-separated origins. Leave empty (same-origin only) when the app is served by this server |
| `SMS_URL`, `SMS_AUTH`, `SMS_SENDER` | SMS provider (see §8). `SMS_AUTH` format `Header-Name: value`. Without `SMS_URL` messages are only logged (dry-run) |
| `GATEWAY_WEBHOOK_SECRET`, `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `GATEWAY_API_BASE` | Online payments (see §9) |

Never commit secrets. Set them in the host's secret manager.

## 4. Hosting option A — Render (the repo already has `render.yaml`)

1. Push `pf-backend/` to a private GitHub repo (do **not** commit `node_modules`, `*.db`, `data/`).
2. Render → New → Blueprint → select the repo. It reads `render.yaml`.
3. Plan must be a **paid** one with a **persistent disk** (the file mounts a 1 GB disk at `/data`). Free plans have no disk, so data would be lost.
4. Fill the `sync: false` secrets: `ADMIN_PASSWORD`, `DEFAULT_STAFF_PASSWORD`. `JWT_SECRET` is auto-generated.
5. Deploy. Wait for `/api/health` to go green.
6. Domain: add `pratishtha.pro` and `www.pratishtha.pro`; set the DNS records Render shows. HTTPS certificates are automatic. (www redirects to the apex inside the app.)

## 5. Hosting option B — Docker on any VPS (DigitalOcean, AWS Lightsail, Hetzner, etc.)

```bash
# on the server (Ubuntu 22.04+, Docker installed)
git clone <your-private-repo> pratishtha && cd pratishtha/pf-backend
docker build -t pratishtha .

docker run -d --name pratishtha --restart unless-stopped \
  -p 127.0.0.1:5000:5000 \
  -v /srv/pratishtha-data:/data \
  -e NODE_ENV=production \
  -e ADMIN_PASSWORD='...' \
  -e JWT_SECRET='...' \
  -e DEFAULT_STAFF_PASSWORD='...' \
  -e SEED_DEMO=false \
  -e FACE_RP_ID=pratishtha.pro \
  -e FACE_ORIGIN=https://pratishtha.pro \
  pratishtha
```

The container runs as the non-root `node` user, so `chown -R 1000:1000 /srv/pratishtha-data` first.

Put a TLS reverse proxy in front (the app itself expects HTTPS and redirects plain HTTP; it trusts `X-Forwarded-Proto`). Minimal Caddy config:

```
pratishtha.pro, www.pratishtha.pro {
    reverse_proxy 127.0.0.1:5000
}
```

Caddy gets and renews Let's Encrypt certificates automatically. With nginx, pass `X-Forwarded-Proto $scheme` and `X-Forwarded-For`.

## 6. Hosting option C — plain Node + systemd (no Docker)

```bash
node -v                       # must be >= 22.5
cd /opt/pratishtha/pf-backend
npm ci --omit=dev
```

`/etc/systemd/system/pratishtha.service`:

```
[Unit]
Description=Pratishtha Finance
After=network.target

[Service]
User=pratishtha
WorkingDirectory=/opt/pratishtha/pf-backend
EnvironmentFile=/etc/pratishtha.env        # chmod 600, holds all the variables above
ExecStart=/usr/bin/node --disable-warning=ExperimentalWarning server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now pratishtha`, then reverse proxy as in §5.

## 7. First launch checklist

1. Start the server with the production variables. On an empty DB it creates the CEO user (`ADMIN_MOBILE` / `ADMIN_PASSWORD`) and the default roles, permissions, masters and agreement templates. No demo data is loaded.
2. Open `https://<domain>` → log in as CEO → the app forces a password change. Do it immediately.
3. Create staff users (roles: CEO, managers, accountant, branch staff, receptionist, etc.). **Only the CEO controls permissions** (Settings → Permissions).
4. Fill Master Data (branches, products/schemes, charges) before entering customers.
5. Verify: `/api/health` returns OK; HTTP redirects to HTTPS; a wrong password is rejected; demo numbers do not exist.
6. Take a manual backup (§10) and confirm you can download it.

## 8. SMS (reminders, alerts)

- Set `SMS_URL` to your provider's HTTP endpoint, `SMS_AUTH` to `Header-Name: value` (for example `Authorization: Bearer xxxx`), `SMS_SENDER` to the approved 6-char header (default `PRATFN`).
- The server POSTs JSON `{ "to": "<mobile>", "message": "<text>", "sender": "<id>" }`. If your provider needs a different body, adapt the call in `server.js` (search `SMS_URL`).
- Indian providers need DLT registration (entity, header, templates). Texts must match approved templates, so get them approved first.
- Limits built in: 8 SMS per mobile per day, retry with back-off. CEO can send a test SMS from the admin screen.
- Without `SMS_URL` nothing is sent; messages are marked `logged`.

## 9. Online payments (Razorpay-style)

Flow: app creates an order → customer pays in checkout → gateway calls our **signed webhook** → a *verified pending payment* is recorded → staff confirms it.

1. Create a Razorpay account (KYC complete), generate live keys.
2. Set `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `GATEWAY_WEBHOOK_SECRET` (choose a long random string).
3. In the Razorpay dashboard add webhook URL `https://<domain>/api/pay/webhook`, same secret, events `payment.captured` (and order paid).
4. Test with a small real payment. The webhook verifies the `x-razorpay-signature` HMAC; clients cannot forge the gateway flags.
5. Until all three variables are set, online payment shows as "not switched on".

## 10. Backups and restore (very important)

- Automatic: daily backup, last 7 kept in `backups/` beside the DB.
- Manual: CEO → Admin → Backup now (keeps last 10 manual), or `GET /api/admin/backup` to download a consistent copy.
- **These backups are on the same disk.** Also copy them off-server daily (cron + `rclone`/`aws s3 cp`/provider snapshots). A disk failure otherwise loses everything.
- Restore: stop the server → replace the file at `DB_PATH` with a backup file (`cp backup.db /data/pratishtha.db`) → remove stale `-wal` / `-shm` files next to it → start. Restore drill: do it once on a staging copy before launch.
- Do not copy the live `.db` file with plain `cp` while the server runs (WAL); use the app's backup.

## 11. Security notes (already built in)

HTTPS redirect + HSTS, www→apex, CSP/frame-ancestors/nosniff, rate limits (login/API/verify), account lockout, JWT revocation on password change/reset/logout, role-based access on every collection, DB file mode 600, non-root container, graceful SIGTERM shutdown. `npm audit --omit=dev` reports 0 vulnerabilities at hand-over.

Developer responsibilities: keep secrets out of git; rotate `JWT_SECRET` if leaked (all users get logged out); restrict SSH; keep the OS, Node and `npm audit` current; get an independent security audit before large-scale use.

## 12. Monitoring and operations

- Uptime monitor (UptimeRobot / BetterStack) on `https://<domain>/api/health`, alert by SMS/WhatsApp.
- Logs: stdout/stderr (`docker logs`, `journalctl -u pratishtha`). Business audit trail is inside the app (Audit Log, CEO only).
- Disk: alert at 80% usage. DB growth is slow; 1 GB is fine for early stage, plan 5–10 GB.
- Updates: take a backup → deploy new files → restart → check `/api/health` → smoke test login and one customer page. Rollback = redeploy previous version (+ restore the backup if a data change misbehaved).

## 13. Running and testing locally

```bash
cd pf-backend
npm ci
npm start                     # http://localhost:5000, demo/dev mode (not production)
npm test                      # 208 tests: unit (needs Chromium via Playwright), integration, security
```

Tests need Playwright's Chromium (`npx playwright install chromium`) for the client unit tests. Each test run starts its own throw-away server and database.

Production-mode dry run:

```bash
NODE_ENV=production DB_PATH=/tmp/pf/pf.db ADMIN_PASSWORD='Strong#Pass2026' \
JWT_SECRET=$(openssl rand -hex 32) DEFAULT_STAFF_PASSWORD='Staff#Start2026' \
SEED_DEMO=false FACE_RP_ID=localhost FACE_ORIGIN=http://localhost:5000 npm start
```
(Production mode redirects non-HTTPS requests unless they carry `X-Forwarded-Proto: https`.)

## 14. Developer notes for changes

- The app file is `public/index.html`. If you edit the source copy `app.html`, copy it into `public/` before deploying. After changing the UI data defaults, `npm run seed` regenerates `seed.json`.
- New API routes must be registered **before** the catch-all `app.use('/api', auth, …)` in `server.js`.
- Collection read/write permissions live in the `COLL` table; server-only collections (agreements, front-desk entries, etc.) cannot be written through sync.
- Add a failing test first (project is test-driven), then the fix; keep `npm test` green before every release.
- Do not remove existing features; role-wise additions only. All UI text stays in English (Hindi only for the customer-facing toggle).

## 15. Items needing human/vendor action (cannot be done in code)

1. Real SMS provider + DLT registration and templates.
2. Razorpay live account, keys and webhook.
3. eNACH / e-sign provider if those features are to run live (test in the live environment).
4. Domain DNS and TLS.
5. Off-server backup destination.
6. CA / advocate review of the agreements and the RD / FD / savings / public-deposit rules against RBI/NBFC regulations.
7. Independent penetration test before heavy use.

## 16. Quick reference

| Task | Command / URL |
|---|---|
| Health | `GET /api/health` |
| Start | `npm start` |
| Tests | `npm test` |
| Backup now | App → Admin → Backup, or `POST /api/admin/backup-now` (CEO) |
| Download backup | `GET /api/admin/backup` (CEO) |
| Webhook | `POST /api/pay/webhook` |
| Generate secret | `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
