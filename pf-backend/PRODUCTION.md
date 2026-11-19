# Going live — checklist

**Required environment variables (the server REFUSES to start in production without them):**
| Variable | Rule |
|---|---|
| `NODE_ENV` | `production` |
| `ADMIN_PASSWORD` | 12+ characters, letters + digits, not the old default / a common word |
| `JWT_SECRET` | 32+ random characters (`node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`) |
| `DEFAULT_STAFF_PASSWORD` | 10+ characters, not the old default (new staff must change it at first login) |
| `SEED_DEMO` | `false` (demo logins are refused in production) |
| `FACE_ORIGIN` / `FACE_RP_ID` | `https://pratishtha.pro` / `pratishtha.pro` |
| `DB_PATH` | on a persistent disk, e.g. `/data/pratishtha.db` |

**Built in:** HTTPS redirect + HSTS, www → apex, CSP / frame-ancestors / nosniff headers, rate limits (login, API, verify), account lockout, JWT revocation on password change/reset/logout, private DB file (mode 600), graceful shutdown (SIGTERM), non-root Docker user + health check, `npm audit` clean.

**Do before launch:** change the CEO password at first login; set up daily backups (`/api/admin/backup-now` or copy the `/data` disk); put the app behind the host's TLS; rotate `JWT_SECRET` if it ever leaks (all users are logged out); get an independent security audit and legal review of the documents / public-deposit rules; test real SMS / payment / eNACH integrations in the live environment (they cannot be tested offline).

**Tests:** `npm test` (unit + integration + security + production-config tests).
