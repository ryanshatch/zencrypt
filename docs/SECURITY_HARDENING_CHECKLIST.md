# Zencrypt Repository Security Hardening Checklist

This checklist focuses on two goals:
1. Prevent accidental exposure of secrets or sensitive operational data in the Git repository.
2. Reduce common Flask web-application attack paths for a small production deployment (25-50 users).

## 1) Repository exposure findings and patches

### Findings identified in this repository layout

- The repository contains operational artifacts (ZAP HTML report, Snyk report, encrypted archives, and environment backup files).
  - These may unintentionally leak endpoint paths, response headers, scanner fingerprints, local directory paths, or operational patterns.
- Existing `.gitignore` used `/etc/secrets/` (absolute path style) which does **not** reliably ignore `etc/secrets/` in the repo root.
- There was no dedicated local scanner for accidental secret exposure in tracked files.

### Patches implemented

- Hardened `.gitignore` with additional patterns for:
  - Relative `etc/secrets/`
  - `.env.*` family while allowing `.env.example`
  - database journal/dump/backup/swap/temp artifacts
  - scanner HTML outputs that may leak internals
- Added `scripts/repo_security_audit.py` to detect:
  - high-risk tracked filenames (`.env`, keys, sqlite files)
  - likely hard-coded secrets by regex
  - very large binary artifacts that increase attack surface

## 2) Flask security hardening recommendations

Implement or verify the following in your Flask app config and routes.

### App configuration

- Set these in production:
  - `DEBUG = False`
  - `TESTING = False`
  - `SECRET_KEY` from env (32+ bytes random)
  - `JWT_SECRET_KEY` from env (32+ bytes random)
  - `SESSION_COOKIE_SECURE = True`
  - `SESSION_COOKIE_HTTPONLY = True`
  - `SESSION_COOKIE_SAMESITE = 'Lax'` (or `'Strict'`)
  - `PERMANENT_SESSION_LIFETIME` tuned for short sessions
- Add upload-size guard:
  - `MAX_CONTENT_LENGTH` (example: 8-16 MB unless large file use case is required)

### CSRF and authentication

- Use CSRF protection for all form POST/PUT/PATCH/DELETE endpoints.
- Ensure login endpoint has:
  - rate limiting (e.g., 5-10 attempts/minute/IP + account lock/backoff)
  - generic error messages (avoid account enumeration)
- Use strong password hashing (`argon2` preferred; `bcrypt` acceptable).

### File encryption / upload routes

- Strict allowlist of file extensions and MIME types.
- Sanitize filenames with Werkzeug `secure_filename`.
- Store uploads outside static/public paths.
- Validate archive extraction logic to prevent zip-slip/path traversal.
- Never execute or import uploaded files.

### SQLite operational security

- Keep database file outside served/static paths.
- Restrict file permissions (owner read/write only where supported).
- Use parameterized queries only (SQLAlchemy ORM or bound params).
- Enable WAL mode if needed for concurrency, and schedule backups.

### HTTP response headers

Add middleware or extension to set:
- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer` (or strict-origin-when-cross-origin)
- `Permissions-Policy` with only required features

### Logging and secrets hygiene

- Never log secrets, raw JWTs, encryption keys, or plaintext payloads.
- Mask PII in logs.
- Keep logs short-retention and access-controlled.

## 3) Deployment safety checks for Render

- Confirm all required env vars are configured in Render dashboard and **not** in repo.
- Rotate all secrets after any suspected leak.
- Enforce automatic deploy only from protected branches.
- Require pull-request review before merge.
- Add CI jobs to run:
  - unit tests
  - lint checks
  - `scripts/repo_security_audit.py`
  - dependency vulnerability scan (`pip-audit`/`npm audit`)

## 4) Ongoing maintenance cadence

- Weekly: run dependency updates and vulnerability scans.
- Monthly: rotate sensitive keys where feasible.
- Quarterly: run OWASP ZAP baseline scan and review findings.
- Per release: verify no sensitive files are added (`git ls-files` + audit script).
