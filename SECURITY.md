# Security Policy

## Supported Versions

The following versions of Zencrypt are currently supported with security updates:

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 6.2.x | ✅ | Current stable version with SQLite integration |
| 6.0.x | ✅ | Database restructuring |
| 5.5.x | ✅ | Final Flask/SQLite optimization |
| 5.3.x | ✅ | Initial web deployment version |
| 5.2.x | ❌ | Deprecated |
| 5.1.x | ❌ | Deprecated |
| 5.0.x | ❌ | Deprecated |
| 4.2.x | ✅ | Final CLI-only version |
| < 4.0 | ❌ | Not supported |

## Key Security Features

### Web Application (v5.0+)
- Flask-based authentication system with JWT tokens
- Secure key storage in dedicated subdirectory
- SQLite database with encrypted storage
- File operation security with password protection
- Session management and user data isolation

### CLI Version (v4.2)
- SHA256 hashing with salt support
- Fernet symmetric encryption
- PGP asymmetric encryption
- Secure file operations with AES
- Local key storage protection

## Reporting a Vulnerability

### How to Report
1. Email: ryanshatch@gmail.com
2. Include version number and steps to reproduce
3. Provide impact assessment if possible

### Response Timeline
- Initial response: Within 24 hours
- Status update: Every 48 hours
- Resolution target: Within 7 days

### Process
1. Submit report
2. Receive acknowledgment
3. Assessment and verification
4. Resolution and patch release
5. Public disclosure (if applicable)

## Security Hardening Baseline (Flask + SQLite)

For production deployments (including Render), verify all items below:

- Keep all secrets in environment variables only (`SECRET_KEY`, JWT secret, encryption passphrases).
- Use randomly generated values for all secrets (minimum 32 bytes entropy).
- Enable secure cookie flags (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE='Lax'` or `'Strict'`).
- Enable CSRF protection on all state-changing form endpoints.
- Add request rate limiting for login, registration, and encryption endpoints.
- Validate and sanitize all user-provided filenames and upload MIME types.
- Limit upload size via `MAX_CONTENT_LENGTH` to prevent denial-of-service.
- Set strict response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Run dependency and secret scanning in CI/CD before deploy.
- Keep SQLite file outside of publicly served directories and enforce file permissions (`0600` where possible).
- Turn off Flask debug mode in production and never expose Werkzeug debugger publicly.

## Security Updates

Security patches are released through the following channels:
- GitHub repository
- Package updates
- Security advisories

Keep your installation updated to receive the latest security fixes.

## Contact

For urgent security matters: security@zencrypt.app

For general inquiries: https://zencrypt.gitbook.io/zencrypt
