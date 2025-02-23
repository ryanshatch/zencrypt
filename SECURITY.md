# Security Policy

## Supported Versions

The following versions of Zencrypt are currently supported with security updates:

```py
/-------- | --------- | -----------------------------------------------\
| Version | Supported | Notes                                          |
| ------- | --------- | ---------------------------------------------- |
| 6.2.x   | ✓         | Current stable version with SQLite integration |
| 6.0.x   | ✓         | Database restructuring                         |
| 5.5.x   | ✓         | Final Flask/SQLite optimization                |
| 5.3.x   | ✓         | Initial web deployment version                 |
| 5.2.x   | ✕         | Deprecated                                     |
| 5.1.x   | ✕         | Deprecated                                     |
| 5.0.x   | ✕         | Deprecated                                     |
| 4.2.x   | ✓         | Final CLI-only version                         |
| < 4.0   | ✕         | Not supported                                  |
\ ------- | --------- | ---------------------------------------------- /
```

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

## Security Updates

Security patches are released through the following channels:
- GitHub repository
- Package updates
- Security advisories

Keep your installation updated to receive the latest security fixes.

## Contact

For urgent security matters: security@zencrypt.app

For general inquiries: https://zencrypt.gitbook.io/zencrypt

=======

For general inquiries: https://zencrypt.gitbook.io/zencrypt
