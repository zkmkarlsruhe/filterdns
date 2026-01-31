# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in FilterDNS, please report it responsibly.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email security issues to: **security@zkm.de** (or use GitHub's private vulnerability reporting)
3. Include details of the vulnerability
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment of your report within 48 hours
- Regular updates on the progress of addressing the issue
- Credit in the security advisory (if desired)

## Security Considerations

### Authentication

- Admin passwords must be at least 8 characters (12+ recommended)
- Weak/common passwords are rejected with warnings
- Profile passwords are hashed with bcrypt
- Session tokens expire after 1 hour

### Network Security

- Use TLS certificates for production deployments (DoH/DoT)
- Configure firewall rules to restrict access to admin endpoints
- Consider running behind a reverse proxy (nginx, Caddy, Traefik)

### Environment Variables

Never commit sensitive values. Use environment variables for:
- `FILTERDNS_ADMIN_PASSWORD`
- `DATABASE_URL` (if contains credentials)
- TLS certificate paths

### Rate Limiting

Built-in rate limiting protects against:
- Admin login brute force (5 attempts per 5 minutes)
- Profile creation abuse (30 requests per minute)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Updates

Security patches will be released as soon as possible after a vulnerability is confirmed. We recommend always running the latest version.
