# Security (OWASP Top 10) and Production Checklist

This document summarizes the OWASP Top 10–related review and fixes applied, and lists production recommendations.

---

## OWASP Top 10 – Summary

| Category | Status | Notes |
|----------|--------|--------|
| **A01 – Broken Access Control** | Addressed | `upload_writeup_image` now requires `@login_required`; CSRF restored on `save_node_position` (frontend already sends token). Protected media served only to authorized users. |
| **A02 – Cryptographic Failures** | Addressed | `SECRET_KEY` from env; cookies `HttpOnly` and `SameSite=Lax`. For production, enable `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` and use HTTPS. |
| **A03 – Injection** | Addressed | ORM used for DB; Bleach for HTML in CKEditor; report content escaped. No raw SQL with user input. |
| **A04 – Insecure Design** | Addressed | File uploads: allowed extensions and size limits; path traversal prevented (safe filenames, zip slip–safe restore). |
| **A05 – Security Misconfiguration** | Addressed | `DEBUG` and `ALLOWED_HOSTS` read from environment (see below). Security headers and cookie settings already in place. |
| **A06 – Vulnerable Components** | Your responsibility | Keep dependencies updated (`pip list --outdated`, upgrade Django and apps). |
| **A07 – Auth Failures** | Partially addressed | Strong password validators enabled. Consider rate limiting on login (e.g. `django-ratelimit` or WAF) for production. |
| **A08 – Software/Data Integrity** | Addressed | Backup restore validates zip paths (Zip Slip prevention). No unsigned/unverified external scripts in critical flows. |
| **A09 – Logging/Monitoring** | Your responsibility | In production, disable `DEBUG`, use proper logging and (optionally) monitoring/alerting. |
| **A10 – SSRF** | Low risk | External image fetch in writeups is limited; consider allowlisting or disabling in sensitive deployments. |

---

## Fixes Applied in Code

- **Settings**: `DEBUG` and `ALLOWED_HOSTS` are driven by environment variables so production can run with `DEBUG=False` and explicit hosts.
- **CSRF**: Removed `@csrf_exempt` from `save_node_position` (graph map already sends `X-CSRFToken`). Removed `@csrf_exempt` from `upload_writeup_image` and added `@login_required`.
- **Upload security**: `upload_writeup_image` now validates file type (allowed image extensions), max size (5 MB), and uses a safe filename (no path traversal). `import_attack_narrative` restricts to `.md` and uses a safe basename.
- **Zip Slip**: Backup restore extracts zip entries only under the intended directory; paths are resolved and checked before extraction.
- **Admin**: Removed misleading `@csrf_exempt` from the report button (display only); the actual report view uses normal CSRF.

---

## Production Checklist

Before deploying to production:

1. **Environment**
   - Set `DJANGO_DEBUG=0` (or `False`).
   - Set `DJANGO_ALLOWED_HOSTS` to your domain(s), e.g. `yourdomain.com,www.yourdomain.com`.
   - Set `DJANGO_SECRET_KEY` to a long, random value (do not use the dev default).

2. **HTTPS and cookies**
   - In `settings.py`, uncomment and enable:
     - `SESSION_COOKIE_SECURE = True`
     - `CSRF_COOKIE_SECURE = True`
     - `SECURE_SSL_REDIRECT = True`
     - HSTS-related settings (`SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD`).

3. **Static/Media**
   - Run `collectstatic` and serve static (and optionally media) via the reverse proxy (e.g. Nginx), not Django in production.

4. **Database**
   - Prefer a dedicated DB (e.g. PostgreSQL) and strong credentials; avoid default SQLite in production if you need concurrency and backups.

5. **Logging and errors**
   - Ensure `DEBUG = False` so error pages and stack traces are not exposed. Configure `LOGGING` to write to files or a logging service.

6. **Optional**
   - Rate limit login and/or sensitive endpoints.
   - Use a WAF or reverse proxy rules to limit abuse.
   - Regular dependency updates and security advisories (e.g. `pip audit` or similar).

---

## Quick reference – env vars (production)

```bash
export DJANGO_DEBUG=0
export DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
export DJANGO_SECRET_KEY=<generate-a-long-random-secret>
```

Then enable the HTTPS and HSTS options in `VulnerabilityManager/settings.py` as described above.
