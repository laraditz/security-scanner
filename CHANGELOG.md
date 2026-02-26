# Changelog

All notable changes to `laraditz/security-scanner` will be documented in this file

## 1.0.0 - 2026-02-26

### Added
- Initial release of the Laravel security vulnerability scanner package
- `security:scan` Artisan command with `--path` and `--output` options
- `Scanner` engine with error-resilient multi-checker execution
- `Finding` value object to represent individual vulnerabilities
- **Checkers:**
  - `SqlInjectionChecker` — detects raw SQL injection patterns
  - `XssChecker` — detects unescaped output and XSS vulnerabilities
  - `MassAssignmentChecker` — detects missing `$fillable`/`$guarded` guards
  - `SecretsChecker` — detects hardcoded secrets and credentials
  - `FileUploadChecker` — detects unsafe file upload handling
  - `MaliciousFileChecker` — detects execution of potentially malicious files
  - `AuthorizationChecker` — detects missing authorization checks
  - `CsrfChecker` — detects missing CSRF protection
  - `RateLimitChecker` — detects missing rate limiting on sensitive routes
- **Report generators:** terminal (colored), JSON, and HTML output formats
- `SecurityScannerServiceProvider` with auto-discovery support
- GitHub Actions CI pipeline for PHP 8.2–8.4 and Laravel 11–12
