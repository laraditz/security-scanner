# Checkers Reference

Each checker runs independently against your Laravel application's source tree. They do not execute your code — everything is static analysis of file contents.

---

## SqlInjectionChecker

**Severity:** CRITICAL (concatenation/interpolation) · HIGH (unprepared)

Detects raw database queries that embed user-controlled values via string concatenation or variable interpolation, making them vulnerable to SQL injection attacks.

### What is flagged

- `DB::select()`, `DB::statement()`, `DB::insert()`, `DB::update()`, `DB::delete()` called with `. $var` or `"$var"` patterns
- `whereRaw()`, `orWhereRaw()`, `orderByRaw()`, `groupByRaw()`, `havingRaw()`, `selectRaw()` with concatenated strings
- Any use of `DB::unprepared()` (flagged unconditionally — it bypasses binding entirely)

### Vulnerable

```php
// String concatenation — CRITICAL
DB::select("SELECT * FROM users WHERE name = '" . $name . "'");

// Variable interpolation — CRITICAL
DB::statement("DELETE FROM logs WHERE message = '$term'");

// whereRaw with concatenation — CRITICAL
User::whereRaw("status = '" . $status . "'")->get();

// DB::unprepared — always HIGH
DB::unprepared("TRUNCATE TABLE cache");
```

### Safe

```php
// Positional binding
DB::select("SELECT * FROM users WHERE name = ?", [$name]);

// Named binding
DB::select("SELECT * FROM logs WHERE message = :term", ['term' => $term]);

// Eloquent — safe by default
User::where('status', $status)->get();
```

---

## XssChecker

**Severity:** HIGH

Scans Blade templates for unescaped output (`{!! !!}`) that is not wrapped in a known sanitizer, which may allow attackers to inject JavaScript into pages.

### What is flagged

Any `{!! $expression !!}` that does not contain one of: `e()`, `htmlspecialchars()`, `Purifier::`, `clean()`

### Vulnerable

```blade
{!! $userInput !!}
{!! $comment->body !!}
<p>{!! request('name') !!}</p>
```

### Safe

```blade
{{-- Auto-escaped (preferred) --}}
{{ $userInput }}

{{-- Explicit escape when HTML output is needed --}}
{!! e($userInput) !!}
{!! nl2br(e($userInput)) !!}

{{-- HTML Purifier for rich content --}}
{!! Purifier::clean($userInput) !!}
```

---

## MassAssignmentChecker

**Severity:** HIGH (`$guarded = []`) · MEDIUM (neither defined)

Detects Eloquent models that are fully open to mass assignment, which can allow attackers to set sensitive fields (e.g. `is_admin`, `role`) via `create()` or `fill()`.

### What is flagged

- Models with `protected $guarded = []` — every attribute is mass-assignable
- Models that extend `Model` but define neither `$fillable` nor `$guarded`

### Vulnerable

```php
class User extends Model
{
    protected $guarded = []; // Everything is fillable
}

class Post extends Model
{
    // No $fillable or $guarded — risky
}
```

### Safe

```php
class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
}

class Post extends Model
{
    protected $guarded = ['id', 'user_id', 'is_published'];
}
```

---

## SecretsChecker

**Severity:** CRITICAL

Detects hardcoded credentials and API keys in PHP source files, and dangerous settings in `.env` files.

### What is flagged

**In PHP files** (lines not using `config()` or `env()` are scanned):
- `password`, `passwd`, `pwd` assigned a string literal ≥ 6 characters
- `api_key`, `apikey`, `api_secret` assigned a string ≥ 10 characters
- `secret`, `token`, `auth_key` assigned a string ≥ 10 characters
- Stripe live keys: `sk_live_*` or `sk-live-*`
- AWS access key IDs: `AKIA[A-Z0-9]{16}`

**In `.env` files:**
- `APP_DEBUG=true`

### Vulnerable

```php
class ApiClient
{
    private $apiKey = "sk-live-abc123secretkey9999";
    private $stripeKey = "sk_live_realkey123";
    private $dbPassword = "SuperSecret123!";
}
```

```ini
# .env
APP_DEBUG=true
```

### Safe

```php
class ApiClient
{
    public function __construct()
    {
        $this->apiKey = config('services.api.key');  // Read from config
        $this->stripe = env('STRIPE_SECRET');         // Read from environment
    }
}
```

```ini
# .env
APP_DEBUG=false
```

---

## FileUploadChecker

**Severity:** CRITICAL (public storage) · HIGH (original name / extension-only)

Detects common file upload vulnerabilities: using the original client-supplied filename (path traversal), storing files in a web-accessible directory, and validating only the file extension (which can be spoofed).

### What is flagged

- `getClientOriginalName()` — attacker controls the filename
- `->move(public_path(...), ...)` — file is served directly from the web root
- `getClientOriginalExtension()` — extension alone does not verify file type

### Vulnerable

```php
// Path traversal risk
$name = $request->file('avatar')->getClientOriginalName();
$request->file('avatar')->move(public_path('uploads'), $name);

// MIME spoofing
$ext = $request->file('doc')->getClientOriginalExtension();
if (in_array($ext, ['pdf', 'doc'])) { ... }
```

### Safe

```php
$request->validate([
    'avatar' => 'required|file|mimes:jpg,png,gif|max:2048',
    'doc'    => 'required|file|mimetypes:application/pdf|max:10240',
]);

// Random name, private disk
$path = $request->file('avatar')->store('avatars', 'private');

// Or explicit random name
$path = $request->file('avatar')->storeAs('avatars', Str::uuid(), 'private');
```

---

## MaliciousFileChecker

**Severity:** CRITICAL

Scans upload directories and the `public/` folder for PHP files that should not be there, and checks their contents for known webshell signatures.

### What is flagged

**PHP files in upload directories** (`public/uploads`, `public/storage`, `storage/app/public`, `uploads`):
- Any file with a PHP-executable extension: `.php`, `.phtml`, `.php3`–`.php7`, `.phar`, `.shtml`

**Webshell signatures** (in PHP files inside `public/`):
- `eval(base64_decode(`, `eval(gzinflate(`, `eval(str_rot13(`
- `system($_GET`, `system($_POST`, `passthru($_GET/POST`
- `exec($_GET/POST`, `shell_exec($_GET/POST`
- `assert($_GET`
- `FilesMan` (common webshell identifier)

### Why this matters

A PHP webshell in an upload directory means an attacker has already achieved remote code execution on your server. This checker helps detect compromised files during routine security audits or incident response.

### Remediation

If a webshell is detected:
1. Take the server offline or isolate it immediately
2. Remove the malicious files
3. Rotate **all** credentials (database, API keys, environment variables)
4. Review web server and application access logs
5. Determine the upload vulnerability that allowed the file to be placed

---

## AuthorizationChecker

**Severity:** HIGH

Scans route files for routes under sensitive URL prefixes (`/admin`, `/dashboard`, `/management`, `/api/admin`) that appear to lack `auth` middleware.

### What is flagged

Routes matching a sensitive prefix where neither the route definition line nor the 5 surrounding lines contain an auth middleware reference (`auth`, `auth:sanctum`, `auth:api`, `verified`).

### Vulnerable

```php
// routes/web.php
Route::get('/admin/users', [AdminController::class, 'index']);
Route::post('/admin/users/{id}/delete', [AdminController::class, 'destroy']);
```

### Safe

```php
// Middleware group (entire group is skipped from flagging)
Route::middleware(['auth'])->group(function () {
    Route::get('/admin/users', [AdminController::class, 'index']);
    Route::post('/admin/users/{id}/delete', [AdminController::class, 'destroy']);
});

// Or inline
Route::get('/admin/users', [AdminController::class, 'index'])->middleware('auth');
```

---

## CsrfChecker

**Severity:** CRITICAL (`/api/*`) · HIGH (other wildcards)

Scans `app/Http/Middleware/VerifyCsrfToken.php` for wildcard entries in the `$except` array that bypass CSRF protection for large portions of the application.

### What is flagged

- Any `$except` entry containing a `*` wildcard
- Specifically `/api/*` is flagged at CRITICAL severity

### Vulnerable

```php
class VerifyCsrfToken extends Middleware
{
    protected $except = [
        '/api/*',        // CRITICAL: all API routes unprotected
        '/admin/import', // Specific route — acceptable
    ];
}
```

### Safe

```php
class VerifyCsrfToken extends Middleware
{
    protected $except = [
        '/webhook/stripe',   // Specific webhook — legitimate
        '/webhook/github',
    ];
}
```

> **Note:** Webhooks from third-party services legitimately need to bypass CSRF because they cannot send a CSRF token. Always list specific paths rather than wildcards.

---

## RateLimitChecker

**Severity:** HIGH

Scans route files for authentication-related routes (`/login`, `/register`, `/forgot-password`, `/password/reset`) that do not have `throttle` middleware, leaving them open to brute-force attacks.

### What is flagged

Routes whose path contains a sensitive keyword and whose surrounding 10-line context does not contain the string `throttle`.

### Vulnerable

```php
// routes/web.php or routes/auth.php
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
```

### Safe

```php
Route::middleware(['throttle:10,1'])->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
});
```

The `throttle:10,1` limit means 10 requests per minute per IP. Adjust to suit your application's needs.

---

## Writing a custom checker

Extend `BaseChecker` and implement `check(string $path): array`:

```php
<?php

namespace App\Security\Checkers;

use Laraditz\SecurityScanner\Checkers\BaseChecker;
use Laraditz\SecurityScanner\Finding;

class WeakCryptoChecker extends BaseChecker
{
    public function check(string $path): array
    {
        $findings = [];

        foreach ($this->phpFiles($path . '/app') as $file) {
            $lines = explode("\n", $file->getContents());

            foreach ($lines as $i => $line) {
                if (preg_match('/\bmd5\s*\(|\bsha1\s*\(/', $line)) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $i + 1,
                        message: 'Weak hashing function (md5/sha1) detected',
                        recommendation: 'Use bcrypt() or Hash::make() for passwords',
                    );
                }
            }
        }

        return $findings;
    }
}
```

Then register it in your own Artisan command or extend `SecurityScanCommand` to add it to the scanner:

```php
$scanner->addChecker(new WeakCryptoChecker());
```

Helper methods available from `BaseChecker`:

| Method | Returns | Description |
|--------|---------|-------------|
| `phpFiles(string $dir)` | `SplFileInfo[]` | All `.php` files recursively under `$dir` |
| `bladeFiles(string $dir)` | `SplFileInfo[]` | All `.blade.php` files recursively under `$dir` |
| `checkerName()` | `string` | Short class name, used as the `checker` field in findings |
