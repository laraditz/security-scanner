<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class SecretsChecker extends BaseChecker
{
    private const SECRET_PATTERNS = [
        "/(?:password|passwd|pwd)\\s*=\\s*[\"'][^\"']{6,}[\"']/",
        "/(?:api_?key|apikey|api_?secret)\\s*=\\s*[\"'][^\"']{10,}[\"']/",
        "/(?:secret|token|auth_?key)\\s*=\\s*[\"'][^\"']{10,}[\"']/",
        '/sk_live_[a-zA-Z0-9]+/',
        '/sk-live-[a-zA-Z0-9]+/',
        '/AKIA[0-9A-Z]{16}/',  // AWS access key
    ];

    public function check(string $path): array
    {
        $findings = [];

        // Check PHP files for hardcoded secrets
        $appPath = is_dir($path . '/app') ? $path . '/app' : $path;
        foreach ($this->phpFiles($appPath) as $file) {
            $lines = explode("\n", $file->getContents());
            foreach ($lines as $lineNumber => $line) {
                // Skip lines that use config() or env() - those are safe
                if (str_contains($line, 'config(') || str_contains($line, 'env(')) {
                    continue;
                }

                foreach (self::SECRET_PATTERNS as $pattern) {
                    if (preg_match($pattern, $line)) {
                        $findings[] = new Finding(
                            severity: 'CRITICAL',
                            checker: $this->checkerName(),
                            file: $file->getPathname(),
                            line: $lineNumber + 1,
                            message: 'Hardcoded secret or credential detected',
                            recommendation: 'Move to .env and access via config() or env()',
                        );
                        break;
                    }
                }
            }
        }

        // Check .env for dangerous settings
        $envFile = $path . '/.env';
        if (file_exists($envFile)) {
            $envContents = file_get_contents($envFile);

            if (preg_match('/APP_DEBUG\s*=\s*true/i', $envContents)) {
                $findings[] = new Finding(
                    severity: 'CRITICAL',
                    checker: $this->checkerName(),
                    file: $envFile,
                    line: null,
                    message: 'APP_DEBUG=true exposes stack traces and sensitive data to users',
                    recommendation: 'Set APP_DEBUG=false in production',
                );
            }
        }

        return $findings;
    }
}
