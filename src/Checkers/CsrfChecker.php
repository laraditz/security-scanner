<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class CsrfChecker extends BaseChecker
{
    public function check(string $path): array
    {
        $findings   = [];
        $middleware = $path . '/app/Http/Middleware/VerifyCsrfToken.php';

        if (!file_exists($middleware)) {
            return $findings;
        }

        $contents = file_get_contents($middleware);
        $lines    = explode("\n", $contents);

        foreach ($lines as $lineNumber => $line) {
            // Flag wildcard exceptions (e.g. '/api/*')
            if (preg_match('/["\'][^"\']*\*[^"\']*["\']/', $line)) {
                $findings[] = new Finding(
                    severity: 'HIGH',
                    checker: $this->checkerName(),
                    file: $middleware,
                    line: $lineNumber + 1,
                    message: 'Wildcard CSRF exception found — large portions of your app are unprotected',
                    recommendation: 'List specific routes in $except instead of using wildcards',
                );

                // Flag /api/* specifically at a higher severity
                if (preg_match('/["\']\/api\/?[^"\']*\*["\']/', $line)) {
                    $findings[] = new Finding(
                        severity: 'CRITICAL',
                        checker: $this->checkerName(),
                        file: $middleware,
                        line: $lineNumber + 1,
                        message: 'All /api/* routes are exempt from CSRF — stateful API routes are vulnerable',
                        recommendation: 'Use Sanctum for API auth which handles CSRF properly, or list specific routes',
                    );
                }
            }
        }

        return $findings;
    }
}
