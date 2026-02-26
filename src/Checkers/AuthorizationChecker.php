<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;
use Symfony\Component\Finder\Finder;

class AuthorizationChecker extends BaseChecker
{
    private const SENSITIVE_PREFIXES = ['/admin', '/dashboard', '/management', '/api/admin'];
    private const AUTH_MIDDLEWARE    = ['auth', 'auth:sanctum', 'auth:api', 'verified'];

    public function check(string $path): array
    {
        $findings   = [];
        $routesPath = $path . '/routes';

        if (!is_dir($routesPath)) {
            return $findings;
        }

        $finder = new Finder();
        $finder->files()->name('*.php')->in($routesPath);

        foreach ($finder as $file) {
            $contents = $file->getContents();

            // If the file has a middleware group covering everything, skip analysis
            $hasGlobalAuthGroup = preg_match("/middleware\(\s*\[?\s*['\"]auth['\"].*\]\s*\)->group/", $contents);
            if ($hasGlobalAuthGroup) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNumber => $line) {
                // Look for route definitions
                if (!preg_match("/Route::(get|post|put|patch|delete|any)\s*\(\s*['\"]([^'\"]+)/", $line, $match)) {
                    continue;
                }

                $routePath = $match[2];

                // Check if the route path has sensitive prefixes
                $isSensitive = false;
                foreach (self::SENSITIVE_PREFIXES as $prefix) {
                    if (str_starts_with($routePath, $prefix)) {
                        $isSensitive = true;
                        break;
                    }
                }

                if (!$isSensitive) {
                    continue;
                }

                // Check if this line (or nearby context) has auth middleware
                $context = implode("\n", array_slice($lines, max(0, $lineNumber - 5), 10));
                $hasAuth = false;
                foreach (self::AUTH_MIDDLEWARE as $mw) {
                    if (str_contains($context, "'$mw'") || str_contains($context, "\"$mw\"")) {
                        $hasAuth = true;
                        break;
                    }
                }

                if (!$hasAuth) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: "Sensitive route '{$routePath}' may not have auth middleware",
                        recommendation: "Wrap inside Route::middleware(['auth'])->group() or add ->middleware('auth')",
                    );
                }
            }
        }

        return $findings;
    }
}
