<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;
use Symfony\Component\Finder\Finder;

class RateLimitChecker extends BaseChecker
{
    private const SENSITIVE_ROUTES = ['/login', '/register', '/forgot-password', '/password/reset', '/password/email'];

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
            $lines    = explode("\n", $contents);

            foreach ($lines as $lineNumber => $line) {
                if (!preg_match("/Route::(post|get)\s*\(\s*['\"]([^'\"]+)/", $line, $match)) {
                    continue;
                }

                $routePath = $match[2];

                $isSensitive = false;
                foreach (self::SENSITIVE_ROUTES as $sensitive) {
                    if (str_contains($routePath, ltrim($sensitive, '/'))) {
                        $isSensitive = true;
                        break;
                    }
                }

                if (!$isSensitive) {
                    continue;
                }

                // Check context for throttle middleware
                $context     = implode("\n", array_slice($lines, max(0, $lineNumber - 5), 10));
                $hasThrottle = str_contains($context, 'throttle');

                if (!$hasThrottle) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: "Route '{$routePath}' has no rate limiting — vulnerable to brute force attacks",
                        recommendation: "Add throttle middleware: Route::middleware(['throttle:10,1'])->group()",
                    );
                }
            }
        }

        return $findings;
    }
}
