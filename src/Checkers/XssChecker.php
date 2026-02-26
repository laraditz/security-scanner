<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class XssChecker extends BaseChecker
{
    // Safe patterns: {!! e($var) !!}, {!! nl2br(e($var)) !!}, {!! Purifier::clean($var) !!}, {!! clean($var) !!}
    private const SAFE_PATTERNS = ['/e\(/', '/Purifier::/', '/clean\(/', '/htmlspecialchars\(/'];

    public function check(string $path): array
    {
        $findings     = [];
        $resourcePath = $path . '/resources';
        $searchPath   = is_dir($resourcePath) ? $resourcePath : $path;

        foreach ($this->bladeFiles($searchPath) as $file) {
            $lines = explode("\n", $file->getContents());

            foreach ($lines as $lineNumber => $line) {
                if (!preg_match('/\{!!\s*.+\s*!!\}/', $line)) {
                    continue;
                }

                // Check if a known safe sanitizer is used
                $isSafe = false;
                foreach (self::SAFE_PATTERNS as $pattern) {
                    if (preg_match($pattern, $line)) {
                        $isSafe = true;
                        break;
                    }
                }

                if (!$isSafe) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: 'Unescaped output {!! !!} without sanitization — potential XSS',
                        recommendation: 'Use {{ $var }} for auto-escaping, or {!! e($var) !!} if HTML is required',
                    );
                }
            }
        }

        return $findings;
    }
}
