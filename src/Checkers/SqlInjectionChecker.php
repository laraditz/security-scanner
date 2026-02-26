<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class SqlInjectionChecker extends BaseChecker
{
    private const DANGEROUS_METHODS = [
        'DB::statement', 'DB::select', 'DB::insert', 'DB::update', 'DB::delete',
        'whereRaw', 'orWhereRaw', 'orderByRaw', 'groupByRaw', 'havingRaw', 'selectRaw',
    ];

    public function check(string $path): array
    {
        $findings = [];
        $appPath  = $path . '/app';

        foreach ($this->phpFiles(is_dir($appPath) ? $appPath : $path) as $file) {
            $contents = $file->getContents();
            $lines    = explode("\n", $contents);

            foreach ($lines as $lineNumber => $line) {
                // Flag DB::unprepared always
                if (str_contains($line, 'DB::unprepared(')) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: 'DB::unprepared() bypasses query binding entirely',
                        recommendation: 'Replace with a prepared statement using DB::statement() with bindings',
                    );
                    continue;
                }

                // Flag dangerous methods with string concatenation or variable interpolation
                foreach (self::DANGEROUS_METHODS as $method) {
                    if (!str_contains($line, $method . '(')) {
                        continue;
                    }

                    // Look for string concatenation (. $var) or interpolation ($var inside quotes)
                    if (preg_match('/\.\s*\$\w+/', $line) || preg_match('/"[^"]*\$\w+[^"]*"/', $line)) {
                        $findings[] = new Finding(
                            severity: 'CRITICAL',
                            checker: $this->checkerName(),
                            file: $file->getPathname(),
                            line: $lineNumber + 1,
                            message: "Potential SQL injection: {$method}() called with string concatenation or interpolation",
                            recommendation: 'Use parameter binding: pass an array of values as the second argument',
                        );
                    }
                }
            }
        }

        return $findings;
    }
}
