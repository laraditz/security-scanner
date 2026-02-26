<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class FileUploadChecker extends BaseChecker
{
    public function check(string $path): array
    {
        $findings = [];
        $appPath  = is_dir($path . '/app') ? $path . '/app' : $path;

        foreach ($this->phpFiles($appPath) as $file) {
            $contents = $file->getContents();

            // Skip files that don't deal with file uploads
            if (!str_contains($contents, '->file(') && !str_contains($contents, 'hasFile(')) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNumber => $line) {
                // Flag getClientOriginalName — path traversal risk
                if (str_contains($line, 'getClientOriginalName()')) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: 'getClientOriginalName() used — attacker can craft malicious filenames (path traversal)',
                        recommendation: 'Use a random filename: Str::uuid() or $file->hashName()',
                    );
                }

                // Flag storing in public/ directly
                if (str_contains($line, 'public_path(') && str_contains($line, 'move(')) {
                    $findings[] = new Finding(
                        severity: 'CRITICAL',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: 'File moved directly into public/ — uploaded files are web-accessible',
                        recommendation: 'Store files outside public/ using Storage::disk("private")->put()',
                    );
                }

                // Flag extension-only validation
                if (str_contains($line, 'getClientOriginalExtension()')) {
                    $findings[] = new Finding(
                        severity: 'HIGH',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: $lineNumber + 1,
                        message: 'Extension-only validation — MIME type can be spoofed',
                        recommendation: 'Use Laravel validation with mimes: or mimetypes: rules',
                    );
                }
            }
        }

        return $findings;
    }
}
