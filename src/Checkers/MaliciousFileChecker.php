<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;
use Symfony\Component\Finder\Finder;

class MaliciousFileChecker extends BaseChecker
{
    private const WEBSHELL_SIGNATURES = [
        'eval(base64_decode(',
        'eval(gzinflate(',
        'eval(str_rot13(',
        'system($_GET',
        'system($_POST',
        'passthru($_GET',
        'passthru($_POST',
        'exec($_GET',
        'exec($_POST',
        'shell_exec($_GET',
        'shell_exec($_POST',
        'assert($_GET',
        "preg_replace('/.*/e'",
        'FilesMan',
    ];

    private const DANGEROUS_EXTENSIONS = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'shtml'];

    private const UPLOAD_DIRECTORIES = ['public/uploads', 'public/storage', 'storage/app/public', 'uploads'];

    public function check(string $path): array
    {
        $findings = [];
        $path = rtrim(str_replace('\\', '/', realpath($path) ?: $path), '/');

        foreach (self::UPLOAD_DIRECTORIES as $uploadDir) {
            $fullPath = $path . '/' . $uploadDir;

            if (!is_dir($fullPath)) {
                continue;
            }

            $finder = new Finder();
            $finder->files()->in($fullPath);

            foreach ($finder as $file) {
                $ext = strtolower($file->getExtension());

                // Flag PHP files in upload directories
                if (in_array($ext, self::DANGEROUS_EXTENSIONS)) {
                    $findings[] = new Finding(
                        severity: 'CRITICAL',
                        checker: $this->checkerName(),
                        file: $file->getPathname(),
                        line: null,
                        message: "PHP file in upload directory: {$uploadDir}",
                        recommendation: 'Remove this file immediately and investigate — this may be a webshell',
                    );

                    // Also scan the PHP file for webshell signatures
                    $contents = $file->getContents();
                    foreach (self::WEBSHELL_SIGNATURES as $signature) {
                        if (str_contains($contents, $signature)) {
                            $findings[] = new Finding(
                                severity: 'CRITICAL',
                                checker: $this->checkerName(),
                                file: $file->getPathname(),
                                line: null,
                                message: "Webshell signature detected: {$signature}",
                                recommendation: 'URGENT: Remove this file, rotate all credentials, and audit server access logs',
                            );
                        }
                    }
                }
            }
        }

        // Also scan entire public/ for PHP files with webshell signatures
        $publicPath = $path . '/public';
        if (is_dir($publicPath)) {
            foreach ($this->phpFiles($publicPath) as $file) {
                $contents = $file->getContents();
                foreach (self::WEBSHELL_SIGNATURES as $signature) {
                    if (str_contains($contents, $signature)) {
                        $findings[] = new Finding(
                            severity: 'CRITICAL',
                            checker: $this->checkerName(),
                            file: $file->getPathname(),
                            line: null,
                            message: "Webshell signature detected in public directory: {$signature}",
                            recommendation: 'URGENT: Remove this file, rotate all credentials, and audit server access logs',
                        );
                    }
                }
            }
        }

        return $findings;
    }
}
