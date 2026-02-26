<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\MaliciousFileChecker;
use PHPUnit\Framework\TestCase;

class MaliciousFileCheckerTest extends TestCase
{
    private MaliciousFileChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new MaliciousFileChecker();
    }

    public function test_flags_php_files_in_upload_directories(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/malicious');
        $this->assertNotEmpty($findings);
    }

    public function test_flags_webshell_signatures(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/malicious');
        $msgs = array_map(fn($f) => $f->message, $findings);
        $hasWebshell = count(array_filter($msgs, fn($m) =>
            str_contains($m, 'webshell') || str_contains($m, 'PHP file in upload')
        )) > 0;
        $this->assertTrue($hasWebshell);
    }

    public function test_does_not_flag_clean_directories(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/clean');
        $this->assertCount(0, $findings);
    }
}
