<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\FileUploadChecker;
use PHPUnit\Framework\TestCase;

class FileUploadCheckerTest extends TestCase
{
    private FileUploadChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new FileUploadChecker();
    }

    public function test_flags_getclientoriginalname_usage(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $msgs = array_map(fn($f) => $f->message, $findings);
        $this->assertTrue(
            count(array_filter($msgs, fn($m) => str_contains($m, 'getClientOriginalName'))) > 0
        );
    }

    public function test_does_not_flag_validated_uploads(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $uploadFindings = array_filter($findings, fn($f) => $f->checker === 'FileUploadChecker');
        $this->assertCount(0, $uploadFindings);
    }
}
