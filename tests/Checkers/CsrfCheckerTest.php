<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\CsrfChecker;
use PHPUnit\Framework\TestCase;

class CsrfCheckerTest extends TestCase
{
    private CsrfChecker $checker;

    protected function setUp(): void { $this->checker = new CsrfChecker(); }

    public function test_flags_wildcard_csrf_exceptions(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $csrfFindings = array_filter($findings, fn($f) => $f->checker === 'CsrfChecker');
        $this->assertNotEmpty($csrfFindings);
    }

    public function test_does_not_flag_specific_webhook_exceptions(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $csrfFindings = array_filter($findings, fn($f) => $f->checker === 'CsrfChecker');
        $this->assertCount(0, $csrfFindings);
    }
}
