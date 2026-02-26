<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\XssChecker;
use PHPUnit\Framework\TestCase;

class XssCheckerTest extends TestCase
{
    private XssChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new XssChecker();
    }

    public function test_flags_unescaped_blade_output(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $this->assertNotEmpty($findings);
        $this->assertSame('XssChecker', $findings[0]->checker);
    }

    public function test_does_not_flag_escaped_blade_output(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $xssFindings = array_filter($findings, fn($f) => $f->checker === 'XssChecker');
        $this->assertCount(0, $xssFindings);
    }
}
