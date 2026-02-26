<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\RateLimitChecker;
use PHPUnit\Framework\TestCase;

class RateLimitCheckerTest extends TestCase
{
    private RateLimitChecker $checker;

    protected function setUp(): void { $this->checker = new RateLimitChecker(); }

    public function test_flags_login_routes_without_throttle(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $rlFindings = array_filter($findings, fn($f) => $f->checker === 'RateLimitChecker');
        $this->assertNotEmpty($rlFindings);
    }

    public function test_does_not_flag_throttled_routes(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $rlFindings = array_filter($findings, fn($f) => $f->checker === 'RateLimitChecker');
        $this->assertCount(0, $rlFindings);
    }
}
