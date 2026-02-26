<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\AuthorizationChecker;
use PHPUnit\Framework\TestCase;

class AuthorizationCheckerTest extends TestCase
{
    private AuthorizationChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new AuthorizationChecker();
    }

    public function test_flags_admin_routes_without_auth_middleware(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $authFindings = array_filter($findings, fn($f) => $f->checker === 'AuthorizationChecker');
        $this->assertNotEmpty($authFindings);
    }

    public function test_does_not_flag_routes_inside_auth_middleware_group(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $authFindings = array_filter($findings, fn($f) => $f->checker === 'AuthorizationChecker');
        $this->assertCount(0, $authFindings);
    }
}
