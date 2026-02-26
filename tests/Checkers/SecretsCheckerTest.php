<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\SecretsChecker;
use PHPUnit\Framework\TestCase;

class SecretsCheckerTest extends TestCase
{
    private SecretsChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new SecretsChecker();
    }

    public function test_flags_hardcoded_credentials(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $secretFindings = array_filter($findings, fn($f) => $f->checker === 'SecretsChecker');
        $this->assertNotEmpty($secretFindings);
    }

    public function test_flags_app_debug_true_in_env(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $msgs = array_map(fn($f) => $f->message, $findings);
        $this->assertTrue(
            count(array_filter($msgs, fn($m) => str_contains($m, 'APP_DEBUG'))) > 0
        );
    }

    public function test_does_not_flag_config_usage(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $secretFindings = array_filter($findings, fn($f) => $f->checker === 'SecretsChecker');
        $this->assertCount(0, $secretFindings);
    }
}
