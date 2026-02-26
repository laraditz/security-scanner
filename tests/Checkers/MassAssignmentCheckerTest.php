<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\MassAssignmentChecker;
use PHPUnit\Framework\TestCase;

class MassAssignmentCheckerTest extends TestCase
{
    private MassAssignmentChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new MassAssignmentChecker();
    }

    public function test_flags_empty_guarded(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/vulnerable');
        $msgs = array_map(fn($f) => $f->message, $findings);
        $this->assertTrue(
            count(array_filter($msgs, fn($m) => str_contains($m, 'guarded'))) > 0
        );
    }

    public function test_does_not_flag_models_with_fillable(): void
    {
        $findings = $this->checker->check(__DIR__ . '/../Fixtures/safe');
        $maFindings = array_filter($findings, fn($f) => $f->checker === 'MassAssignmentChecker');
        $this->assertCount(0, $maFindings);
    }
}
