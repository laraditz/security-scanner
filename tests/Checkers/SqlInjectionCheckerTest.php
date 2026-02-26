<?php

namespace Laraditz\SecurityScanner\Tests\Checkers;

use Laraditz\SecurityScanner\Checkers\SqlInjectionChecker;
use PHPUnit\Framework\TestCase;

class SqlInjectionCheckerTest extends TestCase
{
    private SqlInjectionChecker $checker;
    private string $vulnerableDir;
    private string $safeDir;

    protected function setUp(): void
    {
        $this->checker       = new SqlInjectionChecker();
        $this->vulnerableDir = __DIR__ . '/../Fixtures/vulnerable';
        $this->safeDir       = __DIR__ . '/../Fixtures/safe';
    }

    public function test_flags_string_concatenation_in_db_select(): void
    {
        $findings = $this->checker->check($this->vulnerableDir);
        $messages = array_column(array_map(fn($f) => $f->toArray(), $findings), 'message');

        $this->assertTrue(
            count(array_filter($messages, fn($m) => str_contains($m, 'DB::select'))) > 0,
            'Expected SqlInjectionChecker to flag DB::select with concatenation'
        );
    }

    public function test_flags_db_unprepared(): void
    {
        $findings = $this->checker->check($this->vulnerableDir);
        $messages = array_column(array_map(fn($f) => $f->toArray(), $findings), 'message');

        $this->assertTrue(
            count(array_filter($messages, fn($m) => str_contains($m, 'unprepared'))) > 0,
            'Expected SqlInjectionChecker to flag DB::unprepared'
        );
    }

    public function test_does_not_flag_safe_code(): void
    {
        $findings = $this->checker->check($this->safeDir);

        $sqlFindings = array_filter($findings, fn($f) => $f->checker === 'SqlInjectionChecker');

        $this->assertCount(0, $sqlFindings, 'Expected no findings on safe code');
    }
}
