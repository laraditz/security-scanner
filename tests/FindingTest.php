<?php

namespace Laraditz\SecurityScanner\Tests;

use Laraditz\SecurityScanner\Finding;
use PHPUnit\Framework\TestCase;

class FindingTest extends TestCase
{
    public function test_finding_stores_all_properties(): void
    {
        $finding = new Finding(
            severity: 'CRITICAL',
            checker: 'SqlInjectionChecker',
            file: 'app/Http/Controllers/UserController.php',
            line: 42,
            message: 'Raw query with string concatenation detected',
            recommendation: 'Use parameter binding instead',
        );

        $this->assertSame('CRITICAL', $finding->severity);
        $this->assertSame('SqlInjectionChecker', $finding->checker);
        $this->assertSame('app/Http/Controllers/UserController.php', $finding->file);
        $this->assertSame(42, $finding->line);
        $this->assertSame('Raw query with string concatenation detected', $finding->message);
        $this->assertSame('Use parameter binding instead', $finding->recommendation);
    }

    public function test_finding_allows_null_line(): void
    {
        $finding = new Finding(
            severity: 'HIGH',
            checker: 'SecretsChecker',
            file: '.env',
            line: null,
            message: 'APP_DEBUG is true',
            recommendation: 'Set APP_DEBUG=false in production',
        );

        $this->assertNull($finding->line);
    }

    public function test_finding_can_be_converted_to_array(): void
    {
        $finding = new Finding('HIGH', 'XssChecker', 'resources/views/user.blade.php', 10, 'Unescaped output', 'Use {{ }} instead');

        $array = $finding->toArray();

        $this->assertSame('HIGH', $array['severity']);
        $this->assertSame('XssChecker', $array['checker']);
    }
}
