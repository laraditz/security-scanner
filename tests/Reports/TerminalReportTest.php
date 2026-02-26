<?php

namespace Laraditz\SecurityScanner\Tests\Reports;

use Laraditz\SecurityScanner\Finding;
use Laraditz\SecurityScanner\Reports\TerminalReport;
use PHPUnit\Framework\TestCase;

class TerminalReportTest extends TestCase
{
    public function test_generates_summary_grouped_by_severity(): void
    {
        $findings = [
            new Finding('CRITICAL', 'SqlChecker', 'app/Http/UserController.php', 42, 'Raw query', 'Use bindings'),
            new Finding('HIGH',     'XssChecker', 'resources/views/user.blade.php', 5, 'Unescaped output', 'Use {{ }}'),
            new Finding('CRITICAL', 'SecretsChecker', '.env', null, 'Debug mode on', 'Set APP_DEBUG=false'),
        ];

        $report = new TerminalReport($findings, []);
        $summary = $report->getSummary();

        $this->assertSame(2, $summary['CRITICAL']);
        $this->assertSame(1, $summary['HIGH']);
        $this->assertSame(0, $summary['MEDIUM']);
        $this->assertSame(0, $summary['LOW']);
    }

    public function test_generates_lines_for_each_finding(): void
    {
        $findings = [
            new Finding('HIGH', 'XssChecker', 'views/user.blade.php', 10, 'Unescaped output', 'Use {{ }}'),
        ];

        $report = new TerminalReport($findings, []);
        $lines = $report->getLines();

        $this->assertNotEmpty($lines);
        $this->assertTrue(collect($lines)->contains(fn($l) => str_contains($l, 'XssChecker')));
        $this->assertTrue(collect($lines)->contains(fn($l) => str_contains($l, 'views/user.blade.php')));
    }
}
