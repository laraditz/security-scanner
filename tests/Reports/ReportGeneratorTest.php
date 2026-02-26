<?php

namespace Laraditz\SecurityScanner\Tests\Reports;

use Laraditz\SecurityScanner\Finding;
use Laraditz\SecurityScanner\Reports\ReportGenerator;
use PHPUnit\Framework\TestCase;

class ReportGeneratorTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/scanner_test_' . uniqid();
        mkdir($this->tmpDir);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob("{$this->tmpDir}/*"));
        rmdir($this->tmpDir);
    }

    public function test_saves_json_report(): void
    {
        $findings = [
            new Finding('HIGH', 'XssChecker', 'views/user.blade.php', 10, 'Unescaped', 'Use {{ }}'),
        ];

        $generator = new ReportGenerator($findings, [], $this->tmpDir);
        $paths = $generator->save('2026-02-26');

        $this->assertFileExists($paths['json']);
        $data = json_decode(file_get_contents($paths['json']), true);
        $this->assertCount(1, $data['findings']);
        $this->assertSame('HIGH', $data['findings'][0]['severity']);
    }

    public function test_saves_html_report(): void
    {
        $findings = [
            new Finding('CRITICAL', 'SqlInjectionChecker', 'app/Http/UserController.php', 42, 'Raw query', 'Use bindings'),
        ];

        $generator = new ReportGenerator($findings, [], $this->tmpDir);
        $paths = $generator->save('2026-02-26');

        $this->assertFileExists($paths['html']);
        $html = file_get_contents($paths['html']);
        $this->assertStringContainsString('CRITICAL', $html);
        $this->assertStringContainsString('SqlInjectionChecker', $html);
    }
}
