<?php

namespace Laraditz\SecurityScanner\Tests;

use Laraditz\SecurityScanner\Checkers\BaseChecker;
use Laraditz\SecurityScanner\Finding;
use Laraditz\SecurityScanner\Scanner;
use PHPUnit\Framework\TestCase;

class ScannerTest extends TestCase
{
    public function test_scanner_collects_findings_from_all_checkers(): void
    {
        $checker1 = new class extends BaseChecker {
            public function check(string $path): array {
                return [new Finding('HIGH', 'Checker1', 'file.php', 1, 'msg', 'fix')];
            }
        };

        $checker2 = new class extends BaseChecker {
            public function check(string $path): array {
                return [new Finding('LOW', 'Checker2', 'file2.php', 2, 'msg2', 'fix2')];
            }
        };

        $scanner = new Scanner();
        $scanner->addChecker($checker1)->addChecker($checker2);

        $findings = $scanner->run('/some/path');

        $this->assertCount(2, $findings);
        $this->assertSame('HIGH', $findings[0]->severity);
        $this->assertSame('LOW', $findings[1]->severity);
    }

    public function test_scanner_continues_when_checker_throws(): void
    {
        $failingChecker = new class extends BaseChecker {
            public function check(string $path): array {
                throw new \RuntimeException('checker exploded');
            }
        };

        $goodChecker = new class extends BaseChecker {
            public function check(string $path): array {
                return [new Finding('INFO', 'GoodChecker', 'f.php', null, 'm', 'r')];
            }
        };

        $scanner = new Scanner();
        $scanner->addChecker($failingChecker)->addChecker($goodChecker);

        $findings = $scanner->run('/some/path');

        $this->assertCount(1, $findings);
        $this->assertCount(1, $scanner->getErrors());
        $this->assertStringContainsString('checker exploded', $scanner->getErrors()[0]['message']);
    }

    public function test_scanner_returns_empty_when_no_checkers(): void
    {
        $scanner = new Scanner();
        $this->assertSame([], $scanner->run('/some/path'));
    }
}
