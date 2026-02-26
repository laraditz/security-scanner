<?php

namespace Laraditz\SecurityScanner\Commands;

use Illuminate\Console\Command;
use Laraditz\SecurityScanner\Checkers\AuthorizationChecker;
use Laraditz\SecurityScanner\Checkers\CsrfChecker;
use Laraditz\SecurityScanner\Checkers\FileUploadChecker;
use Laraditz\SecurityScanner\Checkers\MaliciousFileChecker;
use Laraditz\SecurityScanner\Checkers\MassAssignmentChecker;
use Laraditz\SecurityScanner\Checkers\RateLimitChecker;
use Laraditz\SecurityScanner\Checkers\SecretsChecker;
use Laraditz\SecurityScanner\Checkers\SqlInjectionChecker;
use Laraditz\SecurityScanner\Checkers\XssChecker;
use Laraditz\SecurityScanner\Reports\ReportGenerator;
use Laraditz\SecurityScanner\Reports\TerminalReport;
use Laraditz\SecurityScanner\Scanner;

class SecurityScanCommand extends Command
{
    protected $signature = 'security:scan
        {--path= : Path to Laravel app root (defaults to base_path())}
        {--output= : Directory to save report files (defaults to storage/logs/)}';

    protected $description = 'Scan this Laravel application for security vulnerabilities';

    public function handle(): int
    {
        $path   = $this->option('path') ?? base_path();
        $output = $this->option('output') ?? storage_path('logs');

        if (!is_dir($path)) {
            $this->error("Path does not exist: {$path}");
            return self::FAILURE;
        }

        $this->line('');
        $this->line('<fg=bright-white;options=bold>laraditz/security-scanner</>');
        $this->line("Scanning: <fg=yellow>{$path}</>");
        $this->line('');

        $scanner = new Scanner();
        $scanner
            ->addChecker(new SqlInjectionChecker())
            ->addChecker(new AuthorizationChecker())
            ->addChecker(new SecretsChecker())
            ->addChecker(new FileUploadChecker())
            ->addChecker(new MaliciousFileChecker())
            ->addChecker(new XssChecker())
            ->addChecker(new MassAssignmentChecker())
            ->addChecker(new CsrfChecker())
            ->addChecker(new RateLimitChecker());

        $findings = $scanner->run($path);
        $errors   = $scanner->getErrors();

        $terminal = new TerminalReport($findings, $errors);
        $this->output->write($terminal->render());

        if (!is_dir($output)) {
            @mkdir($output, 0755, true);
        }

        $date      = date('Y-m-d');
        $generator = new ReportGenerator($findings, $errors, $output);
        $paths     = $generator->save($date);

        $this->line("<fg=green>Report saved:</> {$paths['html']}");
        $this->line('');

        return self::SUCCESS;
    }
}
