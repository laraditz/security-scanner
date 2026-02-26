<?php

namespace Laraditz\SecurityScanner\Reports;

use Laraditz\SecurityScanner\Finding;

class TerminalReport
{
    private const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    private const COLORS = [
        'CRITICAL' => "\e[1;31m",  // bold red
        'HIGH'     => "\e[31m",    // red
        'MEDIUM'   => "\e[33m",    // yellow
        'LOW'      => "\e[36m",    // cyan
        'INFO'     => "\e[37m",    // white
        'RESET'    => "\e[0m",
    ];

    /** @param Finding[] $findings */
    public function __construct(
        private readonly array $findings,
        private readonly array $errors,
    ) {}

    public function getSummary(): array
    {
        $counts = array_fill_keys(self::SEVERITIES, 0);

        foreach ($this->findings as $finding) {
            if (isset($counts[$finding->severity])) {
                $counts[$finding->severity]++;
            }
        }

        return $counts;
    }

    /** @return string[] */
    public function getLines(): array
    {
        $lines = [];

        foreach (self::SEVERITIES as $severity) {
            $group = array_filter($this->findings, fn($f) => $f->severity === $severity);
            foreach ($group as $finding) {
                $color = self::COLORS[$severity] ?? self::COLORS['INFO'];
                $reset = self::COLORS['RESET'];
                $loc = $finding->file . ($finding->line ? ':' . $finding->line : '');
                $lines[] = "{$color}[{$finding->severity}]{$reset} {$finding->checker}";
                $lines[] = "  {$loc}";
                $lines[] = "  {$finding->message}";
                $lines[] = "  Fix: {$finding->recommendation}";
                $lines[] = '';
            }
        }

        if (!empty($this->errors)) {
            $lines[] = "\e[33m[WARNINGS]\e[0m Some checkers encountered errors:";
            foreach ($this->errors as $error) {
                $lines[] = "  {$error['checker']}: {$error['message']}";
            }
            $lines[] = '';
        }

        return $lines;
    }

    public function render(): string
    {
        $output = implode("\n", $this->getLines()) . "\n";

        $summary = $this->getSummary();
        $output .= str_repeat('─', 40) . "\n";
        foreach (self::SEVERITIES as $severity) {
            if ($summary[$severity] > 0) {
                $color = self::COLORS[$severity];
                $reset = self::COLORS['RESET'];
                $output .= sprintf("  {$color}%-10s{$reset} %d\n", $severity, $summary[$severity]);
            }
        }
        $output .= str_repeat('─', 40) . "\n";

        return $output;
    }
}
