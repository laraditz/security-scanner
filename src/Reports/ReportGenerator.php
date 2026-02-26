<?php

namespace Laraditz\SecurityScanner\Reports;

use Laraditz\SecurityScanner\Finding;

class ReportGenerator
{
    /** @param Finding[] $findings */
    public function __construct(
        private readonly array $findings,
        private readonly array $errors,
        private readonly string $outputDir,
    ) {}

    /** @return array{json: string, html: string} */
    public function save(string $date): array
    {
        $jsonPath = $this->outputDir . "/security-scan-{$date}.json";
        $htmlPath = $this->outputDir . "/security-scan-{$date}.html";

        file_put_contents($jsonPath, $this->toJson());
        file_put_contents($htmlPath, $this->toHtml($date));

        return ['json' => $jsonPath, 'html' => $htmlPath];
    }

    private function toJson(): string
    {
        return json_encode([
            'generated_at' => date('Y-m-d H:i:s'),
            'total'        => count($this->findings),
            'findings'     => array_map(fn($f) => $f->toArray(), $this->findings),
            'errors'       => $this->errors,
        ], JSON_PRETTY_PRINT);
    }

    private function toHtml(string $date): string
    {
        $rows = '';
        $severityColors = [
            'CRITICAL' => '#dc2626',
            'HIGH'     => '#ea580c',
            'MEDIUM'   => '#d97706',
            'LOW'      => '#2563eb',
            'INFO'     => '#6b7280',
        ];

        foreach ($this->findings as $f) {
            $color = $severityColors[$f->severity] ?? '#6b7280';
            $line = $f->line ?? '-';
            $rows .= "<tr>
                <td><span style='color:{$color};font-weight:bold'>{$f->severity}</span></td>
                <td>{$f->checker}</td>
                <td>{$f->file}:{$line}</td>
                <td>{$f->message}</td>
                <td>{$f->recommendation}</td>
            </tr>";
        }

        $total = count($this->findings);

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Security Scan Report — {$date}</title>
            <style>
                body { font-family: monospace; padding: 2rem; background: #0f172a; color: #e2e8f0; }
                h1 { color: #f8fafc; }
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                th { background: #1e293b; padding: 0.5rem 1rem; text-align: left; }
                td { padding: 0.5rem 1rem; border-bottom: 1px solid #1e293b; }
                tr:hover td { background: #1e293b; }
            </style>
        </head>
        <body>
            <h1>laraditz/security-scanner</h1>
            <p>Scan date: {$date} &mdash; {$total} finding(s) found</p>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Checker</th><th>Location</th><th>Issue</th><th>Recommendation</th></tr>
                </thead>
                <tbody>{$rows}</tbody>
            </table>
        </body>
        </html>
        HTML;
    }
}
