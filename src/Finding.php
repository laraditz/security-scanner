<?php

namespace Laraditz\SecurityScanner;

class Finding
{
    public function __construct(
        public readonly string $severity,
        public readonly string $checker,
        public readonly string $file,
        public readonly ?int $line,
        public readonly string $message,
        public readonly string $recommendation,
    ) {}

    public function toArray(): array
    {
        return [
            'severity'       => $this->severity,
            'checker'        => $this->checker,
            'file'           => $this->file,
            'line'           => $this->line,
            'message'        => $this->message,
            'recommendation' => $this->recommendation,
        ];
    }
}
