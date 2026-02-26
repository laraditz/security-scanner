<?php

namespace Laraditz\SecurityScanner;

use Laraditz\SecurityScanner\Checkers\BaseChecker;

class Scanner
{
    /** @var BaseChecker[] */
    private array $checkers = [];

    /** @var array<array{checker: string, message: string}> */
    private array $errors = [];

    public function addChecker(BaseChecker $checker): static
    {
        $this->checkers[] = $checker;
        return $this;
    }

    /** @return Finding[] */
    public function run(string $path): array
    {
        $findings = [];

        foreach ($this->checkers as $checker) {
            try {
                $findings = array_merge($findings, $checker->check($path));
            } catch (\Throwable $e) {
                $this->errors[] = [
                    'checker' => get_class($checker),
                    'message' => $e->getMessage(),
                ];
            }
        }

        return $findings;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }
}
