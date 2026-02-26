<?php

namespace Laraditz\SecurityScanner\Checkers;

class MaliciousFileChecker extends BaseChecker
{
    public function check(string $path): array { return []; }
}
