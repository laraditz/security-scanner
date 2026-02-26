<?php

namespace Laraditz\SecurityScanner\Checkers;

class CsrfChecker extends BaseChecker
{
    public function check(string $path): array { return []; }
}
