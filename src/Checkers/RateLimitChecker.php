<?php

namespace Laraditz\SecurityScanner\Checkers;

class RateLimitChecker extends BaseChecker
{
    public function check(string $path): array { return []; }
}
