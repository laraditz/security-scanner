<?php

namespace Laraditz\SecurityScanner;

use Illuminate\Support\ServiceProvider;
use Laraditz\SecurityScanner\Commands\SecurityScanCommand;

class SecurityScannerServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([SecurityScanCommand::class]);
        }
    }
}
