<?php

namespace Laraditz\SecurityScanner\Tests\Commands;

use Laraditz\SecurityScanner\SecurityScannerServiceProvider;
use Orchestra\Testbench\TestCase;

class SecurityScanCommandTest extends TestCase
{
    public static $latestResponse;

    protected function getPackageProviders($app): array
    {
        return [SecurityScannerServiceProvider::class];
    }

    public function test_command_is_registered(): void
    {
        $this->assertTrue(
            $this->app->make('Illuminate\Contracts\Console\Kernel')
                ->all()['security:scan'] !== null
        );
    }

    public function test_command_runs_without_error(): void
    {
        $this->artisan('security:scan', ['--path' => __DIR__ . '/../Fixtures'])
            ->assertExitCode(0);
    }

    public function test_command_accepts_custom_path(): void
    {
        $this->artisan('security:scan', [
            '--path' => __DIR__ . '/../Fixtures',
            '--output' => sys_get_temp_dir(),
        ])->assertExitCode(0);
    }
}
