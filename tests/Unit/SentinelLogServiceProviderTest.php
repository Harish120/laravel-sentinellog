<?php

declare(strict_types=1);

namespace Tests\Unit;

use Tests\TestCase;

class SentinelLogServiceProviderTest extends TestCase
{
    /** @test */
    public function it_properly_merges_config(): void
    {
        $config = config('sentinel-log');

        expect($config)->toBeArray()
            ->and($config)->toHaveKey('enabled')
            ->and($config)->toHaveKey('events')
            ->and($config)->toHaveKey('table_name')
            ->and($config['table_name'])->toBe('authentication_logs');
    }

    /** @test */
    public function it_loads_migrations(): void
    {
        $migrations = $this->app->make('migrator')
            ->getMigrationFiles(__DIR__.'/../../database/migrations');

        expect($migrations)->toBeArray()
            ->and($migrations)->toHaveCount(5); // We have 5 migration files in the package
    }
}
