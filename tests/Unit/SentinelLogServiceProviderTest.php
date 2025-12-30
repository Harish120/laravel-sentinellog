<?php

declare(strict_types=1);

namespace Tests\Unit;

describe('SentinelLogServiceProviderTest', function () {
    it('properly merges config', function () {
        $config = config('sentinel-log');

        expect($config)->toBeArray()
            ->and($config)->toHaveKey('enabled')
            ->and($config)->toHaveKey('events')
            ->and($config)->toHaveKey('table_name')
            ->and($config['table_name'])->toBe('authentication_logs');
    });

    it('loads migrations', function () {
        $migrations = app('migrator')
            ->getMigrationFiles(__DIR__ . '/../../database/migrations');

        expect($migrations)->toBeArray()
            ->and($migrations)->toHaveCount(5); // We have 5 migration files in the package
    });
});
