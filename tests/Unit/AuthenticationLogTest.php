<?php

declare(strict_types=1);

namespace Tests\Unit;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\SentinelSession;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;

describe('AuthenticationLogTest', function () {
    it('uses correct table name from config', function () {
        $model = new AuthenticationLog;

        expect($model->getTable())->toBe('authentication_logs');

        config(['sentinel-log.table_name' => 'custom_auth_logs']);
        expect($model->getTable())->toBe('custom_auth_logs');
    });

    it('has correct fillable attributes', function () {
        $model = new AuthenticationLog;

        expect($model->getFillable())->toBe([
            'authenticatable_id',
            'authenticatable_type',
            'session_id',
            'event_name',
            'ip_address',
            'user_agent',
            'device_info',
            'location',
            'is_successful',
            'event_at',
            'cleared_at',
        ]);
    });

    it('has correct cast attributes', function () {
        $model = new AuthenticationLog;

        $expectedCasts = [
            'device_info' => 'array',
            'location' => 'array',
            'is_successful' => 'boolean',
            'event_at' => 'datetime',
            'cleared_at' => 'datetime',
        ];

        expect(array_intersect($expectedCasts, $model->getCasts()))->toBe($expectedCasts);
    });

    it('has correct relationship methods', function () {
        $model = new AuthenticationLog;

        expect($model->authenticatable())->toBeInstanceOf(MorphTo::class);

        $sessionRelation = $model->session();
        expect($sessionRelation)
            ->toBeInstanceOf(BelongsTo::class)
            ->and($sessionRelation->getRelated())->toBeInstanceOf(SentinelSession::class)
            ->and($sessionRelation->getForeignKeyName())->toBe('session_id');
    });

    it('can set attributes', function () {
        $model = new AuthenticationLog;

        $model->fill([
            'event_name' => 'login',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'PHPUnit Test',
            'device_info' => ['browser' => 'Test Browser'],
            'location' => ['country' => 'Test Country'],
            'is_successful' => true,
        ]);

        expect($model->event_name)->toBe('login')
            ->and($model->ip_address)->toBe('127.0.0.1')
            ->and($model->user_agent)->toBe('PHPUnit Test')
            ->and($model->device_info)->toBe(['browser' => 'Test Browser'])
            ->and($model->location)->toBe(['country' => 'Test Country'])
            ->and($model->is_successful)->toBeTrue();
    });
});
