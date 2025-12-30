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

        // Default table name
        $this->assertEquals('authentication_logs', $model->getTable());

        // Custom table name
        config(['sentinel-log.table_name' => 'custom_auth_logs']);
        $this->assertEquals('custom_auth_logs', $model->getTable());
    });

    it('has correct fillable attributes', function () {
        $model = new AuthenticationLog;

        $expectedFillable = [
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
        ];

        $this->assertEquals($expectedFillable, $model->getFillable());
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

        $this->assertEquals($expectedCasts, array_intersect($expectedCasts, $model->getCasts()));
    });

    it('has correct relationship methods', function () {
        $model = new AuthenticationLog;

        $this->assertInstanceOf(MorphTo::class, $model->authenticatable());

        $sessionRelation = $model->session();
        $this->assertInstanceOf(BelongsTo::class, $sessionRelation);
        $this->assertInstanceOf(SentinelSession::class, $sessionRelation->getRelated());
        $this->assertEquals('session_id', $sessionRelation->getForeignKeyName());
    });

    it('can set attributes', function () {
        $model = new AuthenticationLog;

        $data = [
            'event_name' => 'login',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'PHPUnit Test',
            'device_info' => ['browser' => 'Test Browser'],
            'location' => ['country' => 'Test Country'],
            'is_successful' => true,
        ];

        $model->fill($data);

        $this->assertEquals('login', $model->event_name);
        $this->assertEquals('127.0.0.1', $model->ip_address);
        $this->assertEquals('PHPUnit Test', $model->user_agent);
        $this->assertEquals(['browser' => 'Test Browser'], $model->device_info);
        $this->assertEquals(['country' => 'Test Country'], $model->location);
        $this->assertTrue($model->is_successful);
    });
});
