<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\LocationVerification;
use Harryes\SentinelLog\Services\LocationVerificationService;

function makeVerification(mixed $user): LocationVerification
{
    return LocationVerification::create([
        'authenticatable_type' => get_class($user),
        'authenticatable_id'   => $user->id,
        'token'                => \Illuminate\Support\Str::random(64),
        'ip_address'           => '1.2.3.4',
        'location'             => ['city' => 'Paris', 'country' => 'France'],
        'expires_at'           => now()->addMinutes(30),
    ]);
}

it('verify() returns the record on first call', function () {
    $user    = makeUser();
    $record  = makeVerification($user);
    $service = app(LocationVerificationService::class);

    $result = $service->verify($record->token);

    expect($result)->not->toBeNull()
        ->and($result->id)->toBe($record->id)
        ->and(AuthenticationLog::where('event_name', 'location_verified')->count())->toBe(1);
});

it('verify() returns null on second call — idempotent', function () {
    $user    = makeUser();
    $record  = makeVerification($user);
    $service = app(LocationVerificationService::class);

    $service->verify($record->token);
    $second = $service->verify($record->token);

    expect($second)->toBeNull()
        ->and(AuthenticationLog::where('event_name', 'location_verified')->count())->toBe(1);
});

it('deny() returns the record on first call', function () {
    $user    = makeUser();
    $record  = makeVerification($user);
    $service = app(LocationVerificationService::class);

    $result = $service->deny($record->token);

    expect($result)->not->toBeNull()
        ->and(AuthenticationLog::where('event_name', 'location_denied')->count())->toBe(1);
});

it('deny() returns null on second call — idempotent', function () {
    $user    = makeUser();
    $record  = makeVerification($user);
    $service = app(LocationVerificationService::class);

    $service->deny($record->token);
    $second = $service->deny($record->token);

    expect($second)->toBeNull()
        ->and(AuthenticationLog::where('event_name', 'location_denied')->count())->toBe(1);
});

it('cannot verify after already denied', function () {
    $user    = makeUser();
    $record  = makeVerification($user);
    $service = app(LocationVerificationService::class);

    $service->deny($record->token);
    $result = $service->verify($record->token);

    expect($result)->toBeNull();
});

it('returns null for an expired token', function () {
    $user    = makeUser();
    $record  = LocationVerification::create([
        'authenticatable_type' => get_class($user),
        'authenticatable_id'   => $user->id,
        'token'                => \Illuminate\Support\Str::random(64),
        'ip_address'           => '1.2.3.4',
        'location'             => ['city' => 'Berlin', 'country' => 'Germany'],
        'expires_at'           => now()->subMinute(), // already expired
    ]);
    $service = app(LocationVerificationService::class);

    expect($service->verify($record->token))->toBeNull()
        ->and($service->deny($record->token))->toBeNull();
});
