<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\SsoToken;
use Harryes\SentinelLog\Services\SsoAuthenticationService;

beforeEach(function () {
    config(['sentinel-log.sso.enabled' => true]);
});

it('generates and validates a token for the correct user', function () {
    $user    = $this->makeUser();
    $service = app(SsoAuthenticationService::class);
    $token   = $service->generateToken($user, 'test-client');

    $resolved = $service->validateToken($token, 'test-client');

    expect($resolved)->not->toBeNull()
        ->and($resolved->id)->toBe($user->id);
});

it('consumes the token on validation — one-time use', function () {
    $user    = $this->makeUser();
    $service = app(SsoAuthenticationService::class);
    $token   = $service->generateToken($user, 'test-client');

    $service->validateToken($token, 'test-client');
    $second = $service->validateToken($token, 'test-client');

    expect($second)->toBeNull()
        ->and(SsoToken::count())->toBe(0);
});

it('returns null for an expired token', function () {
    $user = $this->makeUser();
    SsoToken::create([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'token'                => 'expired-token',
        'client_id'            => 'test-client',
        'expires_at'           => now()->subHour(),
    ]);

    $service = app(SsoAuthenticationService::class);

    expect($service->validateToken('expired-token', 'test-client'))->toBeNull();
});

it('returns null for an unknown token', function () {
    $service = app(SsoAuthenticationService::class);

    expect($service->validateToken('does-not-exist', 'test-client'))->toBeNull();
});

it('returns null for wrong client id', function () {
    $user    = $this->makeUser();
    $service = app(SsoAuthenticationService::class);
    $token   = $service->generateToken($user, 'client-a');

    expect($service->validateToken($token, 'client-b'))->toBeNull();
});

it('does not consume token when user account is deleted', function () {
    $user    = $this->makeUser();
    $service = app(SsoAuthenticationService::class);
    $token   = $service->generateToken($user, 'test-client');

    // Delete the user to simulate a deleted account
    $user->delete();

    $result = $service->validateToken($token, 'test-client');

    expect($result)->toBeNull()
        ->and(SsoToken::count())->toBe(1); // token NOT consumed
});
