<?php

declare(strict_types=1);

use Harryes\SentinelLog\Services\TwoFactorAuthenticationService;

it('accepts a valid TOTP code', function () {
    $service = app(TwoFactorAuthenticationService::class);
    $secret  = $service->generateSecret();
    $code    = $service->generateCode($secret);

    expect($service->verifyCode($secret, $code))->toBeTrue();
});

it('rejects a replayed TOTP code within the same window', function () {
    $service = app(TwoFactorAuthenticationService::class);
    $secret  = $service->generateSecret();
    $code    = $service->generateCode($secret);

    $service->verifyCode($secret, $code); // consumes the step

    expect($service->verifyCode($secret, $code))->toBeFalse();
});

it('rejects an incorrect TOTP code', function () {
    $service = app(TwoFactorAuthenticationService::class);
    $secret  = $service->generateSecret();

    expect($service->verifyCode($secret, '000000'))->toBeFalse();
});

it('accepts codes within the time window', function () {
    $service   = app(TwoFactorAuthenticationService::class);
    $secret    = $service->generateSecret();
    $timestamp = (int) floor(time() / 30);

    // Previous step code should be accepted within window=1
    $prevCode = $service->generateCode($secret, $timestamp - 1);

    expect($service->verifyCode($secret, $prevCode, 1))->toBeTrue();
});

it('generates a secret with sufficient entropy', function () {
    $service = app(TwoFactorAuthenticationService::class);
    $secret  = $service->generateSecret();

    // Base32 encoded 20 bytes = 32 characters
    expect(strlen($secret))->toBeGreaterThanOrEqual(32);
});
