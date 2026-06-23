<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\BlockedIp;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpKernel\Exception\HttpException;

beforeEach(function () {
    config([
        'sentinel-log.brute_force.enabled'        => true,
        'sentinel-log.brute_force.threshold'      => 3,
        'sentinel-log.brute_force.window'         => 15,
        'sentinel-log.brute_force.block_duration' => 24,
    ]);
});

it('records a failed login attempt', function () {
    $user = $this->makeUser();

    event(new Failed('web', $user, ['email' => $user->email, 'password' => 'wrong']));

    expect(AuthenticationLog::where('event_name', 'failed')->count())->toBe(1);
});

it('blocks IP after threshold is reached', function () {
    $service = app(BruteForceProtectionService::class);

    foreach (range(1, 3) as $i) {
        try {
            $service->checkBruteForce();
        } catch (HttpException) {
            // expected on block
        }
    }

    expect(BlockedIp::where('ip_address', '127.0.0.1')->whereNotNull('expires_at')->exists())->toBeTrue();
});

it('clears the attempt counter after successful login', function () {
    $service = app(BruteForceProtectionService::class);
    $user    = $this->makeUser();

    // Build up some attempts
    $service->checkBruteForce(); // attempt 1
    expect($service->getAttempts('127.0.0.1'))->toBe(1);

    Auth::login($user);
    $service->clearAttempts('127.0.0.1');

    expect($service->getAttempts('127.0.0.1'))->toBe(0);
});

it('expired block does not prevent login', function () {
    BlockedIp::create([
        'ip_address' => '127.0.0.1',
        'blocked_at' => now()->subDay(),
        'expires_at' => now()->subHour(),
        'reason'     => 'expired',
    ]);

    $user = $this->makeUser();
    Auth::login($user);

    expect(Auth::check())->toBeTrue();
});

it('pruneExpired removes expired block records', function () {
    BlockedIp::create([
        'ip_address' => '10.0.0.1',
        'blocked_at' => now()->subDay(),
        'expires_at' => now()->subHour(),
        'reason'     => 'expired',
    ]);
    BlockedIp::create([
        'ip_address' => '10.0.0.2',
        'blocked_at' => now(),
        'expires_at' => now()->addHour(),
        'reason'     => 'active',
    ]);

    $deleted = app(BruteForceProtectionService::class)->pruneExpired();

    expect($deleted)->toBe(1)
        ->and(BlockedIp::count())->toBe(1)
        ->and(BlockedIp::first()->ip_address)->toBe('10.0.0.2');
});
