<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\BlockedIp;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Symfony\Component\HttpKernel\Exception\HttpException;

it('blocks login and logs out user when IP is blocked', function () {
    $user = $this->makeUser();

    BlockedIp::create([
        'ip_address' => '127.0.0.1',
        'blocked_at' => now(),
        'expires_at' => now()->addHours(24),
        'reason'     => 'test block',
    ]);

    $exception = null;

    try {
        Auth::login($user);
    } catch (HttpException $e) {
        $exception = $e;
    }

    expect($exception)->not->toBeNull()
        ->and($exception->getStatusCode())->toBe(403)
        ->and(Auth::check())->toBeFalse();
});

it('allows login when IP block has expired', function () {
    $user = $this->makeUser();

    BlockedIp::create([
        'ip_address' => '127.0.0.1',
        'blocked_at' => now()->subDay(),
        'expires_at' => now()->subHour(), // expired
        'reason'     => 'old block',
    ]);

    Auth::login($user);

    expect(Auth::check())->toBeTrue()
        ->and(AuthenticationLog::where('event_name', 'login')->count())->toBe(1);
});

it('records a login audit log for non-blocked IP', function () {
    $user = $this->makeUser();

    Auth::login($user);

    expect(AuthenticationLog::where('authenticatable_id', $user->id)
        ->where('event_name', 'login')
        ->where('is_successful', true)
        ->exists()
    )->toBeTrue();
});
