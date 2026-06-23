<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\SentinelSession;
use Illuminate\Support\Facades\Auth;

it('allows login when sessions are disabled', function () {
    config(['sentinel-log.sessions.enabled' => false]);

    $user = makeUser();
    Auth::login($user);

    expect(Auth::check())->toBeTrue()
        ->and(AuthenticationLog::where('event_name', 'login')->count())->toBe(1);
});

it('does not create a sentinel session record when sessions are disabled', function () {
    config(['sentinel-log.sessions.enabled' => false]);

    $user = makeUser();
    Auth::login($user);

    expect(SentinelSession::count())->toBe(0);
});

it('creates a sentinel session record when sessions are enabled', function () {
    config(['sentinel-log.sessions.enabled' => true]);

    $user = makeUser();
    Auth::login($user);

    expect(SentinelSession::where('authenticatable_id', $user->id)->count())->toBe(1);
});

it('blocks login and throws when max active sessions exceeded', function () {
    config([
        'sentinel-log.sessions.enabled'    => true,
        'sentinel-log.sessions.max_active' => 1,
    ]);

    $user = makeUser();
    Auth::login($user);
    Auth::logout();

    // First login created 1 session, second login should exceed the limit
    // Manually re-login same user after logout cleaned the session
    $user2 = makeUser(['email' => 'user2@example.com']);
    Auth::login($user2); // creates session for user2

    // Simulate a second concurrent session for user2 already exists
    SentinelSession::create([
        'authenticatable_id'   => $user2->id,
        'authenticatable_type' => get_class($user2),
        'session_id'           => 'existing-session-id',
        'ip_address'           => '127.0.0.1',
        'last_activity'        => now(),
    ]);

    expect(fn () => Auth::login($user2))
        ->toThrow(\Symfony\Component\HttpKernel\Exception\HttpException::class);
});
