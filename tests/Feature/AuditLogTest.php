<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Auth;

it('records event_at on every login log entry', function () {
    $user = makeUser();
    Auth::login($user);

    $log = AuthenticationLog::where('event_name', 'login')->first();

    expect($log)->not->toBeNull()
        ->and($log->event_at)->not->toBeNull();
});

it('records the correct authenticatable on login', function () {
    $user = makeUser();
    Auth::login($user);

    $log = AuthenticationLog::where('event_name', 'login')->first();

    expect($log->authenticatable_id)->toBe($user->id)
        ->and($log->authenticatable_type)->toBe(get_class($user))
        ->and($log->is_successful)->toBeTrue();
});

it('records a failed login with is_successful false', function () {
    $user = makeUser();

    event(new Failed('web', $user, ['email' => $user->email, 'password' => 'wrong']));

    $log = AuthenticationLog::where('event_name', 'failed')->first();

    expect($log)->not->toBeNull()
        ->and($log->is_successful)->toBeFalse()
        ->and($log->authenticatable_id)->toBe($user->id);
});

it('records a logout event', function () {
    $user = makeUser();
    Auth::login($user);
    Auth::logout();

    expect(AuthenticationLog::where('event_name', 'logout')->count())->toBe(1);
});

it('records failed attempt without user when credentials are completely wrong', function () {
    event(new Failed('web', null, ['email' => 'nobody@example.com', 'password' => 'wrong']));

    $log = AuthenticationLog::where('event_name', 'failed')->first();

    expect($log)->not->toBeNull()
        ->and($log->authenticatable_id)->toBeNull()
        ->and($log->is_successful)->toBeFalse();
});
