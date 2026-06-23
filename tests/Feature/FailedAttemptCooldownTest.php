<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Notifications\FailedLoginAttempt;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;

beforeEach(function () {
    Notification::fake();
    config([
        'sentinel-log.notifications.failed_attempt.enabled'   => true,
        'sentinel-log.notifications.failed_attempt.threshold' => 3,
        'sentinel-log.notifications.failed_attempt.window'    => 60,
    ]);
});

it('sends notification when failed attempts reach the threshold', function () {
    $user = $this->makeUser();

    // Seed 3 failed attempts within the window
    foreach (range(1, 3) as $i) {
        AuthenticationLog::create([
            'authenticatable_id'   => $user->id,
            'authenticatable_type' => get_class($user),
            'event_name'           => 'failed',
            'is_successful'        => false,
            'ip_address'           => '127.0.0.1',
            'event_at'             => now(),
        ]);
    }

    $log = AuthenticationLog::where('authenticatable_id', $user->id)->first();
    $user->notifyFailedAttempt($log);

    Notification::assertSentTo($user, FailedLoginAttempt::class);
});

it('does not send notification below the threshold', function () {
    $user = $this->makeUser();

    // Only 2 failed attempts — below threshold of 3
    foreach (range(1, 2) as $i) {
        AuthenticationLog::create([
            'authenticatable_id'   => $user->id,
            'authenticatable_type' => get_class($user),
            'event_name'           => 'failed',
            'is_successful'        => false,
            'ip_address'           => '127.0.0.1',
            'event_at'             => now(),
        ]);
    }

    $log = AuthenticationLog::where('authenticatable_id', $user->id)->first();
    $user->notifyFailedAttempt($log);

    Notification::assertNotSentTo($user, FailedLoginAttempt::class);
});

it('sends notification only once per window due to cooldown', function () {
    $user = $this->makeUser();

    foreach (range(1, 5) as $i) {
        AuthenticationLog::create([
            'authenticatable_id'   => $user->id,
            'authenticatable_type' => get_class($user),
            'event_name'           => 'failed',
            'is_successful'        => false,
            'ip_address'           => '127.0.0.1',
            'event_at'             => now(),
        ]);
    }

    $log = AuthenticationLog::where('authenticatable_id', $user->id)->first();

    // Call multiple times — cooldown must prevent spam
    $user->notifyFailedAttempt($log);
    $user->notifyFailedAttempt($log);
    $user->notifyFailedAttempt($log);

    Notification::assertSentToTimes($user, FailedLoginAttempt::class, 1);
});
