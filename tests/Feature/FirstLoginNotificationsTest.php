<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Notifications\NewDeviceLogin;
use Harryes\SentinelLog\Notifications\NewLocationLogin;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Notification;

beforeEach(function () {
    Notification::fake();
    config([
        'sentinel-log.notifications.new_device.enabled' => true,
        'sentinel-log.location_verification.enabled'    => true,
    ]);
});

it('does not send new-device notification on first ever login', function () {
    $user = makeUser();

    Auth::login($user);

    Notification::assertNotSentTo($user, NewDeviceLogin::class);
});

it('does not send new-location email on first ever login', function () {
    $user = makeUser();

    Auth::login($user);

    Notification::assertNotSentTo($user, NewLocationLogin::class);
});

it('sends new-device notification when user has prior login history and a new token appears', function () {
    $user = makeUser();

    // Seed a prior login with a known device token so there is login history
    AuthenticationLog::create([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'event_name'           => 'login',
        'is_successful'        => true,
        'device_info'          => ['token' => 'old-known-token'],
        'ip_address'           => '127.0.0.1',
        'event_at'             => now()->subDay(),
    ]);

    // Login with a new device (no matching token in history) — should notify
    Auth::login($user);

    Notification::assertSentTo($user, NewDeviceLogin::class);
});

it('sends new-location email when user has prior login history and a new location appears', function () {
    $user = makeUser();

    // Seed a prior login from a known location
    AuthenticationLog::create([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'event_name'           => 'login',
        'is_successful'        => true,
        'location'             => ['city' => 'London', 'country' => 'United Kingdom'],
        'device_info'          => ['token' => 'some-token'],
        'ip_address'           => '1.2.3.4',
        'event_at'             => now()->subDay(),
    ]);

    // Login from localhost → returns 'Local' country → no email (local IPs are excluded)
    Auth::login($user);

    Notification::assertNotSentTo($user, NewLocationLogin::class);
});
