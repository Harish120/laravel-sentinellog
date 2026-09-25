<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\LocationVerification;
use Harryes\SentinelLog\Models\SentinelSession;
use Harryes\SentinelLog\Notifications\FailedLoginAttempt;
use Harryes\SentinelLog\Notifications\NewDeviceLogin;
use Harryes\SentinelLog\Notifications\NewLocationLogin;
use Harryes\SentinelLog\Notifications\SessionHijackingDetected;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;

/**
 * @param array<string, mixed> $attributes
 */
function makeAuthLog(mixed $user, array $attributes = []): AuthenticationLog
{
    return AuthenticationLog::create(array_merge([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'event_name'           => 'login',
        'is_successful'        => true,
        'ip_address'           => '1.2.3.4',
        'location'             => ['city' => 'Paris', 'country' => 'France'],
        'device_info'          => ['browser' => 'Firefox', 'token' => 'token-123'],
        'event_at'             => now(),
    ], $attributes));
}

function makeLocationVerification(mixed $user): LocationVerification
{
    return LocationVerification::create([
        'authenticatable_type' => get_class($user),
        'authenticatable_id'   => $user->id,
        'token'                => Str::random(64),
        'ip_address'           => '1.2.3.4',
        'location'             => ['city' => 'Paris', 'country' => 'France'],
        'expires_at'           => now()->addMinutes(30),
    ]);
}

function makeSentinelSession(mixed $user): SentinelSession
{
    return SentinelSession::create([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'session_id'           => Str::random(40),
        'ip_address'           => '1.2.3.4',
        'device_info'          => ['browser' => 'Firefox'],
        'location'             => ['city' => 'Paris', 'country' => 'France'],
        'last_activity'        => now(),
    ]);
}

beforeEach(function () {
    Mail::fake();
    Http::fake();

    config([
        'sentinel-log.channels.slack.webhook_url'    => 'https://hooks.slack.test/services/xyz',
        'sentinel-log.channels.discord.webhook_url'  => 'https://discord.test/api/webhooks/xyz',
        'sentinel-log.channels.teams.webhook_url'    => 'https://outlook.office.test/webhook/xyz',
        'sentinel-log.channels.telegram.bot_token'   => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'     => '999888777',
        'sentinel-log.channels.webhook.webhook_url'  => 'https://example.test/hooks/sentinel-log',
    ]);
});

/**
 * All five optional channels enabled at once, alongside mail.
 *
 * @return array<int, string>
 */
function allOptionalChannels(): array
{
    return ['mail', 'slack', 'discord', 'teams', 'telegram', 'webhook'];
}

it('does not call any webhook when channels are left at the mail-only default', function () {
    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    Http::assertNothingSent();
});

it('sends the new device login alert to every optional channel when they are all enabled', function () {
    config(['sentinel-log.notifications.new_device.channels' => allOptionalChannels()]);

    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    Http::assertSent(fn ($request) => $request->url() === 'https://hooks.slack.test/services/xyz'
        && str_contains($request['text'], 'New device login detected')
        && str_contains($request['text'], '1.2.3.4'));

    Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/api/webhooks/xyz'
        && str_contains($request['content'], 'New device login detected')
        && str_contains($request['content'], '1.2.3.4'));

    Http::assertSent(fn ($request) => $request->url() === 'https://outlook.office.test/webhook/xyz'
        && str_contains($request['text'], 'New device login detected')
        && str_contains($request['text'], '1.2.3.4'));

    Http::assertSent(fn ($request) => $request->url() === 'https://api.telegram.org/bot123456:ABC-DEF/sendMessage'
        && $request['chat_id'] === '999888777'
        && str_contains($request['text'], 'New device login detected'));

    Http::assertSent(fn ($request) => $request->url() === 'https://example.test/hooks/sentinel-log'
        && $request['event'] === 'new_device_login'
        && $request['ip_address'] === '1.2.3.4');
});

it('sends the failed login attempt alert to every optional channel when they are all enabled', function () {
    config(['sentinel-log.notifications.failed_attempt.channels' => allOptionalChannels()]);

    $user = makeUser();
    $log  = makeAuthLog($user, ['event_name' => 'failed', 'is_successful' => false]);

    Notification::send($user, new FailedLoginAttempt($log, 4));

    Http::assertSent(fn ($request) => $request->url() === 'https://hooks.slack.test/services/xyz'
        && str_contains($request['text'], '4 failed login attempts'));

    Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/api/webhooks/xyz'
        && str_contains($request['content'], '4 failed login attempts'));

    Http::assertSent(fn ($request) => $request->url() === 'https://outlook.office.test/webhook/xyz'
        && str_contains($request['text'], '4 failed login attempts'));

    Http::assertSent(fn ($request) => $request->url() === 'https://api.telegram.org/bot123456:ABC-DEF/sendMessage'
        && str_contains($request['text'], '4 failed login attempts'));

    Http::assertSent(fn ($request) => $request->url() === 'https://example.test/hooks/sentinel-log'
        && $request['event'] === 'failed_login_attempt'
        && $request['attempt_count'] === 4);
});

it('sends the new location login alert to every optional channel when they are all enabled', function () {
    config(['sentinel-log.location_verification.channels' => allOptionalChannels()]);

    $user         = makeUser();
    $verification = makeLocationVerification($user);

    Notification::send($user, new NewLocationLogin($verification));

    Http::assertSent(fn ($request) => $request->url() === 'https://hooks.slack.test/services/xyz'
        && str_contains($request['text'], 'New login location detected')
        && str_contains($request['text'], (string) $verification->token));

    Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/api/webhooks/xyz'
        && str_contains($request['content'], 'New login location detected')
        && str_contains($request['content'], (string) $verification->token));

    Http::assertSent(fn ($request) => $request->url() === 'https://outlook.office.test/webhook/xyz'
        && str_contains($request['text'], 'New login location detected')
        && str_contains($request['text'], (string) $verification->token));

    Http::assertSent(fn ($request) => $request->url() === 'https://api.telegram.org/bot123456:ABC-DEF/sendMessage'
        && str_contains($request['text'], 'New login location detected')
        && str_contains($request['text'], (string) $verification->token));

    Http::assertSent(fn ($request) => $request->url() === 'https://example.test/hooks/sentinel-log'
        && $request['event'] === 'new_location_login'
        && $request['verification_id'] === $verification->id);
});

it('sends the session hijacking alert to every optional channel when they are all enabled', function () {
    config(['sentinel-log.notifications.session_hijacking.channels' => allOptionalChannels()]);

    $user    = makeUser();
    $session = makeSentinelSession($user);

    Notification::send($user, new SessionHijackingDetected($session, 'IP address changed mid-session'));

    Http::assertSent(fn ($request) => $request->url() === 'https://hooks.slack.test/services/xyz'
        && str_contains($request['text'], 'Possible session hijacking detected')
        && str_contains($request['text'], 'IP address changed mid-session'));

    Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/api/webhooks/xyz'
        && str_contains($request['content'], 'Possible session hijacking detected')
        && str_contains($request['content'], 'IP address changed mid-session'));

    Http::assertSent(fn ($request) => $request->url() === 'https://outlook.office.test/webhook/xyz'
        && str_contains($request['text'], 'Possible session hijacking detected')
        && str_contains($request['text'], 'IP address changed mid-session'));

    Http::assertSent(fn ($request) => $request->url() === 'https://api.telegram.org/bot123456:ABC-DEF/sendMessage'
        && str_contains($request['text'], 'Possible session hijacking detected')
        && str_contains($request['text'], 'IP address changed mid-session'));

    Http::assertSent(fn ($request) => $request->url() === 'https://example.test/hooks/sentinel-log'
        && $request['event'] === 'session_hijacking'
        && $request['reason'] === 'IP address changed mid-session');
});

it('still delivers mail and does not throw when slack is enabled but has no webhook url set', function () {
    config([
        'sentinel-log.channels.slack.webhook_url'      => null,
        'sentinel-log.notifications.new_device.channels' => ['mail', 'slack'],
    ]);

    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    Http::assertNothingSent();
    // Reaching this line means the missing webhook did not break the notification.
    expect(true)->toBeTrue();
});

it('still delivers mail and does not throw when the slack webhook itself is unreachable', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });

    config(['sentinel-log.notifications.new_device.channels' => ['mail', 'slack']]);

    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    expect(true)->toBeTrue();
});

it('still delivers mail and does not throw when telegram has no bot token configured', function () {
    config([
        'sentinel-log.channels.telegram.bot_token'       => null,
        'sentinel-log.notifications.new_device.channels' => ['mail', 'telegram'],
    ]);

    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    Http::assertNothingSent();
});

it('still delivers mail and does not throw when the generic webhook has no url configured', function () {
    config([
        'sentinel-log.channels.webhook.webhook_url'      => null,
        'sentinel-log.notifications.new_device.channels' => ['mail', 'webhook'],
    ]);

    $user = makeUser();
    $log  = makeAuthLog($user);

    Notification::send($user, new NewDeviceLogin($log));

    Http::assertNothingSent();
});
