<?php

declare(strict_types=1);

namespace Tests\Unit\Channels;

use Harryes\SentinelLog\Channels\DiscordWebhookChannel;
use Harryes\SentinelLog\Notifications\Messages\DiscordMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class DiscordTestNotification extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['discord'];
    }

    public function toDiscord(object $notifiable): DiscordMessage
    {
        return (new DiscordMessage)->content('New device login detected.');
    }
}

class DiscordTestNotificationWithoutToDiscord extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['discord'];
    }
}

class DiscordTestNotifiable
{
    public ?string $discordWebhook = null;

    public function routeNotificationFor(string $driver): ?string
    {
        return $driver === 'discord' ? $this->discordWebhook : null;
    }
}

beforeEach(function () {
    config(['sentinel-log.channels.discord.webhook_url' => null]);
});

it('posts the discord message payload to the configured webhook', function () {
    Http::fake();
    config(['sentinel-log.channels.discord.webhook_url' => 'https://discord.test/api/webhooks/xyz']);

    (new DiscordWebhookChannel)->send(new DiscordTestNotifiable, new DiscordTestNotification);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://discord.test/api/webhooks/xyz'
            && $request['content'] === 'New device login detected.';
    });
});

it('prefers a per notifiable webhook url over the config default', function () {
    Http::fake();
    config(['sentinel-log.channels.discord.webhook_url' => 'https://discord.test/default']);

    $notifiable = new DiscordTestNotifiable;
    $notifiable->discordWebhook = 'https://discord.test/per-user';

    (new DiscordWebhookChannel)->send($notifiable, new DiscordTestNotification);

    Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/per-user');
});

it('does nothing when no webhook url is configured', function () {
    Http::fake();

    (new DiscordWebhookChannel)->send(new DiscordTestNotifiable, new DiscordTestNotification);

    Http::assertNothingSent();
});

it('does not throw when the webhook request fails, it just logs a warning', function () {
    Http::fake(['*' => Http::response('bad request', 400)]);
    config(['sentinel-log.channels.discord.webhook_url' => 'https://discord.test/api/webhooks/xyz']);

    (new DiscordWebhookChannel)->send(new DiscordTestNotifiable, new DiscordTestNotification);

    expect(true)->toBeTrue();
});

it('does not throw when the connection itself fails', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });
    config(['sentinel-log.channels.discord.webhook_url' => 'https://discord.test/api/webhooks/xyz']);

    (new DiscordWebhookChannel)->send(new DiscordTestNotifiable, new DiscordTestNotification);

    expect(true)->toBeTrue();
});

it('skips notifications that have no toDiscord method', function () {
    Http::fake();
    config(['sentinel-log.channels.discord.webhook_url' => 'https://discord.test/api/webhooks/xyz']);

    (new DiscordWebhookChannel)->send(new DiscordTestNotifiable, new DiscordTestNotificationWithoutToDiscord);

    Http::assertNothingSent();
});
