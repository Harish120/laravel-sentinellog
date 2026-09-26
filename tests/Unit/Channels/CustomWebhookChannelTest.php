<?php

declare(strict_types=1);

namespace Tests\Unit\Channels;

use Harryes\SentinelLog\Channels\CustomWebhookChannel;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class WebhookTestNotification extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['webhook'];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'event'      => 'new_device_login',
            'ip_address' => '1.2.3.4',
        ];
    }
}

class WebhookTestNotifiable
{
    public ?string $webhookUrl = null;

    public function routeNotificationFor(string $driver): ?string
    {
        return $driver === 'webhook' ? $this->webhookUrl : null;
    }
}

beforeEach(function () {
    config(['sentinel-log.channels.webhook.webhook_url' => null]);
});

it('posts the notification toArray payload to the configured webhook', function () {
    Http::fake();
    config(['sentinel-log.channels.webhook.webhook_url' => 'https://example.test/hooks/sentinel-log']);

    (new CustomWebhookChannel)->send(new WebhookTestNotifiable, new WebhookTestNotification);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://example.test/hooks/sentinel-log'
            && $request['event'] === 'new_device_login'
            && $request['ip_address'] === '1.2.3.4';
    });
});

it('prefers a per notifiable webhook url over the config default', function () {
    Http::fake();
    config(['sentinel-log.channels.webhook.webhook_url' => 'https://example.test/default']);

    $notifiable = new WebhookTestNotifiable;
    $notifiable->webhookUrl = 'https://example.test/per-user';

    (new CustomWebhookChannel)->send($notifiable, new WebhookTestNotification);

    Http::assertSent(fn ($request) => $request->url() === 'https://example.test/per-user');
});

it('does nothing when no webhook url is configured', function () {
    Http::fake();

    (new CustomWebhookChannel)->send(new WebhookTestNotifiable, new WebhookTestNotification);

    Http::assertNothingSent();
});

it('does not throw when the webhook request fails, it just logs a warning', function () {
    Http::fake(['*' => Http::response('bad request', 400)]);
    config(['sentinel-log.channels.webhook.webhook_url' => 'https://example.test/hooks/sentinel-log']);

    (new CustomWebhookChannel)->send(new WebhookTestNotifiable, new WebhookTestNotification);

    expect(true)->toBeTrue();
});

it('does not throw when the connection itself fails', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });
    config(['sentinel-log.channels.webhook.webhook_url' => 'https://example.test/hooks/sentinel-log']);

    (new CustomWebhookChannel)->send(new WebhookTestNotifiable, new WebhookTestNotification);

    expect(true)->toBeTrue();
});
