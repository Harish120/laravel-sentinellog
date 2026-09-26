<?php

declare(strict_types=1);

namespace Tests\Unit\Channels;

use Harryes\SentinelLog\Channels\SlackWebhookChannel;
use Harryes\SentinelLog\Notifications\Messages\SlackMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class SlackTestNotification extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['slack'];
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        return (new SlackMessage)->text('New device login detected.');
    }
}

class SlackTestNotificationWithoutToSlack extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['slack'];
    }
}

class SlackTestNotifiable
{
    public ?string $slackWebhook = null;

    public function routeNotificationFor(string $driver): ?string
    {
        return $driver === 'slack' ? $this->slackWebhook : null;
    }
}

beforeEach(function () {
    config(['sentinel-log.channels.slack.webhook_url' => null]);
});

it('posts the slack message payload to the configured webhook', function () {
    Http::fake();
    config(['sentinel-log.channels.slack.webhook_url' => 'https://hooks.slack.test/services/xyz']);

    (new SlackWebhookChannel)->send(new SlackTestNotifiable, new SlackTestNotification);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://hooks.slack.test/services/xyz'
            && $request['text'] === 'New device login detected.';
    });
});

it('prefers a per notifiable webhook url over the config default', function () {
    Http::fake();
    config(['sentinel-log.channels.slack.webhook_url' => 'https://hooks.slack.test/default']);

    $notifiable = new SlackTestNotifiable;
    $notifiable->slackWebhook = 'https://hooks.slack.test/per-user';

    (new SlackWebhookChannel)->send($notifiable, new SlackTestNotification);

    Http::assertSent(fn ($request) => $request->url() === 'https://hooks.slack.test/per-user');
});

it('does nothing when no webhook url is configured', function () {
    Http::fake();

    (new SlackWebhookChannel)->send(new SlackTestNotifiable, new SlackTestNotification);

    Http::assertNothingSent();
});

it('does not throw when the webhook request fails, it just logs a warning', function () {
    Http::fake(['*' => Http::response('bad request', 400)]);
    config(['sentinel-log.channels.slack.webhook_url' => 'https://hooks.slack.test/services/xyz']);

    (new SlackWebhookChannel)->send(new SlackTestNotifiable, new SlackTestNotification);

    // Reaching this line means the exception did not bubble up.
    expect(true)->toBeTrue();
});

it('does not throw when the connection itself fails', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });
    config(['sentinel-log.channels.slack.webhook_url' => 'https://hooks.slack.test/services/xyz']);

    (new SlackWebhookChannel)->send(new SlackTestNotifiable, new SlackTestNotification);

    expect(true)->toBeTrue();
});

it('skips notifications that have no toSlack method', function () {
    Http::fake();
    config(['sentinel-log.channels.slack.webhook_url' => 'https://hooks.slack.test/services/xyz']);

    (new SlackWebhookChannel)->send(new SlackTestNotifiable, new SlackTestNotificationWithoutToSlack);

    Http::assertNothingSent();
});
