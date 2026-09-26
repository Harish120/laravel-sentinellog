<?php

declare(strict_types=1);

namespace Tests\Unit\Channels;

use Harryes\SentinelLog\Channels\TeamsWebhookChannel;
use Harryes\SentinelLog\Notifications\Messages\TeamsMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class TeamsTestNotification extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['teams'];
    }

    public function toTeams(object $notifiable): TeamsMessage
    {
        return (new TeamsMessage)->text('New device login detected.');
    }
}

class TeamsTestNotificationWithoutToTeams extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['teams'];
    }
}

class TeamsTestNotifiable
{
    public ?string $teamsWebhook = null;

    public function routeNotificationFor(string $driver): ?string
    {
        return $driver === 'teams' ? $this->teamsWebhook : null;
    }
}

beforeEach(function () {
    config(['sentinel-log.channels.teams.webhook_url' => null]);
});

it('posts the teams message payload to the configured webhook', function () {
    Http::fake();
    config(['sentinel-log.channels.teams.webhook_url' => 'https://outlook.office.test/webhook/xyz']);

    (new TeamsWebhookChannel)->send(new TeamsTestNotifiable, new TeamsTestNotification);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://outlook.office.test/webhook/xyz'
            && $request['text'] === 'New device login detected.';
    });
});

it('prefers a per notifiable webhook url over the config default', function () {
    Http::fake();
    config(['sentinel-log.channels.teams.webhook_url' => 'https://outlook.office.test/default']);

    $notifiable = new TeamsTestNotifiable;
    $notifiable->teamsWebhook = 'https://outlook.office.test/per-user';

    (new TeamsWebhookChannel)->send($notifiable, new TeamsTestNotification);

    Http::assertSent(fn ($request) => $request->url() === 'https://outlook.office.test/per-user');
});

it('does nothing when no webhook url is configured', function () {
    Http::fake();

    (new TeamsWebhookChannel)->send(new TeamsTestNotifiable, new TeamsTestNotification);

    Http::assertNothingSent();
});

it('does not throw when the webhook request fails, it just logs a warning', function () {
    Http::fake(['*' => Http::response('bad request', 400)]);
    config(['sentinel-log.channels.teams.webhook_url' => 'https://outlook.office.test/webhook/xyz']);

    (new TeamsWebhookChannel)->send(new TeamsTestNotifiable, new TeamsTestNotification);

    expect(true)->toBeTrue();
});

it('does not throw when the connection itself fails', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });
    config(['sentinel-log.channels.teams.webhook_url' => 'https://outlook.office.test/webhook/xyz']);

    (new TeamsWebhookChannel)->send(new TeamsTestNotifiable, new TeamsTestNotification);

    expect(true)->toBeTrue();
});

it('skips notifications that have no toTeams method', function () {
    Http::fake();
    config(['sentinel-log.channels.teams.webhook_url' => 'https://outlook.office.test/webhook/xyz']);

    (new TeamsWebhookChannel)->send(new TeamsTestNotifiable, new TeamsTestNotificationWithoutToTeams);

    Http::assertNothingSent();
});
