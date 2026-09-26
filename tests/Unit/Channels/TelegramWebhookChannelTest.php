<?php

declare(strict_types=1);

namespace Tests\Unit\Channels;

use Harryes\SentinelLog\Channels\TelegramWebhookChannel;
use Harryes\SentinelLog\Notifications\Messages\TelegramMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class TelegramTestNotification extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['telegram'];
    }

    public function toTelegram(object $notifiable): TelegramMessage
    {
        return (new TelegramMessage)->text('New device login detected.');
    }
}

class TelegramTestNotificationWithoutToTelegram extends Notification
{
    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['telegram'];
    }
}

class TelegramTestNotifiable
{
    public ?string $telegramChatId = null;

    public function routeNotificationFor(string $driver): ?string
    {
        return $driver === 'telegram' ? $this->telegramChatId : null;
    }
}

beforeEach(function () {
    config([
        'sentinel-log.channels.telegram.bot_token' => null,
        'sentinel-log.channels.telegram.chat_id'   => null,
    ]);
});

it('posts to the telegram bot api with the bot token in the url and the chat id in the payload', function () {
    Http::fake();
    config([
        'sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'   => '999888777',
    ]);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotification);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://api.telegram.org/bot123456:ABC-DEF/sendMessage'
            && $request['chat_id'] === '999888777'
            && $request['text'] === 'New device login detected.';
    });
});

it('prefers a per notifiable chat id over the config default', function () {
    Http::fake();
    config([
        'sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'   => '999888777',
    ]);

    $notifiable = new TelegramTestNotifiable;
    $notifiable->telegramChatId = '111222333';

    (new TelegramWebhookChannel)->send($notifiable, new TelegramTestNotification);

    Http::assertSent(fn ($request) => $request['chat_id'] === '111222333');
});

it('does nothing when no bot token is configured', function () {
    Http::fake();
    config(['sentinel-log.channels.telegram.chat_id' => '999888777']);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotification);

    Http::assertNothingSent();
});

it('does nothing when no chat id is configured or routed', function () {
    Http::fake();
    config(['sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF']);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotification);

    Http::assertNothingSent();
});

it('does not throw when the telegram api request fails, it just logs a warning', function () {
    Http::fake(['*' => Http::response('bad request', 400)]);
    config([
        'sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'   => '999888777',
    ]);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotification);

    expect(true)->toBeTrue();
});

it('does not throw when the connection itself fails', function () {
    Http::fake(function () {
        throw new \Illuminate\Http\Client\ConnectionException('Could not connect');
    });
    config([
        'sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'   => '999888777',
    ]);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotification);

    expect(true)->toBeTrue();
});

it('skips notifications that have no toTelegram method', function () {
    Http::fake();
    config([
        'sentinel-log.channels.telegram.bot_token' => '123456:ABC-DEF',
        'sentinel-log.channels.telegram.chat_id'   => '999888777',
    ]);

    (new TelegramWebhookChannel)->send(new TelegramTestNotifiable, new TelegramTestNotificationWithoutToTelegram);

    Http::assertNothingSent();
});
