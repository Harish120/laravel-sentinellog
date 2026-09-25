<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

/**
 * Telegram does not take a plain webhook URL, the bot token goes in the URL
 * itself and the chat to post into is a separate value, so this overrides
 * buildRequest() instead of relying on the base "webhook URL" resolution.
 */
class TelegramWebhookChannel extends WebhookChannel
{
    protected function configKey(): string
    {
        return 'telegram';
    }

    protected function routeKey(): string
    {
        return 'telegram';
    }

    protected function notificationMethod(): string
    {
        return 'toTelegram';
    }

    protected function displayName(): string
    {
        return 'Telegram';
    }

    /**
     * @param array<string, mixed> $payload
     * @return array{url: string, payload: array<string, mixed>}|null
     */
    protected function buildRequest(object $notifiable, array $payload): ?array
    {
        $botToken = config('sentinel-log.channels.telegram.bot_token');

        if (blank($botToken)) {
            return null;
        }

        $chatId = $this->resolveChatId($notifiable);

        if (blank($chatId)) {
            return null;
        }

        return [
            'url'     => "https://api.telegram.org/bot{$botToken}/sendMessage",
            'payload' => array_merge(['chat_id' => $chatId], $payload),
        ];
    }

    protected function resolveChatId(object $notifiable): ?string
    {
        if (method_exists($notifiable, 'routeNotificationFor')) {
            $chatId = $notifiable->routeNotificationFor($this->routeKey());

            if (! blank($chatId)) {
                return (string) $chatId;
            }
        }

        $chatId = config('sentinel-log.channels.telegram.chat_id');

        return blank($chatId) ? null : (string) $chatId;
    }
}
