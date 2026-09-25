<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

class DiscordWebhookChannel extends WebhookChannel
{
    protected function configKey(): string
    {
        return 'discord';
    }

    protected function routeKey(): string
    {
        return 'discord';
    }

    protected function notificationMethod(): string
    {
        return 'toDiscord';
    }

    protected function displayName(): string
    {
        return 'Discord';
    }
}
