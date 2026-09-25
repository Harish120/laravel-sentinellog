<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

class TeamsWebhookChannel extends WebhookChannel
{
    protected function configKey(): string
    {
        return 'teams';
    }

    protected function routeKey(): string
    {
        return 'teams';
    }

    protected function notificationMethod(): string
    {
        return 'toTeams';
    }

    protected function displayName(): string
    {
        return 'Microsoft Teams';
    }
}
