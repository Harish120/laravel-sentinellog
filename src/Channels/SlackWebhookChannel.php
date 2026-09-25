<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

class SlackWebhookChannel extends WebhookChannel
{
    protected function configKey(): string
    {
        return 'slack';
    }

    protected function routeKey(): string
    {
        return 'slack';
    }

    protected function notificationMethod(): string
    {
        return 'toSlack';
    }

    protected function displayName(): string
    {
        return 'Slack';
    }
}
