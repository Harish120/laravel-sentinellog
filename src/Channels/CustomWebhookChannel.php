<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

/**
 * A catch-all channel for anything that is not one of the named ones. It
 * posts the notification's existing toArray() payload (the same data the
 * database channel stores) to a single webhook URL, so it works for Zapier,
 * n8n, PagerDuty, or any endpoint of your own without needing a dedicated
 * toWebhook() method on every notification.
 */
class CustomWebhookChannel extends WebhookChannel
{
    protected function configKey(): string
    {
        return 'webhook';
    }

    protected function routeKey(): string
    {
        return 'webhook';
    }

    protected function notificationMethod(): string
    {
        return 'toArray';
    }

    protected function displayName(): string
    {
        return 'custom webhook';
    }
}
