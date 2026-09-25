<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Channels;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Base class for optional chat webhook channels (Slack, Discord, Microsoft
 * Teams, Telegram, and a generic custom webhook). A new channel is usually
 * just a small subclass naming its config key, route key, and notification
 * method. Telegram needs a different request shape (bot token in the URL,
 * chat id in the payload), so it overrides buildRequest() instead.
 *
 * These channels are opt-in. If one is not configured, or the request fails,
 * we log a warning and move on instead of throwing. A broken Slack webhook
 * must never take down a user's login.
 */
abstract class WebhookChannel
{
    /**
     * The key under config('sentinel-log.channels.*') for this channel.
     */
    abstract protected function configKey(): string;

    /**
     * The route key notifiable models can use via routeNotificationFor().
     */
    abstract protected function routeKey(): string;

    /**
     * The method Laravel will call on the notification (e.g. toSlack).
     */
    abstract protected function notificationMethod(): string;

    /**
     * A short, human readable name used in log messages.
     */
    abstract protected function displayName(): string;

    public function send(object $notifiable, Notification $notification): void
    {
        $method = $this->notificationMethod();

        if (! method_exists($notification, $method)) {
            return;
        }

        $message = $notification->{$method}($notifiable);
        $payload = is_array($message) ? $message : $message->toArray();

        $request = $this->buildRequest($notifiable, $payload);

        if ($request === null) {
            Log::warning("SentinelLog: {$this->displayName()} channel is not configured, skipping notification.", [
                'notification' => get_class($notification),
            ]);

            return;
        }

        try {
            $response = Http::timeout($this->timeout())->post($request['url'], $request['payload']);

            if ($response->failed()) {
                Log::warning("SentinelLog: {$this->displayName()} webhook returned an error response.", [
                    'notification' => get_class($notification),
                    'status'       => $response->status(),
                ]);
            }
        } catch (Throwable $e) {
            Log::warning("SentinelLog: {$this->displayName()} notification could not be delivered.", [
                'notification' => get_class($notification),
                'error'        => $e->getMessage(),
            ]);
        }
    }

    /**
     * Build the outgoing request, or return null when this channel has not
     * been configured (no webhook URL, no bot token, and so on). The default
     * implementation covers a plain "webhook URL plus JSON body" channel,
     * which is all Slack, Discord, Teams, and the generic webhook need.
     *
     * @param array<string, mixed> $payload
     * @return array{url: string, payload: array<string, mixed>}|null
     */
    protected function buildRequest(object $notifiable, array $payload): ?array
    {
        $webhookUrl = $this->resolveWebhookUrl($notifiable);

        if (blank($webhookUrl)) {
            return null;
        }

        return ['url' => $webhookUrl, 'payload' => $payload];
    }

    protected function resolveWebhookUrl(object $notifiable): ?string
    {
        if (method_exists($notifiable, 'routeNotificationFor')) {
            $route = $notifiable->routeNotificationFor($this->routeKey());

            if (! blank($route)) {
                return $route;
            }
        }

        return config("sentinel-log.channels.{$this->configKey()}.webhook_url");
    }

    protected function timeout(): int
    {
        return (int) config("sentinel-log.channels.{$this->configKey()}.timeout", 3);
    }
}
