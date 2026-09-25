<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Notifications\Messages\DiscordMessage;
use Harryes\SentinelLog\Notifications\Messages\SlackMessage;
use Harryes\SentinelLog\Notifications\Messages\TeamsMessage;
use Harryes\SentinelLog\Notifications\Messages\TelegramMessage;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class FailedLoginAttempt extends Notification
{
    use Queueable;

    public function __construct(
        protected AuthenticationLog $log,
        protected int $attemptCount
    ) {}

    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return config('sentinel-log.notifications.failed_attempt.channels', ['mail']);
    }

    public function toMail(object $notifiable): MailMessage
    {
        $location = $this->log->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';
        $browser  = $this->log->device_info['browser'] ?? 'Unknown';

        return (new MailMessage)
            ->subject('Multiple Failed Login Attempts')
            ->line("There have been **{$this->attemptCount}** failed login attempts on your account.")
            ->line("**Last Attempt IP:** {$this->log->ip_address}")
            ->line("**Location:** {$city}, {$country}")
            ->line("**Device:** {$browser}")
            ->line("**Time:** {$this->log->event_at}")
            ->action('Secure Your Account', url('/'));
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        return (new SlackMessage)->text($this->chatAlertText());
    }

    public function toTeams(object $notifiable): TeamsMessage
    {
        return (new TeamsMessage)->text($this->chatAlertText());
    }

    public function toTelegram(object $notifiable): TelegramMessage
    {
        return (new TelegramMessage)->text($this->chatAlertText());
    }

    public function toDiscord(object $notifiable): DiscordMessage
    {
        $location = $this->log->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';

        return (new DiscordMessage)->content(
            "**{$this->attemptCount} failed login attempts on this account**\n" .
            "Last IP: {$this->log->ip_address}\n" .
            "Location: {$city}, {$country}\n" .
            "Time: {$this->log->event_at}"
        );
    }

    protected function chatAlertText(): string
    {
        $location = $this->log->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';

        return "{$this->attemptCount} failed login attempts on this account.\n" .
            "Last IP: {$this->log->ip_address}\n" .
            "Location: {$city}, {$country}\n" .
            "Time: {$this->log->event_at}";
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'event'         => 'failed_login_attempt',
            'ip_address'    => $this->log->ip_address,
            'location'      => $this->log->location,
            'attempt_count' => $this->attemptCount,
            'event_at'      => $this->log->event_at->toDateTimeString(),
        ];
    }
}
