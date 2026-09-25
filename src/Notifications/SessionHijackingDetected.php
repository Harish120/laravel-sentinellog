<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\SentinelSession;
use Harryes\SentinelLog\Notifications\Messages\DiscordMessage;
use Harryes\SentinelLog\Notifications\Messages\SlackMessage;
use Harryes\SentinelLog\Notifications\Messages\TeamsMessage;
use Harryes\SentinelLog\Notifications\Messages\TelegramMessage;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SessionHijackingDetected extends Notification
{
    use Queueable;

    public function __construct(
        protected SentinelSession $session,
        protected string $reason
    ) {}

    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return config('sentinel-log.notifications.session_hijacking.channels', ['mail']);
    }

    public function toMail(object $notifiable): MailMessage
    {
        $location = $this->session->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';
        $browser  = $this->session->device_info['browser'] ?? 'Unknown';

        return (new MailMessage)
            ->subject('Potential Session Hijacking Detected')
            ->line('We detected suspicious activity on your account.')
            ->line("**Reason:** {$this->reason}")
            ->line("**IP Address:** {$this->session->ip_address}")
            ->line("**Location:** {$city}, {$country}")
            ->line("**Device:** {$browser}")
            ->line("**Last Activity:** {$this->session->last_activity}")
            ->action('Review Sessions', url('/'));
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
        $location = $this->session->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';

        return (new DiscordMessage)->content(
            "**Possible session hijacking detected**\n" .
            "Reason: {$this->reason}\n" .
            "IP: {$this->session->ip_address}\n" .
            "Location: {$city}, {$country}\n" .
            "Last activity: {$this->session->last_activity}"
        );
    }

    protected function chatAlertText(): string
    {
        $location = $this->session->location ?? [];
        $city     = $location['city'] ?? 'Unknown';
        $country  = $location['country'] ?? 'Unknown';

        return "Possible session hijacking detected.\n" .
            "Reason: {$this->reason}\n" .
            "IP: {$this->session->ip_address}\n" .
            "Location: {$city}, {$country}\n" .
            "Last activity: {$this->session->last_activity}";
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'event'      => 'session_hijacking',
            'session_id' => $this->session->session_id,
            'ip_address' => $this->session->ip_address,
            'location'   => $this->session->location,
            'reason'     => $this->reason,
        ];
    }
}
