<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\SentinelSession;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SessionHijackingDetected extends Notification
{
    use Queueable;

    protected SentinelSession $session;

    protected string $reason;

    public function __construct(SentinelSession $session, string $reason)
    {
        $this->session = $session;
        $this->reason = $reason;
    }

    /**
     * @return array<int, string>
     */
    public function via(): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $location = $this->session->location ?? [];
        $city = @$location['city'] ?? 'Unknown';
        $country = @$location['country'] ?? 'Unknown';

        return (new MailMessage)
            ->subject('Potential SentinelSession Hijacking Detected')
            ->line('We detected suspicious activity on your account.')
            ->line("Reason: {$this->reason}")
            ->line("IP: {$this->session->ip_address}")
            ->line("Location: {$city}, {$country}")
            ->line("Device: {$this->session->device_info['browser']}")
            ->line("Last Activity: {$this->session->last_activity}")
            ->action('Review Sessions', url('/sessions'));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'event' => 'session_hijacking',
            'session_id' => $this->session->session_id,
            'ip_address' => $this->session->ip_address,
            'location' => $this->session->location,
            'reason' => $this->reason,
        ];
    }
}
