<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewDeviceLogin extends Notification
{
    use Queueable;

    protected AuthenticationLog $log;

    public function __construct(AuthenticationLog $log)
    {
        $this->log = $log;
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
        $location = $this->log->location ?? [];
        $city = $location['city'] ?? 'Unknown';
        $country = $location['country'] ?? 'Unknown';

        return (new MailMessage)
            ->subject('New Device Login Detected')
            ->line('A login was detected from a new device.')
            ->line("IP: {$this->log->ip_address}")
            ->line("Location: {$city}, {$country}")
            ->line("Device: {$this->log->device_info['browser']}")
            ->line("Time: {$this->log->event_at}")
            ->action('Review Activity', url('/'));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'event' => 'new_device_login',
            'ip_address' => $this->log->ip_address,
            'location' => $this->log->location,
            'event_at' => $this->log->event_at->toDateTimeString(),
        ];
    }
}
