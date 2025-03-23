<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class FailedLoginAttempt extends Notification
{
    use Queueable;

    protected AuthenticationLog $log;
    protected int $attemptCount;

    public function __construct(AuthenticationLog $log, int $attemptCount)
    {
        $this->log = $log;
        $this->attemptCount = $attemptCount;
    }

    public function via(object $notifiable): array
    {
        return config('sentinel-log.notifications.failed_attempt.channels', ['mail']);
    }

    public function toMail(object $notifiable): MailMessage
    {
        $location = $this->log->location ?? [];
        $city = $location['city'] ?? 'Unknown';
        $country = $location['country'] ?? 'Unknown';

        return (new MailMessage)
            ->subject('Multiple Failed Login Attempts')
            ->line("There have been {$this->attemptCount} failed login attempts on your account.")
            ->line("Last Attempt IP: {$this->log->ip_address}")
            ->line("Location: {$city}, {$country}")
           ->line("Device: {$this->log->device_info['browser']}")
            ->line("Time: {$this->log->event_at}")
            ->action('Secure Your Account', url('/'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'event' => 'failed_login_attempt',
            'ip_address' => $this->log->ip_address,
            'location' => $this->log->location,
            'attempt_count' => $this->attemptCount,
            'event_at' => $this->log->event_at->toDateTimeString(),
        ];
    }
}