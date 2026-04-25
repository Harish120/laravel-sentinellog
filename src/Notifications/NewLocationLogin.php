<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\LocationVerification;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewLocationLogin extends Notification
{
    use Queueable;

    public function __construct(protected LocationVerification $verification) {}

    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return config('sentinel-log.location_verification.channels', ['mail']);
    }

    public function toMail(object $notifiable): MailMessage
    {
        $location = $this->verification->location ?? [];
        $city = $location['city'] ?? 'Unknown';
        $country = $location['country'] ?? 'Unknown';

        $verifyUrl = route('sentinel-log.location.verify', $this->verification->token);
        $denyUrl = route('sentinel-log.location.deny', $this->verification->token);
        $expiresIn = config('sentinel-log.location_verification.token_ttl', 30);

        return (new MailMessage)
            ->subject('New Login Location Detected')
            ->greeting('Security Alert')
            ->line('We detected a login to your account from a new location.')
            ->line("**Location:** {$city}, {$country}")
            ->line("**IP Address:** {$this->verification->ip_address}")
            ->line("**Time:** " . $this->verification->created_at->format('D, d M Y H:i:s T'))
            ->line('If this was you, no action is needed — click confirm below to trust this location.')
            ->action('Yes, this was me', $verifyUrl)
            ->line('If you did **not** log in, click the button below to immediately revoke this session.')
            ->action('No, deny this login', $denyUrl)
            ->line("This link expires in {$expiresIn} minutes.")
            ->salutation('The Security Team');
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'event' => 'new_location_login',
            'ip_address' => $this->verification->ip_address,
            'location' => $this->verification->location,
            'token' => $this->verification->token,
            'expires_at' => $this->verification->expires_at->toDateTimeString(),
        ];
    }
}
