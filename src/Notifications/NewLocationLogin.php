<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications;

use Harryes\SentinelLog\Models\LocationVerification;
use Harryes\SentinelLog\Notifications\Messages\DiscordMessage;
use Harryes\SentinelLog\Notifications\Messages\SlackMessage;
use Harryes\SentinelLog\Notifications\Messages\TeamsMessage;
use Harryes\SentinelLog\Notifications\Messages\TelegramMessage;
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

        // Laravel's MailMessage only renders the LAST ->action() call in the default
        // template. Using two ->action() calls silently drops the first button.
        // The deny action is the security-critical CTA and gets the primary button.
        // The verify link is presented as inline text so both are always visible.
        return (new MailMessage)
            ->subject('New Login Location Detected')
            ->greeting('Security Alert')
            ->line('We detected a login to your account from a new location.')
            ->line("**Location:** {$city}, {$country}")
            ->line("**IP Address:** {$this->verification->ip_address}")
            ->line("**Time:** " . $this->verification->created_at->format('D, d M Y H:i:s T'))
            ->line("If this was you, [click here to confirm the login]({$verifyUrl}).")
            ->line('If you did **not** log in, click the button below to immediately revoke this session.')
            ->action('No, deny this login', $denyUrl)
            ->line("Both links expire in {$expiresIn} minutes.")
            ->salutation('The Security Team');
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
        $location = $this->verification->location ?? [];
        $city = $location['city'] ?? 'Unknown';
        $country = $location['country'] ?? 'Unknown';

        $verifyUrl = route('sentinel-log.location.verify', $this->verification->token);
        $denyUrl = route('sentinel-log.location.deny', $this->verification->token);

        return (new DiscordMessage)->content(
            "**New login location detected**\n" .
            "Location: {$city}, {$country}\n" .
            "IP: {$this->verification->ip_address}\n" .
            "Time: " . $this->verification->created_at->format('D, d M Y H:i:s T') . "\n" .
            "This was me: {$verifyUrl}\n" .
            "Not me, revoke this session: {$denyUrl}"
        );
    }

    protected function chatAlertText(): string
    {
        $location = $this->verification->location ?? [];
        $city = $location['city'] ?? 'Unknown';
        $country = $location['country'] ?? 'Unknown';

        $verifyUrl = route('sentinel-log.location.verify', $this->verification->token);
        $denyUrl = route('sentinel-log.location.deny', $this->verification->token);

        return "New login location detected.\n" .
            "Location: {$city}, {$country}\n" .
            "IP: {$this->verification->ip_address}\n" .
            "Time: " . $this->verification->created_at->format('D, d M Y H:i:s T') . "\n" .
            "This was me: {$verifyUrl}\n" .
            "Not me, revoke this session: {$denyUrl}";
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'event'           => 'new_location_login',
            'verification_id' => $this->verification->id,
            'ip_address'      => $this->verification->ip_address,
            'location'        => $this->verification->location,
            'expires_at'      => $this->verification->expires_at->toDateTimeString(),
        ];
    }
}
