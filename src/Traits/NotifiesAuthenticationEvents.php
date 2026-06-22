<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Traits;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Notifications\FailedLoginAttempt;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;

trait NotifiesAuthenticationEvents
{
    use Notifiable;

    /**
     * Get the authentication logs for this model.
     */
    public function authenticationLogs(): MorphMany
    {
        return $this->morphMany(AuthenticationLog::class, 'authenticatable');
    }

    /**
     * Notify about repeated failed login attempts.
     */
    public function notifyFailedAttempt(AuthenticationLog $log): void
    {
        if (! config('sentinel-log.notifications.failed_attempt.enabled', false)) {
            return;
        }

        $threshold = config('sentinel-log.notifications.failed_attempt.threshold', 3);
        $window = config('sentinel-log.notifications.failed_attempt.window', 60);

        $recentFailures = $this->authenticationLogs()
            ->where('event_name', 'failed')
            ->where('event_at', '>=', now()->subMinutes($window))
            ->count();

        if ($recentFailures >= $threshold) {
            // Send at most once per window to prevent notification spam on
            // repeated attempts above the threshold.
            $cooldownKey = 'sentinel_failed_notif_' . $this->getKey();
            if (! Cache::has($cooldownKey)) {
                Notification::send($this, new FailedLoginAttempt($log, $recentFailures));
                Cache::put($cooldownKey, true, now()->addMinutes($window));
            }
        }
    }
}
