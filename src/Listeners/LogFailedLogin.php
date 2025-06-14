<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\DeviceFingerprintService;
use Harryes\SentinelLog\Services\GeolocationService;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\Auth\Authenticatable;

class LogFailedLogin
{
    protected DeviceFingerprintService $fingerprintService;

    protected GeolocationService $geoService;

    protected BruteForceProtectionService $bruteForceService;

    public function __construct(
        DeviceFingerprintService $fingerprintService,
        GeolocationService $geoService,
        BruteForceProtectionService $bruteForceService
    ) {
        $this->fingerprintService = $fingerprintService;
        $this->geoService = $geoService;
        $this->bruteForceService = $bruteForceService;
    }

    public function handle(Failed $event): void
    {
        if (! config('sentinel-log.enabled', true) || ! config('sentinel-log.events.failed', true)) {
            return;
        }

        $this->bruteForceService->checkGeoFence();
        $this->bruteForceService->checkBruteForce();

        $log = AuthenticationLog::create([
            'authenticatable_id' => $event->user ? $event->user->getKey() : null,
            'authenticatable_type' => $event->user ? get_class($event->user) : null,
            'event_name' => 'failed',
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'device_info' => $this->fingerprintService->generate(),
            'location' => $this->geoService->getLocation(request()->ip()),
            'is_successful' => false,
        ]);

        if ($event->user instanceof NotifiableWithFailedAttempt) {
            $event->user->notifyFailedAttempt($log->toArray());
        }
    }
}

/**
 * Interface for users that can be notified of failed login attempts.
 */
interface NotifiableWithFailedAttempt extends Authenticatable
{
    /**
     * Notify the user of a failed login attempt.
     *
     * @param  array<string, mixed>  $data  The authentication log data
     */
    public function notifyFailedAttempt(array $data): void;
}
