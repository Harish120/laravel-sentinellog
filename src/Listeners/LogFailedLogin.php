<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Harryes\SentinelLog\Contracts\NotifiableWithFailedAttempt;
use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\DeviceFingerprintService;
use Harryes\SentinelLog\Services\GeolocationService;
use Illuminate\Auth\Events\Failed;

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

        // Record the attempt BEFORE running checks — checkGeoFence() and
        // checkBruteForce() can abort(), so any create() after them is never reached.
        $log = AuthenticationLog::create([
            'authenticatable_id'   => $event->user?->getKey(),
            'authenticatable_type' => $event->user !== null ? get_class($event->user) : null,
            'event_name'           => 'failed',
            'ip_address'           => request()->ip(),
            'user_agent'           => request()->userAgent(),
            'device_info'          => $this->fingerprintService->generate(),
            'location'             => $this->geoService->getLocation(request()->ip()),
            'is_successful'        => false,
            'event_at'             => now(),
        ]);

        // Notify BEFORE checks — checkGeoFence/checkBruteForce can abort(), which
        // would skip this notification for the threshold-crossing attempt.
        if ($event->user instanceof NotifiableWithFailedAttempt) {
            $event->user->notifyFailedAttempt($log);
        }

        $this->bruteForceService->checkGeoFence($event->user);
        $this->bruteForceService->checkBruteForce();
    }
}
