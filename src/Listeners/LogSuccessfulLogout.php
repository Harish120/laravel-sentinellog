<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\DeviceFingerprintService;
use Harryes\SentinelLog\Services\GeolocationService;
use Harryes\SentinelLog\Services\SessionTrackingService;
use Illuminate\Auth\Events\Logout;

class LogSuccessfulLogout
{
    protected DeviceFingerprintService $fingerprintService;

    protected GeolocationService $geoService;

    protected SessionTrackingService $sessionService;

    public function __construct(
        DeviceFingerprintService $fingerprintService,
        GeolocationService $geoService,
        SessionTrackingService $sessionService
    ) {
        $this->fingerprintService = $fingerprintService;
        $this->geoService = $geoService;
        $this->sessionService = $sessionService;
    }

    public function handle(Logout $event): void
    {
        if (! config('sentinel-log.enabled', true) || ! config('sentinel-log.events.logout', true)) {
            return;
        }

        $sessionId = session()->getId();
        $session = $this->sessionService->track($event->user);

        AuthenticationLog::create([
            'authenticatable_id' => $event->user->getKey(),
            'authenticatable_type' => get_class($event->user),
            'session_id' => $sessionId,
            'event_name' => 'logout',
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'device_info' => $this->fingerprintService->generate(),
            'location' => $this->geoService->getLocation(request()->ip()),
            'is_successful' => true,
        ]);

        $session->delete(); // Clean up session record on logout
    }
}
