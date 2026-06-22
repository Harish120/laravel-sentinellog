<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\GeolocationService;
use Harryes\SentinelLog\Services\SessionTrackingService;
use Illuminate\Auth\Events\Logout;

class LogSuccessfulLogout
{
    protected GeolocationService $geoService;

    protected SessionTrackingService $sessionService;

    public function __construct(GeolocationService $geoService, SessionTrackingService $sessionService)
    {
        $this->geoService = $geoService;
        $this->sessionService = $sessionService;
    }

    public function handle(Logout $event): void
    {
        if (! config('sentinel-log.enabled', true) || ! config('sentinel-log.events.logout', true)) {
            return;
        }

        // Guard against null — Auth::logout() called on an already-logged-out guard
        // (which can happen in error-path listeners) fires a second Logout event
        // with $user = null.
        if ($event->user === null) {
            return;
        }

        $sessionId = session()->getId();

        AuthenticationLog::create([
            'authenticatable_id'   => $event->user->getKey(),
            'authenticatable_type' => get_class($event->user),
            'session_id'           => $sessionId,
            'event_name'           => 'logout',
            'ip_address'           => request()->ip(),
            'user_agent'           => request()->userAgent(),
            'location'             => $this->geoService->getLocation(request()->ip()),
            'is_successful'        => true,
            'event_at'             => now(),
        ]);

        $this->sessionService->terminate($sessionId);
    }
}
