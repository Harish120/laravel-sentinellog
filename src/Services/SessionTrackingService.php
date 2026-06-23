<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Exception;
use Harryes\SentinelLog\Models\SentinelSession;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class SessionTrackingService
{
    protected Request $request;

    protected DeviceFingerprintService $fingerprintService;

    protected GeolocationService $geoService;

    public function __construct(Request $request, DeviceFingerprintService $fingerprintService, GeolocationService $geoService)
    {
        $this->request = $request;
        $this->fingerprintService = $fingerprintService;
        $this->geoService = $geoService;
    }

    /**
     * Track or update a session, enforcing max session limit.
     * Returns null when session tracking is disabled.
     *
     * @throws Exception when the max active session limit is reached
     */
    public function track(Authenticatable $authenticatable): ?SentinelSession
    {
        if (! config('sentinel-log.sessions.enabled', true)) {
            return null;
        }

        $sessionId   = session()->getId();
        $maxSessions = config('sentinel-log.sessions.max_active', 5);
        $fingerprint = $this->fingerprintService->generate();
        $location    = $this->geoService->getLocation($this->request->ip());

        return DB::transaction(function () use ($authenticatable, $sessionId, $maxSessions, $fingerprint, $location) {
            // Lock rows for this user to prevent concurrent logins bypassing the limit
            $activeSessions = SentinelSession::where('authenticatable_id', $authenticatable->getKey())
                ->where('authenticatable_type', get_class($authenticatable))
                ->lockForUpdate()
                ->count();

            $currentExists = SentinelSession::where('session_id', $sessionId)->exists();
            if ($currentExists) {
                $activeSessions = max(0, $activeSessions - 1);
            }

            if ($activeSessions >= $maxSessions) {
                throw new Exception('Maximum active sessions exceeded');
            }

            return SentinelSession::updateOrCreate(
                ['session_id' => $sessionId],
                [
                    'authenticatable_id'   => $authenticatable->getKey(),
                    'authenticatable_type' => get_class($authenticatable),
                    'ip_address'           => $this->request->ip(),
                    'user_agent'           => $this->request->userAgent(),
                    'device_info'          => $fingerprint,
                    'location'             => $location,
                    'last_activity'        => now(),
                ]
            );
        });
    }

    /**
     * Remove the sentinel session record for the given session ID on logout.
     * Safe to call when session tracking is disabled — no-ops silently.
     */
    public function terminate(?string $sessionId): void
    {
        if (! $sessionId || ! config('sentinel-log.sessions.enabled', true)) {
            return;
        }

        SentinelSession::where('session_id', $sessionId)->delete();
    }

    /**
     * Check for potential session hijacking.
     *
     * @return array<string, mixed>|null
     */
    public function detectHijacking(SentinelSession $currentSession): ?array
    {
        $user = Auth::user();
        if (! $user) {
            return null;
        }

        $activeSessions = SentinelSession::where('authenticatable_id', $user->getKey())
            ->where('authenticatable_type', get_class($user))
            ->where('session_id', '!=', $currentSession->session_id)
            ->where('last_activity', '>=', now()->subMinutes(30))
            ->get();

        foreach ($activeSessions as $session) {
            $currentLocation = $currentSession->location ?? [];
            $otherLocation = $session->location ?? [];

            // Cast lat/lon to float before comparison — JSON deserialization can
            // produce int 0 vs float 0.0 for "unknown" coordinates, causing false positives.
            if (
                (float) ($currentLocation['lat'] ?? 0) !== (float) ($otherLocation['lat'] ?? 0) ||
                (float) ($currentLocation['lon'] ?? 0) !== (float) ($otherLocation['lon'] ?? 0) ||
                ($currentSession->device_info['hash'] ?? '') !== ($session->device_info['hash'] ?? '')
            ) {
                // Return the CURRENT (new) session as the suspicious one — it arrived
                // from a different location/device than the existing trusted sessions.
                // Returning the old session caused the notification email to describe
                // the trusted session as suspicious, which confused users.
                return [
                    'session' => $currentSession,
                    'reason'  => 'Location or device mismatch detected',
                ];
            }
        }

        return null;
    }
}
