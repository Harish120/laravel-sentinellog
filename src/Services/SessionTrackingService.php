<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Exception;
use Harryes\SentinelLog\Models\SentinelSession;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

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
     */
    public function track(Authenticatable $authenticatable): SentinelSession
    {
        if (! config('sentinel-log.sessions.enabled', true)) {
            throw new Exception('Session tracking is disabled');
        }

        $sessionId = session()->getId();

        // Check active sessions for the user
        $maxSessions = config('sentinel-log.sessions.max_active', 5);
        $activeSessions = SentinelSession::where('authenticatable_id', $authenticatable->getKey())
            ->where('authenticatable_type', get_class($authenticatable))
            ->count();

        // Exclude current session from count if it exists
        $currentSession = SentinelSession::where('session_id', $sessionId)->first();
        if ($currentSession) {
            $activeSessions = max(0, $activeSessions - 1); // Don't count the session being updated
        }

        if ($activeSessions >= $maxSessions) {
            throw new Exception('Maximum active sessions exceeded');
        }

        // Create or update session
        $session = SentinelSession::updateOrCreate(
            ['session_id' => $sessionId],
            [
                'authenticatable_id' => $authenticatable->getKey(),
                'authenticatable_type' => get_class($authenticatable),
                'ip_address' => $this->request->ip(),
                'user_agent' => $this->request->userAgent(),
                'device_info' => $this->fingerprintService->generate(),
                'location' => $this->geoService->getLocation($this->request->ip()),
                'last_activity' => now(),
            ]
        );

        return $session;
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

            if (
                ($currentLocation['lat'] ?? 0) !== ($otherLocation['lat'] ?? 0) ||
                ($currentLocation['lon'] ?? 0) !== ($otherLocation['lon'] ?? 0) ||
                ($currentSession->device_info['hash'] ?? '') !== ($session->device_info['hash'] ?? '')
            ) {
                return [
                    'session' => $session,
                    'reason' => 'Location or device mismatch detected',
                ];
            }
        }

        return null;
    }
}
