<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\DeviceFingerprintService;
use Harryes\SentinelLog\Services\GeolocationService;
use Harryes\SentinelLog\Services\SessionTrackingService;
use Harryes\SentinelLog\Services\SsoAuthenticationService;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;

class LogSsoLogin
{
    protected DeviceFingerprintService $fingerprintService;

    protected GeolocationService $geoService;

    protected SessionTrackingService $sessionService;

    protected BruteForceProtectionService $bruteForceService;

    protected SsoAuthenticationService $ssoService;

    public function __construct(
        DeviceFingerprintService $fingerprintService,
        GeolocationService $geoService,
        SessionTrackingService $sessionService,
        BruteForceProtectionService $bruteForceService,
        SsoAuthenticationService $ssoService
    ) {
        $this->fingerprintService = $fingerprintService;
        $this->geoService = $geoService;
        $this->sessionService = $sessionService;
        $this->bruteForceService = $bruteForceService;
        $this->ssoService = $ssoService;
    }

    public function handle(Login $event): void
    {
        if (! config('sentinel-log.sso.enabled', false) || ! request()->has('sso_token')) {
            return;
        }

        // Note: Auth::check() cannot be used here — the Login event fires after
        // Auth::login() has already set the user in the guard, so it is always true.

        $this->bruteForceService->checkGeoFence(); // user not yet resolved at this point
        $user = $this->ssoService->validateToken(request('sso_token'), config('sentinel-log.sso.client_id', 'default_client'));
        if (! $user) {
            // Auth::login() already completed — log out before aborting so the
            // attacker cannot reuse the authenticated session on the next request.
            Auth::logout();
            abort(401, 'Invalid SSO token.');
        }

        // Log SSO event manually without re-triggering Auth::login()
        try {
            $session = $this->sessionService->track($user);
        } catch (\Exception $e) {
            Auth::logout();
            abort(403, $e->getMessage());
        }

        $sessionId = $session !== null ? $session->session_id : session()->getId();

        AuthenticationLog::create([
            'authenticatable_id'   => $user->getKey(),
            'authenticatable_type' => get_class($user),
            'session_id'           => $sessionId,
            'event_name'           => 'sso_login',
            'ip_address'           => request()->ip(),
            'user_agent'           => request()->userAgent(),
            'device_info'          => $this->fingerprintService->generate(),
            'location'             => $this->geoService->getLocation(request()->ip()),
            'is_successful'        => true,
            'event_at'             => now(),
        ]);

        $this->bruteForceService->clearAttempts(request()->ip());
    }
}
