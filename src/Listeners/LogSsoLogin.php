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
        if (! config('sentinel-log.sso.enabled', false) || ! request()->has('sso_token') || Auth::check()) {
            return; // Exit if not SSO, no token, or already logged in
        }

        $this->bruteForceService->checkGeoFence(); // user not yet resolved at this point
        $user = $this->ssoService->validateToken(request('sso_token'), config('sentinel-log.sso.client_id', 'default_client'));
        if (! $user) {
            abort(401, 'Invalid SSO token.');
        }

        // Log SSO event manually without re-triggering Auth::login()
        try {
            $session = $this->sessionService->track($user);
        } catch (\Exception $e) {
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
        ]);

        $this->bruteForceService->clearAttempts(request()->ip());
    }
}
