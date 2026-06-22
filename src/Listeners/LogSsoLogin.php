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
use Symfony\Component\HttpKernel\Exception\HttpException;

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

        // Reject tokens submitted via GET query string — they appear in server logs,
        // browser history and referrer headers. SSO tokens must travel via POST body.
        if (request()->query('sso_token') !== null) {
            return;
        }

        // Geo-fence runs before user is resolved. Auth::login() already completed so
        // we must logout before re-throwing to prevent auth bypass on next request.
        try {
            $this->bruteForceService->checkGeoFence();
        } catch (HttpException $e) {
            Auth::logout();
            throw $e;
        }

        $user = $this->ssoService->validateToken(request()->post('sso_token'), config('sentinel-log.sso.client_id', 'default_client'));

        if (! $user) {
            // Token is invalid or not an SSO login — silently skip.
            // Do NOT abort or logout: the user may have logged in via normal credentials
            // with an unrelated sso_token parameter present in the request.
            return;
        }

        // Ensure the SSO token's user matches the user who just authenticated.
        // A mismatched token means someone appended another user's SSO token to a
        // normal login request — skip to prevent audit log pollution and wrong user tracking.
        if ($user->getKey() !== $event->user->getKey() ||
            get_class($user) !== get_class($event->user)) {
            return;
        }

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
