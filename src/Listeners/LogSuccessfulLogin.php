<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Listeners;

use Exception;
use Harryes\SentinelLog\Contracts\TwoFactorAuthenticatable;
use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Notifications\NewDeviceLogin;
use Harryes\SentinelLog\Notifications\SessionHijackingDetected;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\DeviceFingerprintService;
use Harryes\SentinelLog\Services\GeolocationService;
use Harryes\SentinelLog\Services\SessionTrackingService;
use Harryes\SentinelLog\Services\TwoFactorAuthenticationService;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Notification;

class LogSuccessfulLogin
{
    protected DeviceFingerprintService $fingerprintService;

    protected GeolocationService $geoService;

    protected TwoFactorAuthenticationService $twoFactorService;

    protected SessionTrackingService $sessionService;

    protected BruteForceProtectionService $bruteForceService;

    public function __construct(
        DeviceFingerprintService $fingerprintService,
        GeolocationService $geoService,
        TwoFactorAuthenticationService $twoFactorService,
        SessionTrackingService $sessionService,
        BruteForceProtectionService $bruteForceService
    ) {
        $this->fingerprintService = $fingerprintService;
        $this->geoService = $geoService;
        $this->twoFactorService = $twoFactorService;
        $this->sessionService = $sessionService;
        $this->bruteForceService = $bruteForceService;
    }

    public function handle(Login $event): void
    {
        if (! config('sentinel-log.enabled', true) || ! config('sentinel-log.events.login', true)) {
            return;
        }

        if ($this->bruteForceService->isIpBlocked(request()->ip())) {
            abort(403, 'Your IP has been blocked due to suspicious activity.');
        }

        try {
            $session = $this->sessionService->track($event->user);
        } catch (Exception $e) {
            abort(403, $e->getMessage()); // e.g., "Maximum active sessions exceeded"
        }

        $deviceInfo = $this->fingerprintService->generate();
        $hash = $deviceInfo['hash'] ?? '';
        $isNewDevice = config('sentinel-log.notifications.new_device.enabled', false) &&
            $this->fingerprintService->isNewDevice($event->user, $hash);

        $log = AuthenticationLog::create([
            'authenticatable_id' => $event->user->getKey(),
            'authenticatable_type' => get_class($event->user),
            'session_id' => $session->session_id,
            'event_name' => 'login',
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'device_info' => $deviceInfo,
            'location' => $this->geoService->getLocation(request()->ip()),
            'is_successful' => true,
        ]);

        $this->bruteForceService->checkGeoFence();
        $this->bruteForceService->clearAttempts(request()->ip());

        $user = $event->user;

        if ($user instanceof TwoFactorAuthenticatable) {
            $twoFactorEnabled = (bool) $user->getTwoFactorSecret();
            if ($twoFactorEnabled && ! session()->has('2fa_verified')) {
                AuthenticationLog::create([
                    'authenticatable_id' => $event->user->getKey(),
                    'authenticatable_type' => get_class($event->user),
                    'session_id' => $session->session_id,
                    'event_name' => '2fa_required',
                    'ip_address' => request()->ip(),
                    'user_agent' => request()->userAgent(),
                    'device_info' => $this->fingerprintService->generate(),
                    'location' => $this->geoService->getLocation(request()->ip()),
                    'is_successful' => false,
                ]);
            }
        }

        if ($isNewDevice) {
            Notification::send($event->user, new NewDeviceLogin($log));
        }

        if (config('sentinel-log.sessions.enabled', true)) {
            $hijacking = $this->sessionService->detectHijacking($session);
            if ($hijacking) {
                Notification::send($event->user, new SessionHijackingDetected($hijacking['session'], $hijacking['reason']));
                AuthenticationLog::create([
                    'authenticatable_id' => $event->user->getKey(),
                    'authenticatable_type' => get_class($event->user),
                    'session_id' => $session->session_id,
                    'event_name' => 'hijacking_detected',
                    'ip_address' => request()->ip(),
                    'user_agent' => request()->userAgent(),
                    'device_info' => $this->fingerprintService->generate(),
                    'location' => $this->geoService->getLocation(request()->ip()),
                    'is_successful' => false,
                ]);
            }
        }
    }
}
