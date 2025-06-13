<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\BlockedIp;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class BruteForceProtectionService
{
    protected Request $request;

    protected GeolocationService $geoService;

    public function __construct(Request $request, GeolocationService $geoService)
    {
        $this->request = $request;
        $this->geoService = $geoService;
    }

    /**
     * Check if the IP is blocked.
     */
    public function isIpBlocked(string $ip): bool
    {
        if (!config('sentinel-log.brute_force.enabled', true)) {
            return false;
        }

        $blocked = BlockedIp::where('ip_address', $ip)->first();

        return $blocked && $blocked->isActive();
    }

    /**
     * Get current attempt count for an IP.
     */
    public function getAttempts(string $ip): int
    {
        if (!config('sentinel-log.brute_force.enabled', true)) {
            return 0;
        }

        return Cache::get("sentinel_brute_force_{$ip}", 0);
    }

    /**
     * Check and enforce brute force protection for failed attempts.
     */
    public function checkBruteForce(): void
    {
        if (!config('sentinel-log.brute_force.enabled', true)) {
            return;
        }

        $ip = $this->request->ip();
        if ($this->isIpBlocked($ip)) {
            abort(403, 'Your IP has been blocked due to suspicious activity.');
        }

        $threshold = config('sentinel-log.brute_force.threshold', 5);
        $window = config('sentinel-log.brute_force.window', 15);
        $cacheKey = "sentinel_brute_force_{$ip}";
        $attempts = Cache::get($cacheKey, 0) + 1;

        Cache::put($cacheKey, $attempts, now()->addMinutes($window));

        if ($attempts >= $threshold) {
            BlockedIp::create([
                'ip_address' => $ip,
                'expires_at' => now()->addHours(config('sentinel-log.brute_force.block_duration', 24)),
                'reason'     => 'Excessive failed login attempts',
            ]);
            Cache::forget($cacheKey);
            abort(403, 'Too many login attempts. Your IP is now blocked.');
        }
    }

    /**
     * Check geo-fencing rules.
     */
    public function checkGeoFence(): void
    {
        if (!config('sentinel-log.geo_fencing.enabled', false)) {
            return;
        }

        $allowedCountries = config('sentinel-log.geo_fencing.allowed_countries', []);
        if (empty($allowedCountries)) {
            return;
        }

        $location = $this->geoService->getLocation($this->request->ip());
        $country = $location['country'] ?? null;

        if ($country && !in_array($country, $allowedCountries, true)) {
            AuthenticationLog::create([
                'event_name'    => 'geo_fence_blocked',
                'ip_address'    => $this->request->ip(),
                'user_agent'    => $this->request->userAgent(),
                'location'      => $location,
                'is_successful' => false,
            ]);
            abort(403, 'Login not allowed from your location.');
        }
    }

    /**
     * Clear brute force attempts after successful login.
     */
    public function clearAttempts(string $ip): void
    {
        Cache::forget("sentinel_brute_force_{$ip}");
        BlockedIp::where('ip_address', $ip)->delete();
    }
}
