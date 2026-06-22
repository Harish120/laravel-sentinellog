<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;

class DeviceFingerprintService
{
    private const COOKIE_NAME = 'sentinel_device_token';
    private const COOKIE_LIFETIME = 60 * 24 * 365 * 2; // 2 years in minutes
    private const TOKEN_LENGTH = 64;

    protected Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Generate a device fingerprint for the current request.
     *
     * The `token` field is the primary device identity signal — a random value
     * persisted in a long-lived HttpOnly cookie, stable across IP and UA changes.
     * The `hash` field is a secondary header-based signal stored for forensic use.
     *
     * @return array<string, mixed>
     */
    public function generate(): array
    {
        $headers   = $this->request->headers->all();
        $userAgent = $headers['user-agent'][0] ?? '';

        return [
            'token'           => $this->getOrCreateToken(),
            'browser'         => $userAgent ?: null,
            'accept_language' => $headers['accept-language'][0] ?? null,
            'accept_encoding' => $headers['accept-encoding'][0] ?? null,
            'platform'        => $this->guessPlatform($userAgent),
            'hash'            => $this->createHash(),
        ];
    }

    /**
     * Determine whether this device token has never been seen for this user.
     * A new token means a genuinely new browser, device, or cleared cookies.
     */
    public function isNewDevice(Authenticatable $user, string $token): bool
    {
        return ! AuthenticationLog::where('authenticatable_id', $user->getKey())
            ->where('authenticatable_type', get_class($user))
            ->where('is_successful', true)
            ->where('device_info->token', $token)
            ->exists();
    }

    /**
     * Read the device token from the incoming cookie.
     * If absent, mint a cryptographically random token and queue it on the response
     * as a long-lived, HttpOnly, SameSite=Lax cookie.
     */
    private function getOrCreateToken(): string
    {
        $existing = $this->request->cookie(self::COOKIE_NAME);

        if (is_string($existing) && strlen($existing) === self::TOKEN_LENGTH) {
            return $existing;
        }

        $token = Str::random(self::TOKEN_LENGTH);

        Cookie::queue(
            Cookie::make(
                name: self::COOKIE_NAME,
                value: $token,
                minutes: self::COOKIE_LIFETIME,
                path: '/',
                domain: null,
                secure: (bool) config('session.secure', false),
                httpOnly: true,
                raw: false,
                sameSite: 'Lax',
            )
        );

        return $token;
    }

    /**
     * Guess the platform from the user agent string.
     */
    protected function guessPlatform(string $userAgent): ?string
    {
        return match (true) {
            stripos($userAgent, 'Android') !== false                                         => 'Android',
            stripos($userAgent, 'iPhone') !== false || stripos($userAgent, 'iPad') !== false => 'iOS',
            stripos($userAgent, 'Windows') !== false                                         => 'Windows',
            stripos($userAgent, 'Mac') !== false                                             => 'MacOS',
            stripos($userAgent, 'Linux') !== false                                           => 'Linux',
            default                                                                          => null,
        };
    }

    /**
     * Build a secondary header-based fingerprint hash.
     * IP address is intentionally excluded — it is network state, not device identity,
     * and changes constantly for mobile users and dynamic-IP connections.
     */
    protected function createHash(): string
    {
        $data = array_filter([
            $this->request->userAgent(),
            $this->request->header('accept-language'),
            $this->request->header('accept-encoding'),
        ]);

        return md5(implode('|', $data));
    }
}
