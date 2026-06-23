<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Contracts\TwoFactorAuthenticatable;
use Illuminate\Support\Facades\Cache;
use ParagonIE\ConstantTime\Base32;

class TwoFactorAuthenticationService
{
    /**
     * Generate a new 2FA secret.
     */
    public function generateSecret(): string
    {
        // RFC 6238 recommends 160 bits of entropy for the shared secret.
        // random_bytes(20) gives 160 bits of cryptographically secure randomness
        // with a uniform byte distribution — Str::random() produces only alphanumeric
        // characters (~95 bits, skewed byte distribution) and is not suitable here.
        return Base32::encodeUpper(random_bytes(20));
    }

    /**
     * Generate a TOTP code for a secret.
     */
    public function generateCode(string $secret, ?int $timestamp = null): string
    {
        $secret = Base32::decodeUpper($secret);
        $timestamp = $timestamp ?? floor(time() / 30); // 30-second window

        $binary = pack('N*', 0) . pack('N*', $timestamp);
        $hash = hash_hmac('sha1', $binary, $secret, true);
        $offset = ord($hash[19]) & 0x0F;

        $code = (unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF) % 1000000;

        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a TOTP code against a secret.
     */
    public function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $timestamp  = (int) floor(time() / 30);
        $secretHash = hash('sha256', $secret);

        for ($i = -$window; $i <= $window; $i++) {
            $step     = $timestamp + $i;
            $expected = $this->generateCode($secret, $step);

            if (hash_equals($expected, $code)) {
                // RFC 6238 §5.2: reject replayed codes within the same step window.
                $replayKey = "sentinel_totp_used_{$secretHash}_{$step}";

                if (Cache::has($replayKey)) {
                    return false;
                }

                // Mark this step as consumed for the duration of the window
                Cache::put($replayKey, true, now()->addSeconds(($window * 2 + 1) * 30));

                return true;
            }
        }

        return false;
    }

    /**
     * Generate a QR code URL for authenticator apps.
     */
    public function getQrCodeUrl(string $secret, string $email, string $issuer = 'SentinelLog'): string
    {
        $label = urlencode("{$issuer}:{$email}");
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30,
        ]);

        return "otpauth://totp/{$label}?{$params}";
    }

    /**
     * Check if two-factor authentication is properly set up.
     */
    public function isSetup(TwoFactorAuthenticatable $user): bool
    {
        return $user->getTwoFactorEnabledAt() !== null &&
               $user->getTwoFactorSecret() !== null;
    }

    /**
     * Check if two-factor authentication is required.
     */
    public function isRequired(TwoFactorAuthenticatable $user): bool
    {
        return config('sentinel-log.two_factor.required', false);
    }
}
