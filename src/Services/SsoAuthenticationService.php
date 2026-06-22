<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Models\SsoToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;

class SsoAuthenticationService
{
    public function generateToken(Authenticatable $authenticatable, string $clientId): string
    {
        $token = Str::random(64);
        SsoToken::create([
            'authenticatable_id' => $authenticatable->getKey(),
            'authenticatable_type' => get_class($authenticatable),
            'token' => $token,
            'client_id' => $clientId,
            'expires_at' => now()->addHours(config('sentinel-log.sso.token_lifetime', 24)),
        ]);

        return $token;
    }

    public function validateToken(string $token, string $clientId): ?object
    {
        $ssoToken = SsoToken::where('token', $token)
            ->where('client_id', $clientId)
            ->first();

        if ($ssoToken && $ssoToken->isValid()) {
            $user = $ssoToken->authenticatable;

            // Verify the related user still exists before consuming the token.
            // A deleted user account would return null here; deleting the token
            // first would burn it silently with no audit trail.
            if ($user === null) {
                return null;
            }

            $ssoToken->delete(); // One-time use — consumed only after user is confirmed

            return $user;
        }

        return null;
    }
}
