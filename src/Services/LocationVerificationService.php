<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Models\LocationVerification;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class LocationVerificationService
{
    /**
     * Determine if the given location is new for this user.
     * "New" means the user has never successfully logged in from this city+country before.
     *
     * @param array<string, mixed> $location
     */
    public function isNewLocation(Authenticatable $user, array $location): bool
    {
        $city = $location['city'] ?? null;
        $country = $location['country'] ?? null;

        if (in_array($country, ['Local', 'Unknown'], true)) {
            return false;
        }

        return ! AuthenticationLog::where('authenticatable_id', $user->getKey())
            ->where('authenticatable_type', get_class($user))
            ->where('event_name', 'login')
            ->where('is_successful', true)
            ->where('location->city', $city)
            ->where('location->country', $country)
            ->exists();
    }

    /**
     * Create a new pending location verification record and return it.
     *
     * @param array<string, mixed> $location
     * @param array<string, mixed> $deviceInfo
     */
    public function create(
        Authenticatable $user,
        string $ip,
        array $location,
        array $deviceInfo,
        string $userAgent,
        ?string $sessionId
    ): LocationVerification {
        $ttlMinutes = config('sentinel-log.location_verification.token_ttl', 30);

        return LocationVerification::create([
            'authenticatable_type' => get_class($user),
            'authenticatable_id' => $user->getKey(),
            'token' => Str::random(64),
            'session_id' => $sessionId,
            'ip_address' => $ip,
            'location' => $location,
            'user_agent' => $userAgent,
            'device_info' => $deviceInfo,
            'expires_at' => now()->addMinutes($ttlMinutes),
        ]);
    }

    /**
     * Mark a verification token as verified.
     * Returns null if the token is invalid, expired, or already actioned.
     */
    public function verify(string $token): ?LocationVerification
    {
        $record = LocationVerification::where('token', $token)->first();

        if (! $record || ! $record->isPending()) {
            return null;
        }

        $record->update(['verified_at' => now()]);

        AuthenticationLog::create([
            'authenticatable_id' => $record->authenticatable_id,
            'authenticatable_type' => $record->authenticatable_type,
            'session_id' => $record->session_id,
            'event_name' => 'location_verified',
            'ip_address' => $record->ip_address,
            'user_agent' => $record->user_agent,
            'device_info' => $record->device_info,
            'location' => $record->location,
            'is_successful' => true,
            'event_at' => now(),
        ]);

        return $record;
    }

    /**
     * Mark a verification token as denied and invalidate the associated session.
     * Returns null if the token is invalid, expired, or already actioned.
     */
    public function deny(string $token): ?LocationVerification
    {
        $record = LocationVerification::where('token', $token)->first();

        if (! $record || ! $record->isPending()) {
            return null;
        }

        $record->update(['denied_at' => now()]);

        AuthenticationLog::create([
            'authenticatable_id' => $record->authenticatable_id,
            'authenticatable_type' => $record->authenticatable_type,
            'session_id' => $record->session_id,
            'event_name' => 'location_denied',
            'ip_address' => $record->ip_address,
            'user_agent' => $record->user_agent,
            'device_info' => $record->device_info,
            'location' => $record->location,
            'is_successful' => false,
            'event_at' => now(),
        ]);

        $this->invalidateSession($record->session_id);

        return $record;
    }

    /**
     * Delete expired verification records.
     */
    public function pruneExpired(): int
    {
        return LocationVerification::where('expires_at', '<', now())
            ->whereNull('verified_at')
            ->whereNull('denied_at')
            ->delete();
    }

    private function invalidateSession(?string $sessionId): void
    {
        if (! $sessionId) {
            return;
        }

        // Invalidate database-backed sessions
        try {
            DB::table(config('session.table', 'sessions'))
                ->where('id', $sessionId)
                ->delete();
        } catch (\Throwable) {
            // Session driver may not be database — silently skip
        }
    }
}
