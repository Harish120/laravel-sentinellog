<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int            $id
 * @property string         $authenticatable_type
 * @property int            $authenticatable_id
 * @property string         $token
 * @property string|null    $session_id
 * @property string         $ip_address
 * @property array<string, mixed>|null $location
 * @property string|null    $user_agent
 * @property array<string, mixed>|null $device_info
 * @property \Carbon\Carbon $expires_at
 * @property \Carbon\Carbon|null $verified_at
 * @property \Carbon\Carbon|null $denied_at
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 */
class LocationVerification extends Model
{
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'token',
        'session_id',
        'ip_address',
        'location',
        'user_agent',
        'device_info',
        'expires_at',
        'verified_at',
        'denied_at',
    ];

    protected $casts = [
        'location' => 'array',
        'device_info' => 'array',
        'expires_at' => 'datetime',
        'verified_at' => 'datetime',
        'denied_at' => 'datetime',
    ];

    /** @phpstan-ignore-next-line */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isPending(): bool
    {
        return is_null($this->verified_at) && is_null($this->denied_at) && ! $this->isExpired();
    }
}
