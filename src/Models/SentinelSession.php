<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int            $id
 * @property string         $session_id
 * @property string         $ip_address
 * @property array          $device_info
 * @property array          $location
 * @property int            $authenticatable_id
 * @property string         $authenticatable_type
 * @property \Carbon\Carbon $last_activity
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 */
class SentinelSession extends Model
{
    protected $table = 'sentinel_sessions';

    protected $fillable = [
        'authenticatable_id',
        'authenticatable_type',
        'session_id',
        'ip_address',
        'user_agent',
        'device_info',
        'location',
        'last_activity',
    ];

    protected $casts = [
        'device_info' => 'array',
        'location' => 'array',
        'last_activity' => 'datetime',
    ];

    /**
     * Get the authenticatable model that the session belongs to.
     *
     * @phpstan-ignore-next-line
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Get the authentication logs for the session.
     *
     * @phpstan-ignore-next-line
     */
    public function logs(): HasMany
    {
        return $this->hasMany(AuthenticationLog::class, 'session_id', 'session_id');
    }
}
