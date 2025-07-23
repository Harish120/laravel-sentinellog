<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property string $event_name
 * @property string $ip_address
 * @property string $user_agent
 * @property array $device_info
 * @property array $location
 * @property bool $is_successful
 * @property string $session_id
 * @property int $authenticatable_id
 * @property string $authenticatable_type
 * @property \Carbon\Carbon $event_at
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 */
class AuthenticationLog extends Model
{
    protected $fillable = [
        'authenticatable_id',
        'authenticatable_type',
        'session_id',
        'event_name',
        'ip_address',
        'user_agent',
        'device_info',
        'location',
        'is_successful',
        'event_at',
        'cleared_at',
    ];

    protected $casts = [
        'device_info' => 'array',
        'location' => 'array',
        'is_successful' => 'boolean',
        'event_at' => 'datetime',
        'cleared_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('sentinel-log.table_name', 'authentication_logs');
    }

    /**
     * Get the authenticatable model that the log belongs to.
     *
     * @phpstan-ignore-next-line
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Get the session that the log belongs to.
     *
     * @phpstan-ignore-next-line
     */
    public function session(): BelongsTo
    {
        return $this->belongsTo(SentinelSession::class, 'session_id', 'session_id');
    }

    /**
     * Convert the model instance to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return parent::toArray();
    }
}
