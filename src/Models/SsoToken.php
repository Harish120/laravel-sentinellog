<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property int $authenticatable_id
 * @property string $authenticatable_type
 * @property string $token
 * @property string $client_id
 * @property \Carbon\Carbon|null $issued_at
 * @property \Carbon\Carbon|null $expires_at
 */
class SsoToken extends Model
{
    protected $table = 'sentinel_sso_tokens';

    protected $fillable = [
        'authenticatable_id',
        'authenticatable_type',
        'token',
        'client_id',
        'issued_at',
        'expires_at',
    ];

    protected $casts = [
        'issued_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * Get the authenticatable model that the token belongs to.
     *
     * @phpstan-ignore-next-line
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Check if the token is valid.
     */
    public function isValid(): bool
    {
        return $this->expires_at->isFuture();
    }
}
