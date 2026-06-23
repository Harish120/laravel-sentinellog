<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use DateTimeInterface;
use Harryes\SentinelLog\Contracts\NotifiableWithFailedAttempt;
use Harryes\SentinelLog\Contracts\TwoFactorAuthenticatable;
use Harryes\SentinelLog\Traits\NotifiesAuthenticationEvents;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements TwoFactorAuthenticatable, NotifiableWithFailedAttempt
{
    use NotifiesAuthenticationEvents; // provides notifyFailedAttempt(), satisfying the interface

    protected $table = 'users';

    protected $fillable = [
        'name',
        'email',
        'password',
        'two_factor_secret',
        'two_factor_enabled_at',
    ];

    protected $casts = [
        'two_factor_enabled_at' => 'datetime',
    ];

    public function getTwoFactorSecret(): ?string
    {
        return $this->two_factor_secret;
    }

    public function getTwoFactorEnabledAt(): ?DateTimeInterface
    {
        return $this->two_factor_enabled_at;
    }
}
