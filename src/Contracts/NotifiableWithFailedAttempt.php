<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Contracts;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Contracts\Auth\Authenticatable;

interface NotifiableWithFailedAttempt extends Authenticatable
{
    public function notifyFailedAttempt(AuthenticationLog $log): void;
}
