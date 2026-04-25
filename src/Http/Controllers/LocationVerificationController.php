<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Http\Controllers;

use Harryes\SentinelLog\Services\LocationVerificationService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller;

class LocationVerificationController extends Controller
{
    public function __construct(protected LocationVerificationService $service) {}

    public function verify(string $token): RedirectResponse
    {
        $record = $this->service->verify($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_verify', '/'))
                ->with('sentinel_error', 'This verification link is invalid or has already been used.');
        }

        return redirect(config('sentinel-log.location_verification.redirect_after_verify', '/'))
            ->with('sentinel_success', 'Login location confirmed. Thank you!');
    }

    public function deny(string $token): RedirectResponse
    {
        $record = $this->service->deny($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_deny', '/'))
                ->with('sentinel_error', 'This denial link is invalid or has already been used.');
        }

        return redirect(config('sentinel-log.location_verification.redirect_after_deny', '/'))
            ->with('sentinel_success', 'The session has been revoked. Please secure your account.');
    }
}
