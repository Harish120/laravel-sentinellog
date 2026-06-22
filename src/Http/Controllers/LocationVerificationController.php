<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Http\Controllers;

use Harryes\SentinelLog\Services\LocationVerificationService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller;
use Illuminate\View\View;

class LocationVerificationController extends Controller
{
    public function __construct(protected LocationVerificationService $service) {}

    /**
     * Show a confirmation page before verifying the login location.
     * GET requests can be pre-fetched by email scanners — without a confirmation
     * step a scanner would silently trust the location on delivery.
     * Publish the view with: php artisan vendor:publish --tag=sentinel-log-views
     */
    public function verifyConfirm(string $token): View|RedirectResponse
    {
        $record = $this->service->findPending($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_verify', '/'))
                ->with('sentinel_error', 'This verification link is invalid or has already been used.');
        }

        $location = $record->location ?? [];

        return view('sentinel-log::location.verify-confirm', [
            'city'    => $location['city'] ?? 'Unknown',
            'country' => $location['country'] ?? 'Unknown',
            'ip'      => $record->ip_address ?? 'Unknown',
            'postUrl' => route('sentinel-log.location.verify.confirm', $token),
        ]);
    }

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

    /**
     * Show a confirmation page before denying the login.
     * Same rationale as verifyConfirm — email scanners auto-follow GET links.
     * Publish the view with: php artisan vendor:publish --tag=sentinel-log-views
     */
    public function denyConfirm(string $token): View|RedirectResponse
    {
        $record = $this->service->findPending($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_deny', '/'))
                ->with('sentinel_error', 'This denial link is invalid or has already been used.');
        }

        $location = $record->location ?? [];

        return view('sentinel-log::location.deny-confirm', [
            'city'    => $location['city'] ?? 'Unknown',
            'country' => $location['country'] ?? 'Unknown',
            'ip'      => $record->ip_address ?? 'Unknown',
            'postUrl' => route('sentinel-log.location.deny.confirm', $token),
        ]);
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
