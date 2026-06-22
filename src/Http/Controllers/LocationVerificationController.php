<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Http\Controllers;

use Harryes\SentinelLog\Services\LocationVerificationService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;

class LocationVerificationController extends Controller
{
    public function __construct(protected LocationVerificationService $service) {}

    /**
     * Show a confirmation page before verifying the login location.
     * GET requests can be pre-fetched by email scanners and browsers — without
     * a confirmation step a scanner would silently trust the location on delivery.
     */
    public function verifyConfirm(string $token): Response|RedirectResponse
    {
        $record = $this->service->findPending($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_verify', '/'))
                ->with('sentinel_error', 'This verification link is invalid or has already been used.');
        }

        $location  = $record->location ?? [];
        $city      = e($location['city'] ?? 'Unknown');
        $country   = e($location['country'] ?? 'Unknown');
        $ip        = e($record->ip_address ?? 'Unknown');
        $postUrl   = route('sentinel-log.location.verify.confirm', $token);
        $csrfToken = csrf_token();

        $html = <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Confirm Login Location</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f7fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .card { background: white; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 40px; max-width: 460px; width: 100%; }
                h2 { color: #2b6cb0; margin: 0 0 8px; }
                p { color: #4a5568; line-height: 1.6; }
                .meta { background: #ebf8ff; border-left: 4px solid #2b6cb0; padding: 12px 16px; border-radius: 4px; margin: 20px 0; font-size: 14px; color: #2c5282; }
                .btn-confirm { background: #2b6cb0; color: white; border: none; padding: 12px 28px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
                .btn-confirm:hover { background: #2c5282; }
                .cancel { display: block; text-align: center; margin-top: 14px; color: #718096; font-size: 14px; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Confirm This Login?</h2>
                <p>You received this link because a login was detected from a new location.</p>
                <div class="meta">
                    <strong>Location:</strong> {$city}, {$country}<br>
                    <strong>IP Address:</strong> {$ip}
                </div>
                <p>Click confirm to trust this location. If this was <strong>not</strong> you, close this page and use the deny link in the email instead.</p>
                <form method="POST" action="{$postUrl}">
                    <input type="hidden" name="_token" value="{$csrfToken}">
                    <button type="submit" class="btn-confirm">Yes, this was me</button>
                </form>
                <a href="/" class="cancel">Cancel</a>
            </div>
        </body>
        </html>
        HTML;

        return response($html);
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
     * Using a GET for the deny action would allow email security scanners
     * (Outlook Safe Links, Apple Mail, Gmail) to automatically follow the link
     * on delivery and revoke the user's session before they even read the email.
     * The GET route shows a confirmation form; the POST route performs the denial.
     */
    public function denyConfirm(string $token): Response|RedirectResponse
    {
        $record = $this->service->findPending($token);

        if (! $record) {
            return redirect(config('sentinel-log.location_verification.redirect_after_deny', '/'))
                ->with('sentinel_error', 'This denial link is invalid or has already been used.');
        }

        $location = $record->location ?? [];
        $city     = e($location['city'] ?? 'Unknown');
        $country  = e($location['country'] ?? 'Unknown');
        $ip       = e($record->ip_address ?? 'Unknown');
        $postUrl  = route('sentinel-log.location.deny', $token);
        $csrfToken = csrf_token();

        $html = <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Deny Login — Security Alert</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f7fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .card { background: white; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 40px; max-width: 460px; width: 100%; }
                h2 { color: #e53e3e; margin: 0 0 8px; }
                p { color: #4a5568; line-height: 1.6; }
                .meta { background: #fff5f5; border-left: 4px solid #e53e3e; padding: 12px 16px; border-radius: 4px; margin: 20px 0; font-size: 14px; color: #742a2a; }
                .btn-deny { background: #e53e3e; color: white; border: none; padding: 12px 28px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
                .btn-deny:hover { background: #c53030; }
                .cancel { display: block; text-align: center; margin-top: 14px; color: #718096; font-size: 14px; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Deny This Login?</h2>
                <p>Someone logged in to your account from a location you have not used before.</p>
                <div class="meta">
                    <strong>Location:</strong> {$city}, {$country}<br>
                    <strong>IP Address:</strong> {$ip}
                </div>
                <p>Confirming will <strong>immediately revoke that session</strong> and log a security event. If this was you, click Cancel instead.</p>
                <form method="POST" action="{$postUrl}">
                    <input type="hidden" name="_token" value="{$csrfToken}">
                    <button type="submit" class="btn-deny">Yes, deny this login</button>
                </form>
                <a href="/" class="cancel">Cancel — this was me</a>
            </div>
        </body>
        </html>
        HTML;

        return response($html);
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
