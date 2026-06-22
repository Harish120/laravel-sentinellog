<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Middleware;

use Closure;
use Harryes\SentinelLog\Contracts\TwoFactorAuthenticatable;
use Harryes\SentinelLog\Services\TwoFactorAuthenticationService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

class EnforceTwoFactorAuthentication
{
    public function __construct(
        private TwoFactorAuthenticationService $twoFactorService
    ) {}

    /**
     * Handle the incoming request.
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        $user = $request->user();

        if ($user instanceof TwoFactorAuthenticatable &&
            $this->twoFactorService->isRequired($user) &&
            ! $this->twoFactorService->isSetup($user)) {
            $setupRoute = config('sentinel-log.two_factor.setup_route', 'two-factor.setup');

            abort_unless(
                Route::has($setupRoute),
                500,
                "SentinelLog: 2FA setup route \"{$setupRoute}\" is not defined. Add it to your application or update sentinel-log.two_factor.setup_route."
            );

            return redirect()->route($setupRoute);
        }

        return $next($request);
    }
}
