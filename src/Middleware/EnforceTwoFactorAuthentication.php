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

        if (! $user instanceof TwoFactorAuthenticatable) {
            if (config('sentinel-log.two_factor.required', false) && $user !== null) {
                report(new \LogicException(
                    'SentinelLog: two_factor.required is true but ' . get_class($user) . ' does not implement TwoFactorAuthenticatable.'
                ));
            }

            return $next($request);
        }

        // User has 2FA configured — they must complete the TOTP challenge this session
        if ($this->twoFactorService->isSetup($user) && ! $request->session()->has('2fa_verified')) {
            $verifyRoute = config('sentinel-log.two_factor.verify_route', 'two-factor.verify');

            abort_unless(
                Route::has($verifyRoute),
                500,
                "SentinelLog: 2FA verify route \"{$verifyRoute}\" is not defined. Add it to your application or update sentinel-log.two_factor.verify_route."
            );

            return redirect()->route($verifyRoute);
        }

        // 2FA is required but user has not set it up yet — redirect to setup
        if ($this->twoFactorService->isRequired($user) && ! $this->twoFactorService->isSetup($user)) {
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
