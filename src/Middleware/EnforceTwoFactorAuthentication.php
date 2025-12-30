<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Middleware;

use Closure;
use Harryes\SentinelLog\Contracts\TwoFactorAuthenticatable;
use Harryes\SentinelLog\Services\TwoFactorAuthenticationService;
use Illuminate\Http\Request;
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
            return redirect()->route('two-factor.setup');
        }

        return $next($request);
    }
}
