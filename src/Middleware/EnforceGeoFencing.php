<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Middleware;

use Closure;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Illuminate\Http\Request;

class EnforceGeoFencing
{
    protected BruteForceProtectionService $bruteForceService;

    public function __construct(BruteForceProtectionService $bruteForceService)
    {
        $this->bruteForceService = $bruteForceService;
    }

    public function handle(Request $request, Closure $next): mixed
    {
        if (config('sentinel-log.geo_fencing.enabled', false)) {
            $this->bruteForceService->checkGeoFence($request->user());
        }

        return $next($request);
    }
}
