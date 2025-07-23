<?php

declare(strict_types=1);

namespace Harryes\SentinelLog;

use Harryes\SentinelLog\Listeners\LogFailedLogin;
use Harryes\SentinelLog\Listeners\LogSsoLogin;
use Harryes\SentinelLog\Listeners\LogSuccessfulLogin;
use Harryes\SentinelLog\Listeners\LogSuccessfulLogout;
use Harryes\SentinelLog\Middleware\EnforceGeoFencing;
use Harryes\SentinelLog\Middleware\EnforceTwoFactorAuthentication;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class SentinelLogServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/sentinel-log.php', 'sentinel-log');
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/sentinel-log.php' => config_path('sentinel-log.php')], 'sentinel-log-config');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        Event::listen(Login::class, LogSuccessfulLogin::class);
        Event::listen(Login::class, LogSsoLogin::class);
        Event::listen(Logout::class, LogSuccessfulLogout::class);
        Event::listen(Failed::class, LogFailedLogin::class);

        if (config('sentinel-log.two_factor.enabled', false)) {
            Route::aliasMiddleware('sentinel-log.2fa', EnforceTwoFactorAuthentication::class);
        }
        if (config('sentinel-log.geo_fencing.enabled', false)) {
            Route::aliasMiddleware('sentinel-log.geofence', EnforceGeoFencing::class);
        }
    }
}
