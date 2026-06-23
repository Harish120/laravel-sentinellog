<?php

declare(strict_types=1);

namespace Harryes\SentinelLog;

use Harryes\SentinelLog\Http\Controllers\LocationVerificationController;
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
        $this->mergeConfigFrom(__DIR__ . '/../config/sentinel-log.php', 'sentinel-log');
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/sentinel-log.php' => config_path('sentinel-log.php')], 'sentinel-log-config');
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'sentinel-log');
        $this->publishes([__DIR__ . '/../resources/views' => resource_path('views/sentinel-log')], 'sentinel-log-views');
        Event::listen(Login::class, LogSsoLogin::class);
        Event::listen(Login::class, LogSuccessfulLogin::class);
        Event::listen(Logout::class, LogSuccessfulLogout::class);
        Event::listen(Failed::class, LogFailedLogin::class);

        // Always register aliases — both middleware self-guard when their feature
        // is disabled, so registering unconditionally is safe. Conditional registration
        // caused "Target class does not exist" 500 errors when apps referenced the
        // alias before enabling the feature in config.
        Route::aliasMiddleware('sentinel-log.2fa', EnforceTwoFactorAuthentication::class);
        Route::aliasMiddleware('sentinel-log.geofence', EnforceGeoFencing::class);

        if (config('sentinel-log.location_verification.enabled', true)) {
            Route::group(['middleware' => ['web'], 'prefix' => 'sentinel-log/location'], function () {
                // GET shows confirmation pages — prevents email scanners from auto-actioning
                Route::get('verify/{token}', [LocationVerificationController::class, 'verifyConfirm'])
                    ->name('sentinel-log.location.verify');
                Route::get('deny/{token}', [LocationVerificationController::class, 'denyConfirm'])
                    ->name('sentinel-log.location.deny');

                // POST routes perform the actual actions after user confirms
                Route::post('verify/{token}', [LocationVerificationController::class, 'verify'])
                    ->name('sentinel-log.location.verify.confirm');
                Route::post('deny/{token}', [LocationVerificationController::class, 'deny'])
                    ->name('sentinel-log.location.deny.confirm');
            });
        }
    }
}
