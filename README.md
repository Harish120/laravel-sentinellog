# Laravel SentinelLog

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%20%7C%208.3%20%7C%208.4-blue)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-10.x%20%7C%2011.x%20%7C%2012.x%20%7C%2013.x-blue)](https://laravel.com)

**Laravel SentinelLog** is a powerful, all-in-one authentication logging and security package for Laravel. It provides advanced features like device tracking, 2FA, session management, brute force protection, geo-fencing, and SSO support, ensuring security while keeping users informed.

## Features

- **Authentication Logging**: Logs login, logout, and failed attempts.
- **Device & Geolocation Tracking**: Tracks devices and locations for authentication events.
- **Notifications**: Alerts for new device logins and failed attempts.
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with QR code support.
- **Session Management**: Tracks multiple sessions and detects hijacking.
- **Brute Force Protection**: Rate-limits login attempts and blocks suspicious IPs.
- **Geo-Fencing**: Restricts logins to specific countries.
- **Single Sign-On (SSO)**: Token-based SSO for seamless authentication.
- **New Location Verification**: Detects logins from unrecognised locations and emails the user a verify/deny link, invalidating the session on denial.

## Demo Project

Want to see Laravel SentinelLog in action? Check out our demo project:

### [Laravel SentinelLog Demo](https://github.com/Harish120/sentinel-test)

This demo project showcases:
- Complete authentication system with SentinelLog integration
- Real-world implementation of all features
- Best practices for configuration and usage
- Example of custom notifications and event handling
- Interactive UI for testing various security features

To run the demo locally:
```bash
git clone https://github.com/Harish120/sentinel-test.git
cd sentinel-test
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
php artisan db:seed
php artisan serve
```

Visit `http://localhost:8000` to explore the demo.

## Installation

### Prerequisites
- PHP 8.2 or higher
- Laravel 10.x, 11.x, 12.x, or 13.x
- Composer

### Steps

1. **Install the Package**
```bash
  composer require harryes/laravel-sentinellog
```

2. **Publish Configuration**
```bash
  php artisan vendor:publish --tag=sentinel-log-config
```

3. **Run Migrations**
```bash
  php artisan migrate
```

4. **Add Trait to User Model**
```php
    use Harryes\SentinelLog\Traits\NotifiesAuthenticationEvents;
    
    class User extends Authenticatable
    {
        use NotifiesAuthenticationEvents;
    
        protected $fillable = ['two_factor_secret', 'two_factor_enabled_at'];
        protected $casts = ['two_factor_enabled_at' => 'datetime'];
    }
```

## Configuration

Edit `config/sentinel-log.php` to customize the package. Key options:

### General Settings
```php
    'enabled' => true,
    'events' => ['login' => true, 'logout' => true, 'failed' => true],
    'table_name' => 'authentication_logs',
```

### Notifications
```php
    'new_device' => ['enabled' => true, 'channels' => ['mail']],
    'failed_attempt' => ['enabled' => true, 'threshold' => 3, 'window' => 60],
    'session_hijacking' => ['enabled' => true, 'channels' => ['mail']],
```

### Two-Factor Authentication (2FA)
```php
    'two_factor' => [
        'enabled'     => false,
        'middleware'  => 'sentinel-log.2fa',
        'setup_route' => 'two-factor.setup', // named route users are redirected to when 2FA is not yet configured
    ],
```

> **Important:** The package does not register a `two-factor.setup` route — you must define it in your own application. If your route has a different name, set `setup_route` to match or use the `SENTINEL_LOG_2FA_SETUP_ROUTE` env variable.

### Sessions
```php
    'sessions' => ['enabled' => true, 'max_active' => 5],
```

### Brute Force Protection
```php
    'brute_force' => ['enabled' => true, 'threshold' => 5, 'window' => 15, 'block_duration' => 24],
```

### Geolocation Provider
```php
    // Defaults to ipwho.is — free, HTTPS, no API key required.
    // Override to use your own provider; must return JSON compatible with ipwho.is response format.
    'geo_provider_url' => 'https://ipwho.is',
```

### Geo-Fencing
```php
    'geo_fencing' => ['enabled' => false, 'allowed_countries' => ['United States', 'Canada']],
```

### SSO
```php
    'sso' => ['enabled' => false, 'client_id' => 'default_client', 'token_lifetime' => 24],
```

### New Location Verification
```php
    'location_verification' => [
        'enabled' => true,
        'channels' => ['mail'],
        'token_ttl' => 30, // Minutes until verify/deny links expire
        'redirect_after_verify' => '/',
        'redirect_after_deny' => '/',
    ],
```

### Environment Variables
Add these to `.env`:
```env
    SENTINEL_LOG_ENABLED=true
    SENTINEL_LOG_2FA_ENABLED=true
    SENTINEL_LOG_2FA_SETUP_ROUTE=two-factor.setup
    SENTINEL_LOG_GEO_PROVIDER_URL=https://ipwho.is
    SENTINEL_LOG_GEO_FENCING_ENABLED=true
    SENTINEL_LOG_GEO_FENCING_ALLOWED_COUNTRIES="United States,Canada"
    SENTINEL_LOG_LOCATION_VERIFICATION_ENABLED=true
```

## Usage Examples
 
### 2FA Setup
Generate a 2FA secret and QR code:
```php
    use Harryes\SentinelLog\Services\TwoFactorAuthenticationService;
    
    $service = new TwoFactorAuthenticationService();
    $user->update([
        'two_factor_secret' => $service->generateSecret(),
        'two_factor_enabled_at' => now(),
    ]);
    $qrCodeUrl = $service->getQrCodeUrl($user->two_factor_secret, $user->email);
```

Protect routes with 2FA middleware:
```php
    Route::middleware('sentinel-log.2fa')->group(function () {
        Route::get('/dashboard', fn() => 'Protected!');
    });
```

Verify 2FA code:
```php
    Route::post('/2fa/verify', function (TwoFactorAuthenticationService $service) {
        if ($service->verifyCode(auth()->user()->two_factor_secret, request('code'))) {
            session(['2fa_verified' => true]);
            return redirect('/dashboard');
        }
        return back()->withErrors(['code' => 'Invalid 2FA code']);
    });
```

### Failed Login Attempt Notifications

To receive notifications when a user's account hits the failed attempt threshold, implement the `NotifiableWithFailedAttempt` contract on your User model alongside the `NotifiesAuthenticationEvents` trait:

```php
use Harryes\SentinelLog\Contracts\NotifiableWithFailedAttempt;
use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Traits\NotifiesAuthenticationEvents;

class User extends Authenticatable implements NotifiableWithFailedAttempt
{
    use NotifiesAuthenticationEvents;

    public function notifyFailedAttempt(AuthenticationLog $log): void
    {
        $this->notify(new YourFailedAttemptNotification($log));
    }
}
```

The method is called automatically by the `LogFailedLogin` listener once the threshold defined in `notifications.failed_attempt.threshold` is reached within the configured time window.

### SSO Integration
Generate an SSO token:
```php
    use Harryes\SentinelLog\Services\SsoAuthenticationService;
    
    $ssoService = new SsoAuthenticationService();
    $token = $ssoService->generateToken(auth()->user(), 'client_app_1');
```

Handle SSO login in the client app:
```php
    Route::get('/sso/login', fn() => 'Logged in via SSO')->middleware('auth');
```

### Device Recognition

SentinelLog uses a **persistent cookie token** as the primary device identity signal — the same approach used by GitHub, Google, and Stripe.

**How it works:**
- On first login from a browser, a cryptographically random 64-character token is generated and stored in a long-lived `sentinel_device_token` cookie (2 years, HttpOnly, SameSite=Lax)
- On every subsequent login, the cookie is read and looked up in the login history
- If the token is not found → new device → `NewDeviceLogin` notification sent
- If the token is found → recognised device → no notification

**Why a cookie and not a header hash?**  
Header-based hashes that include the IP address break for mobile users (WiFi ↔ cellular), dynamic IPs, and VPN users. The cookie token is stable across all of these. A secondary header hash (User-Agent + Accept-Language + Accept-Encoding) is still stored in `device_info` alongside the token for forensic reference.

**To enable new device notifications**, set in config:
```php
'notifications' => [
    'new_device' => ['enabled' => true, 'channels' => ['mail']],
],
```

> **Upgrading from a previous version?** Existing login records have no `token` field in `device_info`. Each user will receive a single "new device" email on their first login after the upgrade — after which the cookie is set and recognition is stable.

### Session Management
View active sessions:
```php
    $sessions = auth()->user()->authenticationLogs()->with('session')->get();
```

### Brute Force & Geo-Fencing
Attempts are automatically rate-limited, and IPs are blocked after exceeding the threshold. Geo-fencing blocks logins from unallowed countries based on `config/sentinel-log.php`.

### New Location Verification
When a user logs in from a city/country they have never used before, SentinelLog automatically sends them a `NewLocationLogin` notification with two action links:

- **Yes, this was me** — marks the location as verified and logs a `location_verified` event.
- **No, deny this login** — opens a confirmation page showing the location and IP details. The user must click a confirm button which submits a `POST` request to revoke the session, logging a `location_denied` event.

> **Why a confirmation step for denial?** Email security scanners (Outlook Safe Links, Apple Mail, Gmail) automatically follow every link in an email on delivery. Without a confirmation page, these scanners would revoke the user's session before they even read the email.

The links expire after `token_ttl` minutes (default 30). No application code changes are required — the check runs inside the `LogSuccessfulLogin` listener on every login.

To disable the feature:
```env
SENTINEL_LOG_LOCATION_VERIFICATION_ENABLED=false
```

To prune expired, unactioned verification records:
```php
    use Harryes\SentinelLog\Services\LocationVerificationService;

    app(LocationVerificationService::class)->pruneExpired();
```

## Scheduled Maintenance

SentinelLog accumulates records over time. Add these to your scheduler to keep tables clean:

```php
// routes/console.php (Laravel 11+) or App\Console\Kernel (Laravel 10)
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\LocationVerificationService;

Schedule::call(fn () => app(BruteForceProtectionService::class)->pruneExpired())
    ->daily()
    ->name('sentinel-log:prune-blocked-ips');

Schedule::call(fn () => app(LocationVerificationService::class)->pruneExpired())
    ->daily()
    ->name('sentinel-log:prune-location-verifications');
```

| Method | What it cleans | Recommended frequency |
|---|---|---|
| `BruteForceProtectionService::pruneExpired()` | Expired IP block records from `sentinel_blocked_ips` | Daily |
| `LocationVerificationService::pruneExpired()` | Expired unactioned location verification tokens | Daily |

> **Note on IP blocks:** A blocked IP is considered inactive once its `expires_at` timestamp passes — no record deletion is needed for the block to stop working. `pruneExpired()` is purely a housekeeping concern.

## Contributing
Submit issues or pull requests on GitHub. Feedback is welcome!

## License
This package is open-sourced under the MIT License.
