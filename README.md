# Laravel SentinelLog

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%20%7C%208.x-blue)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-8.x%20%7C%209.x%20%7C%2010.x%20%7C%2011.x%20%7C%2012.x-blue)](https://laravel.com)

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

## Installation

### Prerequisites
- PHP 7.4 or 8.x
- Laravel 8.x, 9.x, 10.x, 11.x, or 12.x
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
    'failed_attempt' => ['threshold' => 5, 'window' => 15],
```

### Two-Factor Authentication (2FA)
```php
    'two_factor' => ['enabled' => false, 'middleware' => 'sentinel-log.2fa'],
```

### Sessions
```php
    'sessions' => ['enabled' => true, 'max_active' => 5],
```

### Brute Force Protection
```php
    'brute_force' => ['enabled' => true, 'threshold' => 5, 'window' => 15, 'block_duration' => 24],
```

### Geo-Fencing
```php
    'geo_fencing' => ['enabled' => false, 'allowed_countries' => ['United States', 'Canada']],
```

### SSO
```php
    'sso' => ['enabled' => false, 'client_id' => 'default_client', 'token_lifetime' => 24],
```

### Environment Variables
Add these to `.env`:
```env
    SENTINEL_LOG_ENABLED=true
    SENTINEL_LOG_2FA_ENABLED=true
    SENTINEL_LOG_GEO_FENCING_ENABLED=true
    SENTINEL_LOG_GEO_FENCING_ALLOWED_COUNTRIES="United States,Canada"
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

### Session Management
View active sessions:
```php
    $sessions = auth()->user()->authenticationLogs()->with('session')->get();
```

### Brute Force & Geo-Fencing
Attempts are automatically rate-limited, and IPs are blocked after exceeding the threshold. Geo-fencing blocks logins from unallowed countries based on `config/sentinel-log.php`.

## Contributing
Submit issues or pull requests on GitHub. Feedback is welcome!

## License
This package is open-sourced under the MIT License.
