# Laravel SentinelLog

[![Latest Version](https://img.shields.io/packagist/v/harryes/laravel-sentinellog.svg)](https://packagist.org/packages/harryes/laravel-sentinellog)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%20%7C%208.3%20%7C%208.4%20%7C%208.5-blue)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-10.x%20%7C%2011.x%20%7C%2012.x%20%7C%2013.x-blue)](https://laravel.com)
[![Tests](https://img.shields.io/badge/tests-52%20passing-brightgreen)](https://github.com/Harish120/laravel-sentinellog/actions)
[![Stable](https://img.shields.io/badge/stable-v1.0.0-brightgreen)](https://packagist.org/packages/harryes/laravel-sentinellog)

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
- PHP 8.2, 8.3, 8.4, or 8.5
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

2a. *(Optional)* **Publish Views** — only if you want to **customise** the verify/deny confirmation pages:
```bash
  php artisan vendor:publish --tag=sentinel-log-views
```
This copies the Blade templates to `resources/views/sentinel-log/location/`.

> **Do not publish unless you intend to customise.** The package serves the confirmation pages automatically via `loadViewsFrom()` — no publishing step is required for them to work. Publishing a copy you never edit will silently shadow future package view updates.

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
        protected $casts = [
            'two_factor_enabled_at' => 'datetime',
            'two_factor_secret'     => 'encrypted', // encrypts the TOTP secret at rest
        ];
    }
```

> **Security:** The `encrypted` cast uses your application's `APP_KEY` to encrypt the 2FA secret in the database. A database dump will not expose raw TOTP secrets. If you have existing unencrypted secrets, re-generate them after adding the cast — existing codes will stop working until the secret is re-saved through the encryption layer.

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
    'new_device'        => ['enabled' => true, 'channels' => ['mail'], 'threshold' => 1],
    'failed_attempt'    => ['enabled' => true, 'channels' => ['mail'], 'threshold' => 3, 'window' => 60],
    'session_hijacking' => ['enabled' => true, 'channels' => ['mail']],
```

To also persist notifications to the database, add `'database'` to the channels array for any notification. Your `users` table must have the `notifications` table from `php artisan notifications:table`.

```php
    'new_device' => ['enabled' => true, 'channels' => ['mail', 'database']],
```

> **Note:** The `NewLocationLogin` database payload stores `verification_id` (the record's primary key) rather than the raw token, so the verify/deny URLs cannot be reconstructed from the notifications table.

### Optional Chat Channels (Slack, Discord, Microsoft Teams, Telegram, custom webhook)

Mail is the default and it keeps working with zero setup. If your team also watches a Slack, Discord, or Teams channel, or you run alerts through a Telegram bot, you can send the same alerts there too. None of this needs an extra composer package, they all just take a plain HTTP POST, so turning any of them on will not add new dependencies to your app.

Add the channel name to whichever notification's `channels` array you want, and fill in its settings:

```php
    'notifications' => [
        'new_device'        => ['enabled' => true, 'channels' => ['mail', 'slack']],
        'failed_attempt'    => ['enabled' => true, 'channels' => ['mail', 'slack', 'discord']],
        'session_hijacking' => ['enabled' => true, 'channels' => ['mail', 'teams', 'telegram']],
    ],

    'channels' => [
        'slack' => [
            'webhook_url' => env('SENTINEL_LOG_SLACK_WEBHOOK_URL'),
        ],
        'discord' => [
            'webhook_url' => env('SENTINEL_LOG_DISCORD_WEBHOOK_URL'),
        ],
        'teams' => [
            'webhook_url' => env('SENTINEL_LOG_TEAMS_WEBHOOK_URL'),
        ],
        'telegram' => [
            'bot_token' => env('SENTINEL_LOG_TELEGRAM_BOT_TOKEN'),
            'chat_id' => env('SENTINEL_LOG_TELEGRAM_CHAT_ID'),
        ],
        'webhook' => [
            'webhook_url' => env('SENTINEL_LOG_WEBHOOK_URL'),
        ],
    ],
```

How to set each one up:

- **Slack**: create an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel you want alerts in.
- **Discord**: open the channel's settings, go to Integrations, and create a webhook there.
- **Microsoft Teams**: add an Incoming Webhook connector to the channel and copy its URL.
- **Telegram**: message [@BotFather](https://t.me/BotFather) to create a bot and get a token, message your bot once, then visit `https://api.telegram.org/bot<token>/getUpdates` to read back the chat id.
- **Custom webhook** (`'webhook'`): a catch-all for anything else, PagerDuty, Zapier, n8n, or your own endpoint. It posts the notification's normal `toArray()` payload, the same data the `database` channel stores, so you get structured JSON rather than a chat message.

If a channel is turned on but not fully configured (no webhook URL, or no bot token), the package logs a warning and moves on. It will never throw an error or stop a login from working. The same goes for a webhook that is down or times out, so a broken Slack or Teams integration can never take your login flow down with it.

You can also point different users at different destinations by adding `routeNotificationForSlack()`, `routeNotificationForDiscord()`, `routeNotificationForTeams()`, or `routeNotificationForTelegram()` to your notifiable model, the same way you would for `routeNotificationForMail()`. For Telegram this should return the chat id, for the others a webhook URL. That value takes priority over the config setting.

Want a channel that is not here yet? Open an issue or a PR, the channel classes in `src/Channels` are built so a new one is just a small subclass.

### Two-Factor Authentication (2FA)
```php
    'two_factor' => [
        'enabled'     => false,
        'required'    => false, // when true, all TwoFactorAuthenticatable users must complete 2FA setup
        'middleware'  => 'sentinel-log.2fa',
        'setup_route' => 'two-factor.setup',
    ],
```

- `enabled` — registers the `sentinel-log.2fa` middleware alias so you can apply it to routes
- `required` — when `true`, the middleware redirects **any** user who has not set up 2FA to the setup route; when `false` (default), only users who have already set up 2FA are prompted to verify

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
    SENTINEL_LOG_2FA_REQUIRED=false
    SENTINEL_LOG_2FA_SETUP_ROUTE=two-factor.setup
    SENTINEL_LOG_GEO_PROVIDER_URL=https://ipwho.is
    SENTINEL_LOG_GEO_FENCING_ENABLED=true
    SENTINEL_LOG_GEO_FENCING_ALLOWED_COUNTRIES="United States,Canada"
    SENTINEL_LOG_LOCATION_VERIFICATION_ENABLED=true
    SENTINEL_LOG_SLACK_WEBHOOK_URL=
    SENTINEL_LOG_DISCORD_WEBHOOK_URL=
    SENTINEL_LOG_TEAMS_WEBHOOK_URL=
    SENTINEL_LOG_TELEGRAM_BOT_TOKEN=
    SENTINEL_LOG_TELEGRAM_CHAT_ID=
    SENTINEL_LOG_WEBHOOK_URL=
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

- **Yes, this was me** — opens a confirmation page. The user clicks confirm which submits a `POST` request, marking the location as trusted and logging a `location_verified` event.
- **No, deny this login** — opens a confirmation page showing the location and IP details. The user clicks confirm which submits a `POST` request to revoke the session, logging a `location_denied` event.

> **Why confirmation pages for both links?** Email security scanners (Outlook Safe Links, Apple Mail, Gmail) automatically follow every link in an email on delivery. Without a confirmation step, scanners would silently trust or revoke the session before the user even reads the email.

Both confirmation pages are Blade templates you can customise — see the installation steps above.

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
use Harryes\SentinelLog\Models\AuthenticationLog;
use Harryes\SentinelLog\Services\BruteForceProtectionService;
use Harryes\SentinelLog\Services\LocationVerificationService;

Schedule::call(fn () => AuthenticationLog::pruneOlderThan())
    ->daily()
    ->name('sentinel-log:prune-auth-logs');

Schedule::call(fn () => app(BruteForceProtectionService::class)->pruneExpired())
    ->daily()
    ->name('sentinel-log:prune-blocked-ips');

Schedule::call(fn () => app(LocationVerificationService::class)->pruneExpired())
    ->daily()
    ->name('sentinel-log:prune-location-verifications');
```

| Method | What it cleans | Recommended frequency |
|---|---|---|
| `AuthenticationLog::pruneOlderThan()` | Auth log entries older than `prune.days` (default 30) | Daily |
| `BruteForceProtectionService::pruneExpired()` | Expired IP block records from `sentinel_blocked_ips` | Daily |
| `LocationVerificationService::pruneExpired()` | Expired unactioned location verification tokens | Daily |

You can override the retention period: `AuthenticationLog::pruneOlderThan(90)` keeps 90 days of history.

> **Note on IP blocks:** A blocked IP is considered inactive once its `expires_at` timestamp passes — no record deletion is needed for the block to stop working. `pruneExpired()` is purely a housekeeping concern.

## Contributing
Submit issues or pull requests on GitHub. Feedback is welcome!

## License
This package is open-sourced under the MIT License.
