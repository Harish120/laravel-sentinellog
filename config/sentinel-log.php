<?php

declare(strict_types=1);

return [
    'enabled' => env('SENTINEL_LOG_ENABLED', true),
    'events' => [
        'login' => true,
        'logout' => true,
        'failed' => true,
    ],
    'table_name' => 'authentication_logs',
    'prune' => [
        'enabled' => true,
        'days' => 30,
    ],
    'notifications' => [
        'new_device' => [
            'enabled' => env('SENTINEL_LOG_NOTIFY_NEW_DEVICE', true),
            'channels' => ['mail'],
            'threshold' => 1,
        ],
        'failed_attempt' => [
            'enabled' => env('SENTINEL_LOG_NOTIFY_FAILED_ATTEMPT', true),
            'channels' => ['mail'],
            'threshold' => 3,
            'window' => 60,
        ],
        'session_hijacking' => [
            'enabled' => env('SENTINEL_LOG_NOTIFY_HIJACKING', true),
            'channels' => ['mail'],
        ],
    ],
    'two_factor' => [
        'enabled'     => env('SENTINEL_LOG_2FA_ENABLED', false),
        'required'    => env('SENTINEL_LOG_2FA_REQUIRED', false), // force all TwoFactorAuthenticatable users to set up 2FA
        'middleware'  => 'sentinel-log.2fa',
        'setup_route' => env('SENTINEL_LOG_2FA_SETUP_ROUTE', 'two-factor.setup'),
    ],
    'sessions' => [
        'enabled' => env('SENTINEL_LOG_SESSIONS_ENABLED', true),
        'max_active' => 5,
    ],
    'brute_force' => [
        'enabled' => env('SENTINEL_LOG_BRUTE_FORCE_ENABLED', true),
        'threshold' => 5,
        'window' => 15,
        'block_duration' => 24,
    ],
    'geo_test_ip' => env('SENTINEL_LOG_GEO_TEST_IP', null),

    // Base URL of the geolocation provider. The package appends /{ip} to this URL.
    // Default uses ipwho.is — free, HTTPS, no API key required.
    // Custom providers must return JSON with: success (bool), country, city, latitude, longitude, ip.
    'geo_provider_url' => env('SENTINEL_LOG_GEO_PROVIDER_URL', 'https://ipwho.is'),
    'geo_fencing' => [
        'enabled' => env('SENTINEL_LOG_GEO_FENCING_ENABLED', false),
        'allowed_countries' => array_values(array_filter(explode(',', env('SENTINEL_LOG_GEO_FENCING_ALLOWED_COUNTRIES', 'United States,Canada')))),
    ],
    'sso' => [
        'enabled' => env('SENTINEL_LOG_SSO_ENABLED', false),
        'client_id' => env('SENTINEL_LOG_SSO_CLIENT_ID', 'default_client'),
        'token_lifetime' => 24, // Hours
    ],

    'location_verification' => [
        'enabled' => env('SENTINEL_LOG_LOCATION_VERIFICATION_ENABLED', true),
        'channels' => ['mail'],
        'token_ttl' => 30, // Minutes until the verify/deny links expire
        'redirect_after_verify' => '/',
        'redirect_after_deny' => '/',
    ],
];
