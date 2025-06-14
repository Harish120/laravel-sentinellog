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
        'enabled' => env('SENTINEL_LOG_2FA_ENABLED', false),
        'middleware' => 'sentinel-log.2fa',
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
    'geo_fencing' => [
        'enabled' => env('SENTINEL_LOG_GEO_FENCING_ENABLED', false),
        'allowed_countries' => explode(',', env('SENTINEL_LOG_GEO_FENCING_ALLOWED_COUNTRIES', 'United States,Canada')),
    ],
    'sso' => [
        'enabled' => env('SENTINEL_LOG_SSO_ENABLED', false),
        'client_id' => env('SENTINEL_LOG_SSO_CLIENT_ID', 'default_client'),
        'token_lifetime' => 24, // Hours
    ],
];
