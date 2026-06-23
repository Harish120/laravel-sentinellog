<?php

declare(strict_types=1);

use Harryes\SentinelLog\Models\AuthenticationLog;

function seedLogs(mixed $user, int $oldCount, int $recentCount): void
{
    foreach (range(1, $oldCount) as $i) {
        AuthenticationLog::create([
            'authenticatable_id'   => $user->id,
            'authenticatable_type' => get_class($user),
            'event_name'           => 'login',
            'is_successful'        => true,
            'ip_address'           => '127.0.0.1',
            'event_at'             => now()->subDays(40),
        ]);
    }

    foreach (range(1, $recentCount) as $i) {
        AuthenticationLog::create([
            'authenticatable_id'   => $user->id,
            'authenticatable_type' => get_class($user),
            'event_name'           => 'login',
            'is_successful'        => true,
            'ip_address'           => '127.0.0.1',
            'event_at'             => now()->subDays(5),
        ]);
    }
}

it('deletes logs older than the default retention period', function () {
    $user = makeUser();
    seedLogs($user, oldCount: 3, recentCount: 2);

    config(['sentinel-log.prune.days' => 30]);
    $deleted = AuthenticationLog::pruneOlderThan();

    expect($deleted)->toBe(3)
        ->and(AuthenticationLog::count())->toBe(2);
});

it('deletes logs older than a custom retention period', function () {
    $user = makeUser();
    seedLogs($user, oldCount: 3, recentCount: 2);

    $deleted = AuthenticationLog::pruneOlderThan(3);

    expect($deleted)->toBe(5) // both old and recent are older than 3 days
        ->and(AuthenticationLog::count())->toBe(0);
});

it('does not delete recent logs', function () {
    $user = makeUser();

    AuthenticationLog::create([
        'authenticatable_id'   => $user->id,
        'authenticatable_type' => get_class($user),
        'event_name'           => 'login',
        'is_successful'        => true,
        'ip_address'           => '127.0.0.1',
        'event_at'             => now(),
    ]);

    $deleted = AuthenticationLog::pruneOlderThan(30);

    expect($deleted)->toBe(0)
        ->and(AuthenticationLog::count())->toBe(1);
});

it('returns zero when there is nothing to prune', function () {
    expect(AuthenticationLog::pruneOlderThan(30))->toBe(0);
});
