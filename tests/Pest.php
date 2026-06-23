<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Fixtures\User;
use Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature');
uses(RefreshDatabase::class)->in('Feature');

/**
 * Create a test user with sensible defaults.
 *
 * @param array<string, mixed> $attributes
 */
function makeUser(array $attributes = []): User
{
    return User::create(array_merge([
        'name'     => 'Test User',
        'email'    => 'test@example.com',
        'password' => bcrypt('password'),
    ], $attributes));
}
