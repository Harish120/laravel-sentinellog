<?php

declare(strict_types=1);

namespace Tests\Unit\Notifications;

use Harryes\SentinelLog\Notifications\Messages\DiscordMessage;
use Harryes\SentinelLog\Notifications\Messages\SlackMessage;
use Harryes\SentinelLog\Notifications\Messages\TeamsMessage;
use Harryes\SentinelLog\Notifications\Messages\TelegramMessage;

describe('SlackMessage', function () {
    it('builds a payload with the given text', function () {
        $message = (new SlackMessage)->text('New device login detected.');

        expect($message->toArray())->toBe([
            'text' => 'New device login detected.',
        ]);
    });

    it('defaults to an empty string when no text is set', function () {
        expect((new SlackMessage)->toArray())->toBe(['text' => '']);
    });

    it('returns itself so calls can be chained', function () {
        $message = new SlackMessage;

        expect($message->text('hello'))->toBe($message);
    });
});

describe('DiscordMessage', function () {
    it('builds a payload with the given content', function () {
        $message = (new DiscordMessage)->content('New device login detected.');

        expect($message->toArray())->toBe([
            'content' => 'New device login detected.',
        ]);
    });

    it('defaults to an empty string when no content is set', function () {
        expect((new DiscordMessage)->toArray())->toBe(['content' => '']);
    });

    it('returns itself so calls can be chained', function () {
        $message = new DiscordMessage;

        expect($message->content('hello'))->toBe($message);
    });
});

describe('TeamsMessage', function () {
    it('builds a payload with the given text', function () {
        $message = (new TeamsMessage)->text('New device login detected.');

        expect($message->toArray())->toBe([
            'text' => 'New device login detected.',
        ]);
    });

    it('defaults to an empty string when no text is set', function () {
        expect((new TeamsMessage)->toArray())->toBe(['text' => '']);
    });

    it('returns itself so calls can be chained', function () {
        $message = new TeamsMessage;

        expect($message->text('hello'))->toBe($message);
    });
});

describe('TelegramMessage', function () {
    it('builds a payload with the given text', function () {
        $message = (new TelegramMessage)->text('New device login detected.');

        expect($message->toArray())->toBe([
            'text' => 'New device login detected.',
        ]);
    });

    it('defaults to an empty string when no text is set', function () {
        expect((new TelegramMessage)->toArray())->toBe(['text' => '']);
    });

    it('returns itself so calls can be chained', function () {
        $message = new TelegramMessage;

        expect($message->text('hello'))->toBe($message);
    });
});
