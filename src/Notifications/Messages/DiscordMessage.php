<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications\Messages;

class DiscordMessage
{
    protected string $content = '';

    public function content(string $content): static
    {
        $this->content = $content;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'content' => $this->content,
        ];
    }
}
