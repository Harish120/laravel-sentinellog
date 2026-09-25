<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Notifications\Messages;

class TeamsMessage
{
    protected string $text = '';

    public function text(string $text): static
    {
        $this->text = $text;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'text' => $this->text,
        ];
    }
}
