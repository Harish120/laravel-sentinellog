<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Harryes\SentinelLog\Models\AuthenticationLog;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class DeviceFingerprintService
{
    protected Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Generate a simple fingerprint based on request headers.
     *
     * @return array<string, mixed>
     */
    public function generate(): array
    {
        $headers = $this->request->headers->all();

        return [
            'browser' => $headers['user-agent'][0] ?? null,
            'accept_language' => $headers['accept-language'][0] ?? null,
            'accept_encoding' => $headers['accept-encoding'][0] ?? null,
            'platform' => $this->guessPlatform($headers['user-agent'][0] ?? ''),
            'hash' => $this->createHash(),
        ];
    }

    /**
     * Check if this is a new device based on fingerprint hash.
     */
    public function isNewDevice(Authenticatable $user, string $hash): bool
    {
        Log::info(
            'parameters ',
            [
                'authenticatable_id' => $user->getKey(),
                'authenticatable_type' => get_class($user),
                'is_successful' => true,
                'hash' => $hash,
            ]
        );
        Log::info(
            'isNewDevice',
            [AuthenticationLog::where('authenticatable_id', $user->getKey())
                ->where('authenticatable_type', get_class($user))
                ->where('is_successful', true)
                ->whereRaw('JSON_UNQUOTE(JSON_EXTRACT(device_info, "$.hash")) = ?', [$hash])->toSql()]
        );
        Log::alert('Exists', [
            AuthenticationLog::where('authenticatable_id', $user->getKey())
                ->where('authenticatable_type', get_class($user))
                ->where('is_successful', true)
                ->whereRaw('JSON_UNQUOTE(JSON_EXTRACT(device_info, "$.hash")) = ?', [$hash])
                ->exists(),
        ]);

        return ! AuthenticationLog::where('authenticatable_id', $user->getKey())
            ->where('authenticatable_type', get_class($user))
            ->where('is_successful', true)
            ->whereRaw('JSON_UNQUOTE(JSON_EXTRACT(device_info, "$.hash")) = ?', [$hash])
            ->exists();
    }

    /**
     * Guess the platform from the user agent.
     */
    protected function guessPlatform(string $userAgent): ?string
    {
        if (stripos($userAgent, 'Windows') !== false) {
            return 'Windows';
        } elseif (stripos($userAgent, 'Mac') !== false) {
            return 'MacOS';
        } elseif (stripos($userAgent, 'Linux') !== false) {
            return 'Linux';
        } elseif (stripos($userAgent, 'Android') !== false) {
            return 'Android';
        } elseif (stripos($userAgent, 'iPhone') !== false || stripos($userAgent, 'iPad') !== false) {
            return 'iOS';
        }

        return null;
    }

    /**
     * Create a unique hash for the device.
     */
    protected function createHash(): string
    {
        $data = [
            $this->request->ip(),
            $this->request->userAgent(),
            $this->request->header('accept-language'),
        ];

        return md5(implode('|', array_filter($data)));
    }
}
