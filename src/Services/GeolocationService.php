<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class GeolocationService
{
    /**
     * Get geolocation data for an IP address.
     *
     * @return array<string, mixed>
     */
    public function getLocation(string $ip): array
    {
        if (in_array($ip, ['127.0.0.1', '::1'])) {
            $testIp = config('sentinel-log.geo_test_ip', null);
            if ($testIp) {
                $ip = $testIp;
            } else {
                return [
                    'country' => 'Local',
                    'city'    => 'Localhost',
                    'lat'     => 0,
                    'lon'     => 0,
                ];
            }
        }

        try {
            $cacheKey = "sentinel_log_geo_{$ip}";

            /** @var array<string, mixed> $data */
            $data = Cache::remember($cacheKey, 3600, function () use ($ip) {
                $baseUrl = rtrim((string) config('sentinel-log.geo_provider_url', 'https://ipwho.is'), '/');

                return Http::get("{$baseUrl}/{$ip}")->json();
            });

            if ($data['success'] === true) {
                return [
                    'country' => $data['country']  ?? 'Unknown',
                    'city'    => $data['city']      ?? 'Unknown',
                    'lat'     => $data['latitude']  ?? 0,
                    'lon'     => $data['longitude'] ?? 0,
                    'ip'      => $data['ip']        ?? $ip,
                ];
            }
        } catch (Exception) {
            // Fall through to default return
        }

        return [
            'country' => 'Unknown',
            'city'    => 'Unknown',
            'lat'     => 0,
            'lon'     => 0,
            'ip'      => $ip,
        ];
    }
}
