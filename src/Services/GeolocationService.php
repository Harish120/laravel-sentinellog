<?php

declare(strict_types=1);

namespace Harryes\SentinelLog\Services;

use Exception;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class GeolocationService
{
    protected Client $client;

    public function __construct()
    {
        $this->client = new Client(['base_uri' => 'http://ip-api.com/json/']);
    }

    /**
     * Get geolocation data for an IP address.
     *
     * @return array<string, mixed>
     */
    public function getLocation(string $ip): array
    {
        if (in_array($ip, ['127.0.0.1', '::1'])) {
            // Use a configurable test IP or fallback
            $testIp = config('sentinel-log.geo_test_ip', null);
            if ($testIp) {
                $ip = $testIp;  // Override with test IP if set
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
            $data = Cache::remember($cacheKey, 3600, function () use ($ip) {
                $response = Http::get("http://ip-api.com/json/{$ip}?fields=country,city,lat,lon,query,status");

                return $response->json();
            });

            if ($data['status'] === 'success') {
                return [
                    'country' => $data['country'] ?? 'Unknown',
                    'city'    => $data['city'] ?? 'Unknown',
                    'lat'     => $data['lat'] ?? 0,
                    'lon'     => $data['lon'] ?? 0,
                    'ip'      => $data['query'] ?? $ip,
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
