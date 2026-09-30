<?php

declare(strict_types=1);

namespace WpSecMon;

/** Minimal HTTPS GET, with the curl extension or PHP streams. Runs as root; never touches sites. */
final class Http
{
    public static function get(string $url, int $timeout = 30, string $proxy = ''): ?string
    {
        $agent = 'wp-secmon/' . VERSION . ' (+read-only WordPress monitor)';
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_USERAGENT => $agent,
                CURLOPT_FAILONERROR => true,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            ]);
            if ($proxy !== '') {
                curl_setopt($ch, CURLOPT_PROXY, $proxy);
            }
            $body = curl_exec($ch);
            $error = curl_error($ch);
            curl_close($ch);
            if ($body === false) {
                Log::debug("GET $url failed: $error");
                return null;
            }
            return (string) $body;
        }

        $opts = ['http' => ['timeout' => $timeout, 'user_agent' => $agent, 'follow_location' => 1, 'max_redirects' => 3]];
        if ($proxy !== '') {
            $opts['http']['proxy'] = preg_replace('#^https?://#', 'tcp://', $proxy);
            $opts['http']['request_fulluri'] = true;
        }
        $body = @file_get_contents($url, false, stream_context_create($opts));
        if ($body === false) {
            Log::debug("GET $url failed");
            return null;
        }
        return $body;
    }

    /** GET $url and check it against the $algo digest published at $sumUrl. Throws on failure. */
    public static function getVerified(string $url, string $sumUrl, string $algo, string $proxy = ''): string
    {
        $body = self::get($url, 120, $proxy);
        $sum = $body !== null ? self::get($sumUrl, 30, $proxy) : null;
        if ($body === null || $sum === null) {
            throw new \RuntimeException(I18n::t('cannot download %s', $body === null ? $url : $sumUrl));
        }
        if (!self::checksumMatches($body, $sum, $algo)) {
            throw new \RuntimeException(I18n::t('checksum mismatch for %s', $url));
        }
        return $body;
    }

    /** True if $published ("<hex digest>", optionally followed by the file name) is the $algo digest of $data. */
    public static function checksumMatches(string $data, string $published, string $algo): bool
    {
        $expected = strtolower((preg_split('/\s+/', trim($published)) ?: [''])[0]);
        return $expected !== '' && hash_equals($expected, hash($algo, $data));
    }
}
