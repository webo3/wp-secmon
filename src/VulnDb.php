<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Vulnerability data from wpvulnerability.net (free, no API key; aggregates
 * CVE, Wordfence, WPScan and Patchstack sources). Responses are cached per
 * component in STATE_DIR/cache/vulndb.
 */
final class VulnDb
{
    private const SEVERITY = ['c' => 'critical', 'h' => 'high', 'm' => 'medium', 'l' => 'low', 'n' => 'none'];
    private const SEVERITY_RANK = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];

    private Config $cfg;
    private string $cacheDir;
    private float $lastRequest = 0.0;
    public int $fetchErrors = 0;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
        $this->cacheDir = $cfg->str('state_dir') . '/cache/vulndb';
    }

    /** API response for core (slug = version), a plugin or a theme; null if unavailable. */
    public function get(string $type, string $slug): ?array
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/', $slug)) {
            return null;
        }
        $file = "{$this->cacheDir}/$type/$slug.json";
        $maxAge = $this->cfg->int('vuln_cache_hours') * 3600;
        if (is_file($file) && time() - (int) filemtime($file) < $maxAge) {
            return Util::readJson($file);
        }

        $delay = $this->cfg->int('vuln_request_delay_ms') / 1000;
        $wait = $this->lastRequest + $delay - microtime(true);
        if ($wait > 0) {
            usleep((int) ($wait * 1e6));
        }
        $this->lastRequest = microtime(true);
        $url = rtrim($this->cfg->str('vuln_api_url'), '/') . "/$type/" . rawurlencode($slug) . '/';
        $body = Http::get($url, 30, $this->cfg->str('http_proxy'));
        $data = $body === null ? null : json_decode($body, true);
        if (is_array($data) && array_key_exists('data', $data)) {
            Util::writeJson($file, $data);
            return $data;
        }
        $this->fetchErrors++;
        return Util::readJson($file); // stale cache is better than nothing
    }

    /**
     * Vulnerabilities in $response affecting $version, most severe first.
     * @return array<int, array{title: string, cves: string[], link: string, severity: ?string, score: ?string, unfixed: bool, fixed: ?string}>
     */
    public static function match(array $response, string $type, string $version): array
    {
        $records = $response['data']['vulnerability'] ?? [];
        if (!is_array($records)) {
            return [];
        }
        $groups = [];
        foreach ($records as $i => $rec) {
            if (!is_array($rec) || !self::affects($rec['operator'] ?? null, $version)) {
                continue;
            }
            // Plugin/theme records are one per vulnerability; core records
            // share a uuid across unrelated issues, so keep those separate.
            $key = $type === 'core' ? "r$i" : (string) ($rec['uuid'] ?? "r$i");
            $groups[$key][] = $rec;
        }

        $out = [];
        foreach ($groups as $group) {
            $sources = [];
            $impact = [];
            foreach ($group as $rec) {
                $sources = array_merge($sources, is_array($rec['source'] ?? null) ? $rec['source'] : []);
                if (!$impact && is_array($rec['impact'] ?? null) && $rec['impact']) {
                    $impact = $rec['impact'];
                }
            }
            $first = $group[0];
            $title = null;
            $description = null;
            $cves = [];
            $link = '';
            foreach ($sources as $src) {
                $name = (string) ($src['name'] ?? '');
                $id = (string) ($src['id'] ?? '');
                if ($title === null && $name !== '' && strncmp($name, 'CVE-', 4) !== 0) {
                    $title = $name;
                }
                if ($description === null && !empty($src['description'])) {
                    $description = (string) preg_replace('/^\[[a-z]+\]\s*/', '', (string) $src['description']);
                }
                if (strncmp($id, 'CVE-', 4) === 0) {
                    $cves[$id] = true;
                }
                if ($link === '' && !empty($src['link'])) {
                    $link = (string) $src['link'];
                }
            }
            if ($title === null && $description !== null) {
                $title = strlen($description) > 160 ? substr($description, 0, 157) . '...' : $description;
            }
            $cvss = is_array($impact['cvss3'] ?? null) ? $impact['cvss3'] : (is_array($impact['cvss'] ?? null) ? $impact['cvss'] : []);
            $op = is_array($first['operator'] ?? null) ? $first['operator'] : [];
            $out[] = [
                'title' => html_entity_decode($title ?? (string) ($first['name'] ?? I18n::t('unnamed vulnerability')), ENT_QUOTES | ENT_HTML5, 'UTF-8'),
                'cves' => array_keys($cves),
                'link' => $link,
                'severity' => self::severity($cvss['severity'] ?? null),
                'score' => isset($cvss['score']) ? (string) $cvss['score'] : null,
                'unfixed' => (string) ($op['unfixed'] ?? '0') === '1',
                'fixed' => ($op['max_operator'] ?? '') === 'lt' ? (string) $op['max_version'] : null,
            ];
        }

        $unique = [];
        foreach ($out as $v) {
            $unique[$v['title']] = $unique[$v['title']] ?? $v;
        }
        $out = array_values($unique);
        usort($out, static function ($a, $b) {
            return [self::SEVERITY_RANK[$a['severity']] ?? 4, $a['title']] <=> [self::SEVERITY_RANK[$b['severity']] ?? 4, $b['title']];
        });
        return $out;
    }

    /** Closure reason when the plugin/theme was closed on wordpress.org, else null. */
    public static function closedReason(array $response): ?string
    {
        $data = $response['data'] ?? [];
        if (!is_array($data) || (string) ($data['closed'] ?? '0') !== '1') {
            return null;
        }
        return (string) ($data['closed_reason'] ?? '');
    }

    /** Does the version range in $op include $version? (the core endpoint has no range) */
    public static function affects($op, string $version): bool
    {
        if (!is_array($op)) {
            return true;
        }
        $min = (string) ($op['min_version'] ?? '');
        if ($min !== '') {
            $c = version_compare($version, $min);
            $ok = ($op['min_operator'] ?? '') === 'gt' ? $c > 0 : (($op['min_operator'] ?? '') === 'eq' ? $c === 0 : $c >= 0);
            if (!$ok) {
                return false;
            }
        }
        $max = (string) ($op['max_version'] ?? '');
        if ($max !== '') {
            $c = version_compare($version, $max);
            $mo = $op['max_operator'] ?? 'lt';
            return $mo === 'le' ? $c <= 0 : ($mo === 'eq' ? $c === 0 : $c < 0);
        }
        return true;
    }

    private static function severity($value): ?string
    {
        if ($value === null) {
            return null;
        }
        $s = strtolower((string) $value);
        return self::SEVERITY[$s] ?? (in_array($s, self::SEVERITY, true) ? $s : null);
    }
}
