<?php

declare(strict_types=1);

namespace WpSecMon\Check;

use WpSecMon\Http;
use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Report;
use WpSecMon\Site;
use WpSecMon\Util;
use WpSecMon\VulnDb;

/**
 * vulns: known vulnerabilities in core, plugins and themes (wpvulnerability.net),
 * plugins/themes closed on wordpress.org, and outdated WordPress core.
 */
final class VulnsCheck extends Check
{
    private VulnDb $db;
    private ?array $versionCheck = null;

    public static function name(): string
    {
        return 'vulns';
    }

    protected function before(): void
    {
        $this->db = new VulnDb($this->ctx->cfg);
        $this->versionCheck = $this->coreReleases();
    }

    protected function after(array $sites): void
    {
        $alerts = $this->ctx->alerts;
        $alerts->setSite(null);
        if ($this->db->fetchErrors > 0) {
            $alerts->alert('warning', 'vulndb-unreachable',
                I18n::t('Vulnerability database unreachable (%s)', $this->ctx->cfg->str('vuln_api_url')),
                '    ' . I18n::n($this->db->fetchErrors, '%d request(s) failed; cached data was used where available.',
                    '%d request(s) failed; cached data was used where available.', $this->db->fetchErrors),
                24, 'unreachable');
        } else {
            $alerts->resolve('vulndb-unreachable');
        }
    }

    protected function checkSite(Site $site): void
    {
        $inv = $this->ctx->inventory($site);
        if ($inv === null) {
            return;
        }
        $alerts = $this->ctx->alerts;
        $repeat = $this->ctx->cfg->int('vuln_repeat_hours');
        $inactive = $this->ctx->cfg->bool('vuln_include_inactive');

        $components = [];
        $core = (string) ($inv['core']['version'] ?? '');
        if ($core !== '') {
            $components[] = ['core', $core, $core, I18n::t('WordPress core %s', $core), ['type' => 'core', 'slug' => 'core', 'name' => 'WordPress', 'version' => $core]];
            $this->outdated($core);
        }
        foreach (['plugin' => 'plugins', 'theme' => 'themes'] as $type => $list) {
            foreach ($inv[$list] ?? [] as $c) {
                $slug = (string) ($c['slug'] ?? '');
                $version = (string) ($c['version'] ?? '');
                if ($slug === '' || (!$inactive && empty($c['active']))) {
                    continue;
                }
                $name = (string) ($c['name'] ?? $slug) ?: $slug;
                if ($type === 'theme') {
                    $label = !empty($c['active']) ? I18n::t('Theme %s %s (%s, active)', $name, $version, $slug)
                        : I18n::t('Theme %s %s (%s, inactive)', $name, $version, $slug);
                } else {
                    $label = !empty($c['active']) ? I18n::t('Plugin %s %s (%s, active)', $name, $version, $slug)
                        : I18n::t('Plugin %s %s (%s, inactive)', $name, $version, $slug);
                }
                $label = Util::oneLine($label);
                $components[] = [$type, $slug, $version, $label, [
                    'type' => $type, 'slug' => $slug, 'name' => (string) ($c['name'] ?? ''), 'version' => $version, 'active' => !empty($c['active']),
                ]];
            }
        }

        $keep = [];
        foreach ($components as [$type, $slug, $version, $label, $meta]) {
            $key = $type === 'core' ? 'core' : "$type.$slug";
            $data = $this->db->get($type, $slug);
            if ($data === null) {
                // Unknown to the API or unreachable: keep whatever is open.
                $keep[] = "vuln.$key";
                $keep[] = "closed.$key";
                continue;
            }
            if ($version !== '') {
                $vulns = VulnDb::match($data, $type, $version);
                if ($vulns) {
                    $keep[] = "vuln.$key";
                    [$sev, $title, $lines, $found] = self::describe($label, $vulns);
                    $alerts->alert($sev, "vuln.$key", $title, $lines, $repeat, null, $meta + $found);
                }
            }
            $reason = $type === 'core' ? null : VulnDb::closedReason($data);
            if ($reason !== null) {
                $keep[] = "closed.$key";
                $alerts->alert(stripos($reason, 'secur') !== false ? 'critical' : 'warning', "closed.$key",
                    $reason !== '' ? I18n::t('%s was closed on wordpress.org (reason: %s)', $label, $reason) : I18n::t('%s was closed on wordpress.org', $label),
                    '    ' . I18n::t('A closed plugin or theme no longer receives updates, including security fixes.'), 24 * 30, null, $meta + ['reason' => $reason]);
            }
        }
        // Components that were updated or removed.
        $alerts->resolveExcept('vuln.', $keep);
        $alerts->resolveExcept('closed.', $keep);
    }

    /**
     * @return array{0: string, 1: string, 2: string[], 3: array} [severity, title, detail lines,
     *         ['count', 'fix' => highest fixed-in version, 'unfixed' => how many have no fix, 'risk' => highest CVSS severity]]
     */
    public static function describe(string $label, array $vulns): array
    {
        $sev = 'warning';
        $lines = [];
        $meta = ['count' => count($vulns), 'fix' => null, 'unfixed' => 0, 'risk' => null];
        $risks = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        foreach ($vulns as $i => $v) {
            if (in_array($v['severity'], ['critical', 'high'], true) || $v['unfixed']) {
                $sev = 'critical';
            }
            if ($v['unfixed']) {
                $meta['unfixed']++;
            } elseif ($v['fixed'] !== null && ($meta['fix'] === null || version_compare($v['fixed'], $meta['fix'], '>'))) {
                $meta['fix'] = $v['fixed'];
            }
            if (($risks[$v['severity']] ?? 0) > ($risks[$meta['risk']] ?? 0)) {
                $meta['risk'] = $v['severity'];
            }
            if ($i >= 15) {
                continue;
            }
            $lines[] = '    - ' . Util::oneLine($v['title']);
            $lines[] = '      ' . I18n::t('severity: %s%s; %s',
                Report::riskName($v['severity']),
                $v['score'] !== null ? ' (CVSS ' . Util::oneLine($v['score'], 10) . ')' : '',
                $v['unfixed'] ? I18n::t('NO FIX AVAILABLE')
                    : ($v['fixed'] !== null ? I18n::t('fixed in %s', Util::oneLine($v['fixed'], 40)) : I18n::t('update to the latest version')));
            $refs = array_filter(array_merge($v['cves'], [$v['link']]), 'strlen');
            if ($refs) {
                $lines[] = '      ' . Util::oneLine(implode('  ', $refs), 400);
            }
        }
        if (count($vulns) > 15) {
            $lines[] = '    ' . I18n::t('... and %d more', count($vulns) - 15);
        }
        $title = I18n::n(count($vulns), '%s: %d known vulnerability', '%s: %d known vulnerabilities', $label, count($vulns));
        return [$sev, $title, $lines, $meta];
    }

    /** Current release of each maintained branch, from api.wordpress.org (cached). */
    private function coreReleases(): ?array
    {
        $file = $this->ctx->cfg->str('state_dir') . '/cache/version-check.json';
        $data = Util::readJson($file);
        if ($data === null || time() - (int) @filemtime($file) > $this->ctx->cfg->int('vuln_cache_hours') * 3600) {
            $body = Http::get($this->ctx->cfg->str('wp_version_api_url'), 30, $this->ctx->cfg->str('http_proxy'));
            $fresh = $body === null ? null : json_decode($body, true);
            if (is_array($fresh) && !empty($fresh['offers'])) {
                Util::writeJson($file, $fresh);
                $data = $fresh;
            } else {
                Log::warning(I18n::t('cannot fetch the WordPress release list; outdated core is not reported this run'));
            }
        }
        $releases = [];
        foreach ($data['offers'] ?? [] as $offer) {
            if (!empty($offer['current'])) {
                $releases[] = (string) $offer['current'];
            }
        }
        return $releases ? array_values(array_unique($releases)) : null;
    }

    private function outdated(string $version): void
    {
        if ($this->versionCheck === null) {
            return;
        }
        [$sev, $title, $lines, $meta] = self::coreStatus($version, $this->versionCheck) ?? [null, null, null, null];
        if ($sev === null) {
            $this->ctx->alerts->resolve('core-outdated');
        } else {
            $this->ctx->alerts->alert($sev, 'core-outdated', $title, $lines, $this->ctx->cfg->int('vuln_repeat_hours'), null, $meta);
        }
    }

    /**
     * @return array{0: string, 1: string, 2: string[], 3: array}|null null when up to date;
     *         [3] = ['version', 'target' => release to install, 'reason' => point|unsupported|major]
     */
    public static function coreStatus(string $version, array $releases): ?array
    {
        $latest = $releases[0];
        $branch = implode('.', array_slice(explode('.', $version), 0, 2));
        $branchLatest = null;
        foreach ($releases as $r) {
            if (implode('.', array_slice(explode('.', $r), 0, 2)) === $branch
                && ($branchLatest === null || version_compare($r, $branchLatest, '>'))) {
                $branchLatest = $r;
            }
        }
        if ($branchLatest !== null && version_compare($version, $branchLatest, '<')) {
            return ['warning', I18n::t('WordPress %s is missing the %s security/maintenance release', $version, $branchLatest),
                ['    ' . I18n::t('Latest WordPress release: %s', $latest)],
                ['version' => $version, 'target' => $branchLatest, 'reason' => 'point']];
        }
        if ($branchLatest === null && version_compare($version, $latest, '<')) {
            return ['warning', I18n::t('WordPress %s is outdated and its branch no longer receives updates', $version),
                ['    ' . I18n::t('Latest WordPress release: %s', $latest)],
                ['version' => $version, 'target' => $latest, 'reason' => 'unsupported']];
        }
        if (version_compare($version, $latest, '<')) {
            return ['info', I18n::t('WordPress %s is not the latest major release (%s)', $version, $latest), [],
                ['version' => $version, 'target' => $latest, 'reason' => 'major']];
        }
        return null;
    }
}
