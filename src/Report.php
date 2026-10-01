<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * The report of one run, built from the alerts it emitted.
 *
 * - details(): every alert with its details, as plain text. Kept in the log
 *   directory (last-report-*.txt), and e-mailed as is with mail_format = text.
 * - text(), html(): a short summary per site that says what to do. Printed on
 *   the terminal and e-mailed. File lists and other details stay in the logs.
 *
 * Titles, names and URLs come from the sites: html() escapes everything and
 * text() only prints values already reduced to one line.
 */
final class Report
{
    /** Kinds about the monitoring itself, shown under "Server notes". */
    private const SERVER_KINDS = ['error', 'skipped', 'badpath', 'vulndb-unreachable', 'sites'];
    private const RISK = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
    private const STYLE = [3 => 'critical', 2 => 'warning', 1 => 'ok', 0 => 'ok'];
    /** [text, background] */
    private const COLOR = [
        'critical' => ['#b42318', '#fef3f2'],
        'warning' => ['#b54708', '#fffaeb'],
        'info' => ['#475467', '#f2f4f7'],
        'ok' => ['#067647', '#ecfdf3'],
    ];
    private const ANSI = ['critical' => '1;31', 'warning' => '1;33', 'info' => '36', 'ok' => '32', 'bold' => '1', 'dim' => '2'];
    private const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    private const WIDTH = 76;

    private array $records;
    private array $run;
    private Config $cfg;
    private ?array $model = null;

    /**
     * @param array $records see Alerts::emit()
     * @param array $run host, checks, started, duration, sites, errors, count (per severity), details (file), log (file)
     */
    public function __construct(array $records, array $run, Config $cfg)
    {
        // Most severe sites first, then by path; inside a site, most severe alerts first.
        $siteMax = [];
        foreach ($records as $i => $r) {
            $records[$i]['i'] = $i;
            $siteMax[$r['root']] = max($siteMax[$r['root']] ?? 0, Alerts::RANK[$r['sev']] ?? 0);
        }
        usort($records, static function ($a, $b) use ($siteMax) {
            return [$siteMax[$b['root']], $a['root'], Alerts::RANK[$b['sev']] ?? 0, $a['i']]
                <=> [$siteMax[$a['root']], $b['root'], Alerts::RANK[$a['sev']] ?? 0, $b['i']];
        });
        $this->records = $records;
        $this->run = $run;
        $this->cfg = $cfg;
    }

    /** Title as logged and in the details, with its "Still present: " or "Resolved: " prefix. */
    public static function fullTitle(array $r): string
    {
        if (($r['kind'] ?? '') === 'resolved') {
            return I18n::t('Resolved: %s', $r['title']);
        }
        return ($r['since'] ?? null) !== null ? I18n::t('Still present: %s', $r['title']) : $r['title'];
    }

    /** A severity (critical, warning, info), as shown to people. */
    public static function severityName(string $sev): string
    {
        switch ($sev) {
            case 'critical':
                return I18n::t('critical');
            case 'warning':
                return I18n::t('warning');
            default:
                return I18n::t('info');
        }
    }

    /** "3 critical", "1 warning"... */
    public static function countLabel(string $sev, int $n): string
    {
        switch ($sev) {
            case 'critical':
                return I18n::n($n, '%d critical', '%d critical', $n);
            case 'warning':
                return I18n::n($n, '%d warning', '%d warning', $n);
            default:
                return I18n::n($n, '%d info', '%d info', $n);
        }
    }

    /** A vulnerability severity from the database (critical, high, medium, low, none), as shown to people. */
    public static function riskName(?string $risk): string
    {
        switch ($risk) {
            case 'critical':
                return I18n::t('critical');
            case 'high':
                return I18n::t('high');
            case 'medium':
                return I18n::t('medium');
            case 'low':
                return I18n::t('low');
            case 'none':
                return I18n::t('none');
            default:
                return I18n::t('unknown');
        }
    }

    /** Whether an alert is about the monitoring itself, for the administrator of the server, not about a site. */
    public static function isServerNote(array $r): bool
    {
        return $r['root'] === '(server)' || in_array($r['kind'], self::SERVER_KINDS, true);
    }

    private static function status(int $level): string
    {
        return $level >= 3 ? I18n::t('Action required') : ($level === 2 ? I18n::t('Attention recommended') : I18n::t('No action needed'));
    }

    // ------------------------------------------------------------------
    // Details
    // ------------------------------------------------------------------

    public function details(): string
    {
        $run = $this->run;
        $count = $run['count'];
        $body = I18n::t('wp-secmon report for %s (%s)', $run['host'], $run['checks']) . "\n";
        $body .= I18n::t('Run started %s, took %ds. Sites checked: %d. Check errors: %d.',
            date('Y-m-d H:i:s T', $run['started']), $run['duration'], $run['sites'], $run['errors']) . "\n";
        $body .= I18n::t('Alerts: %d critical, %d warning, %d info.', $count['critical'], $count['warning'], $count['info']) . "\n";
        $rule = str_repeat('=', 74);
        $current = null;
        foreach ($this->records as $r) {
            if ($r['root'] !== $current) {
                $current = $r['root'];
                $body .= "\n$rule\n" . ($r['root'] === '(server)' ? I18n::t('(server)') : $r['root'])
                    . ($r['user'] !== '-' ? '  ' . I18n::t('(checked as: %s)', $r['user']) : '') . "\n$rule\n";
            }
            $body .= sprintf("\n[%s] %s: %s\n", Util::upper(self::severityName($r['sev'])), $r['check'], self::fullTitle($r));
            if ($r['details'] !== '') {
                $body .= $r['details'] . "\n";
            }
        }
        $body .= "\n--\n" . I18n::t('wp-secmon %s is read-only: it never modifies the sites it checks.', VERSION) . "\n";
        $body .= I18n::t('Alert history: %s   Open alerts: wp-secmon status', $run['log']) . "\n";
        return $body;
    }

    // ------------------------------------------------------------------
    // Summary model
    // ------------------------------------------------------------------

    /** @return array{0: array[], 1: array[]} [sites, server notes] */
    public function model(): array
    {
        if ($this->model !== null) {
            return $this->model;
        }
        $bySite = [];
        $server = [];
        foreach ($this->records as $r) {
            if (self::isServerNote($r)) {
                $server[] = $r;
            } else {
                $bySite[$r['root']][] = $r;
            }
        }
        $sites = [];
        foreach ($bySite as $root => $records) {
            $sites[] = $this->site((string) $root, $records);
        }
        usort($sites, static function ($a, $b) {
            return [$b['level'], $a['root']] <=> [$a['level'], $b['root']];
        });
        return $this->model = [$sites, $server];
    }

    private function site(string $root, array $records): array
    {
        $level = 0;
        $updates = [];
        $findings = [];
        $fixed = [];
        foreach ($records as $r) {
            if ($r['kind'] === 'resolved') {
                $fixed[] = $r;
                continue;
            }
            $level = max($level, Alerts::RANK[$r['sev']] ?? 0);
            if ($r['kind'] === 'vuln' || $r['kind'] === 'closed') {
                self::addUpdate($updates, $r);
            } else {
                $findings[] = $r;
            }
        }
        // WordPress: the release that fixes everything, security releases included.
        foreach ($findings as $r) {
            $target = (string) ($r['meta']['target'] ?? '');
            if ($r['kind'] === 'core-outdated' && ($r['meta']['reason'] ?? '') !== 'major' && isset($updates['core.core'])
                && ($updates['core.core']['fix'] === null || version_compare($target, $updates['core.core']['fix'], '>'))) {
                $updates['core.core']['fix'] = Util::oneLine($target, 30);
            }
        }
        usort($updates, static function ($a, $b) {
            return [$a['type'] !== 'core', -(Alerts::RANK[$a['sev']] ?? 0), -(self::RISK[$a['risk']] ?? 0), strtolower($a['name'])]
                <=> [$b['type'] !== 'core', -(Alerts::RANK[$b['sev']] ?? 0), -(self::RISK[$b['risk']] ?? 0), strtolower($b['name'])];
        });
        return [
            'root' => $root,
            'user' => (string) $records[0]['user'],
            'url' => $this->siteUrl($root),
            'level' => $level,
            'todo' => self::advice($records, $updates),
            'updates' => $updates,
            'findings' => $findings,
            'fixed' => $fixed,
        ];
    }

    /** One row per component: its vulnerabilities and whether it was closed on wordpress.org. */
    private static function addUpdate(array &$rows, array $r): void
    {
        $m = $r['meta'];
        $type = (string) ($m['type'] ?? '');
        $key = $type . '.' . ($m['slug'] ?? '');
        $row = $rows[$key] ?? [
            'type' => $type,
            'name' => $type === 'core' ? 'WordPress' : Util::oneLine((string) (($m['name'] ?? '') ?: ($m['slug'] ?? '?')), 80),
            'version' => Util::oneLine((string) ($m['version'] ?? ''), 30),
            'active' => $type === 'core' || !empty($m['active']),
            'sev' => $r['sev'],
            'vulns' => 0,
            'fix' => null,
            'unfixed' => 0,
            'risk' => null,
            'closed' => null,
        ];
        if ((Alerts::RANK[$r['sev']] ?? 0) > (Alerts::RANK[$row['sev']] ?? 0)) {
            $row['sev'] = $r['sev'];
        }
        if ($r['kind'] === 'vuln') {
            $row['vulns'] = (int) ($m['count'] ?? 0);
            $row['fix'] = isset($m['fix']) ? Util::oneLine((string) $m['fix'], 30) : null;
            $row['unfixed'] = (int) ($m['unfixed'] ?? 0);
            $row['risk'] = isset(self::RISK[$m['risk'] ?? '']) ? $m['risk'] : null;
        } else {
            $row['closed'] = Util::oneLine((string) ($m['reason'] ?? ''), 60);
        }
        $rows[$key] = $row;
    }

    /**
     * What to do on a site, most severe first.
     * @return array<int, array{0: string, 1: string}> [severity, text]
     */
    private static function advice(array $records, array $updates): array
    {
        $by = [];
        foreach ($records as $r) {
            $by[$r['kind']][] = $r;
        }
        $todo = [];
        $add = static function (string $sev, string $text) use (&$todo): void {
            $todo[] = [$sev, $text];
        };

        // Signs of a compromise.
        if (isset($by['admin-new'])) {
            $add('critical', I18n::t('Confirm that each new administrator listed below is legitimate. If nobody on your team created it, '
                . 'treat the site as hacked: delete the account, change every administrator password and have the site cleaned.'));
        }
        foreach ($by['option'] ?? [] as $r) {
            if (in_array($r['meta']['option'] ?? '', ['siteurl', 'home'], true)) {
                $add('critical', I18n::t('The site address changed. If this was not planned, visitors may be sent to another site: '
                    . 'restore the address in Settings > General and find out how it was changed.'));
                break;
            }
        }
        foreach ($by['core-checksums'] ?? [] as $r) {
            $changed = (int) ($r['meta']['modified'] ?? 0) + (int) ($r['meta']['extra'] ?? 0);
            $missing = (int) ($r['meta']['missing'] ?? 0);
            $add($r['sev'], $changed > 0
                ? I18n::n($changed, '%d file was changed or added in WordPress core. WordPress never does this by itself: '
                    . 'it usually means the site was hacked. Reinstall the WordPress core files and look for other backdoors.',
                    '%d files were changed or added in WordPress core. WordPress never does this by itself: '
                    . 'it usually means the site was hacked. Reinstall the WordPress core files and look for other backdoors.', $changed)
                : I18n::n($missing, '%d WordPress core file is missing: reinstall the WordPress core files.',
                    '%d WordPress core files are missing: reinstall the WordPress core files.', $missing));
        }
        if (isset($by['plugin-checksums'])) {
            $slugs = array_map(static function ($r) {
                return Util::oneLine((string) ($r['meta']['slug'] ?? '?'), 80);
            }, $by['plugin-checksums']);
            $add(self::maxSev($by['plugin-checksums']), I18n::n(count(array_unique($slugs)),
                'Files of %s differ from the official version: reinstall it from wordpress.org and look for injected code.',
                'Files of %s differ from the official version: reinstall these plugins from wordpress.org and look for injected code.',
                self::names($slugs)));
        }
        $suspicious = $changed = false;
        foreach ($by['files'] ?? [] as $r) {
            $suspicious = $suspicious || $r['sev'] === 'critical';
            $changed = $changed || $r['sev'] === 'warning';
        }
        if ($suspicious) {
            $add('critical', I18n::t('New PHP files appeared where WordPress does not put them. '
                . 'Check that your team added them: unknown files there are often backdoors.'));
        }
        foreach ($by['uploads-exec'] ?? [] as $r) {
            $n = (int) ($r['meta']['count'] ?? 0);
            $add($r['sev'], I18n::n($n, 'The uploads folder, which should only hold images and documents, contains %d PHP or script file. '
                . 'Have it reviewed and removed, and block PHP in that folder.',
                'The uploads folder, which should only hold images and documents, contains %d PHP or script files. '
                . 'Have them reviewed and removed, and block PHP in that folder.', $n));
        }
        foreach ($by['risky-registration'] ?? [] as $r) {
            $add($r['sev'], I18n::t('Anyone can register and get the "%s" role. Turn off "Anyone can register", '
                . 'or set "New User Default Role" to Subscriber (Settings > General).', Util::oneLine((string) ($r['meta']['role'] ?? '?'), 40)));
        }

        // Updates.
        $core = null;
        $toUpdate = $inactive = $noFix = $closed = [];
        foreach ($updates as $u) {
            if ($u['type'] === 'core') {
                $core = $u;
                continue;
            }
            if ($u['closed'] !== null) {
                $closed[] = $u;
            }
            if ($u['vulns'] === 0) {
                continue;
            }
            if ($u['fix'] === null && $u['unfixed'] > 0) {
                if ($u['closed'] === null) {
                    $noFix[] = $u;
                }
            } elseif (!$u['active']) {
                $inactive[] = $u;
            } else {
                $toUpdate[] = $u;
            }
        }
        $outdated = $by['core-outdated'][0] ?? null;
        $target = $outdated !== null && ($outdated['meta']['reason'] ?? '') !== 'major' ? (string) ($outdated['meta']['target'] ?? '') : '';
        if ($core !== null) {
            $add($core['sev'], I18n::n($core['vulns'], 'Update WordPress %s to %s: this version has %d known security hole.',
                'Update WordPress %s to %s: this version has %d known security holes.', $core['version'],
                $core['fix'] !== null ? I18n::t('%s or later', $core['fix']) : I18n::t('the latest version'), $core['vulns']));
        } elseif ($outdated !== null && $target !== '') {
            $version = Util::oneLine((string) ($outdated['meta']['version'] ?? ''), 30);
            $add($outdated['sev'], ($outdated['meta']['reason'] ?? '') === 'unsupported'
                ? I18n::t('Update WordPress %s to %s: this version no longer receives security fixes.', $version, Util::oneLine($target, 30))
                : I18n::t('Update WordPress %s to %s: it is a security and maintenance release.', $version, Util::oneLine($target, 30)));
        }
        if ($toUpdate) {
            $add(self::maxSev($toUpdate), I18n::t('Update %s with known security holes (see "Updates needed").', self::components($toUpdate)));
        }
        if ($noFix) {
            $add(self::maxSev($noFix), I18n::n(count($noFix), 'No fix exists yet for %s: remove or replace it.',
                'No fix exists yet for %s: remove or replace them.', self::names(array_column($noFix, 'name'))));
        }
        if ($closed) {
            $add(self::maxSev($closed), I18n::n(count($closed), 'Replace %s: it was removed from wordpress.org and no longer gets security fixes.',
                'Replace %s: they were removed from wordpress.org and no longer get security fixes.', self::names(array_column($closed, 'name'))));
        }
        if ($inactive) {
            $add(self::maxSev($inactive), I18n::n(count($inactive),
                'Delete the %s with known security holes if you do not use it, or update it: inactive code can still be attacked.',
                'Delete the %s with known security holes if you do not use them, or update them: inactive code can still be attacked.',
                self::components($inactive, true)));
        }
        if ($outdated !== null && ($outdated['meta']['reason'] ?? '') === 'major' && $core === null) {
            $add('info', I18n::t('WordPress %s is available (this site runs %s): plan the upgrade.',
                Util::oneLine((string) ($outdated['meta']['target'] ?? ''), 30), Util::oneLine((string) ($outdated['meta']['version'] ?? ''), 30)));
        }

        // Changes to confirm.
        if (isset($by['admin-email'])) {
            $add('warning', I18n::t('An administrator e-mail address changed: confirm it. Whoever controls that address can reset the password.'));
        }
        if ($changed) {
            $add('warning', I18n::t('Sensitive files changed, such as wp-config.php, .htaccess or must-use plugins. '
                . 'Confirm that your team made these changes.'));
        }
        if (self::maxSev($by['components'] ?? []) !== 'info') {
            $add('warning', I18n::t('Plugins or themes were installed, activated or deactivated: confirm that your team made these changes.'));
        }
        if (self::maxSev($by['users-new'] ?? []) !== 'info') {
            $add('warning', I18n::t('New accounts were created. This is normal on shops and membership sites; otherwise, look for spam sign-ups.'));
        }
        $other = array_merge($by['admin-lost'] ?? [], $by['user-renamed'] ?? [], array_filter($by['option'] ?? [], static function ($r) {
            return !in_array($r['meta']['option'] ?? '', ['siteurl', 'home'], true);
        }));
        if (self::maxSev($other) !== 'info') {
            $add('warning', I18n::t('Confirm the account and setting changes listed below.'));
        }

        $keys = array_keys($todo);
        usort($keys, static function ($a, $b) use ($todo) {
            return [-(Alerts::RANK[$todo[$a][0]] ?? 0), $a] <=> [-(Alerts::RANK[$todo[$b][0]] ?? 0), $b];
        });
        return array_map(static function ($k) use ($todo) {
            return $todo[$k];
        }, $keys);
    }

    /** Highest severity of $items (records or update rows); "info" when empty. */
    private static function maxSev(array $items): string
    {
        $max = 'info';
        foreach ($items as $i) {
            if ((Alerts::RANK[$i['sev']] ?? 0) > Alerts::RANK[$max]) {
                $max = $i['sev'];
            }
        }
        return $max;
    }

    /** "A, B and C", or "A, B, C and 4 more". */
    private static function names(array $names): string
    {
        $names = array_values(array_unique($names));
        $n = count($names);
        if ($n > 4) {
            return I18n::t('%s and %d more', implode(', ', array_slice($names, 0, 3)), $n - 3);
        }
        return $n > 1 ? I18n::t('%s and %s', implode(', ', array_slice($names, 0, -1)), $names[$n - 1]) : (string) ($names[0] ?? '');
    }

    /** "21 plugins and 1 theme", or "2 inactive plugins" */
    private static function components(array $rows, bool $inactive = false): string
    {
        $plugins = $themes = 0;
        foreach ($rows as $u) {
            if ($u['type'] === 'theme') {
                $themes++;
            } else {
                $plugins++;
            }
        }
        $parts = [];
        if ($plugins > 0) {
            $parts[] = $inactive ? I18n::n($plugins, '%d inactive plugin', '%d inactive plugins', $plugins) : I18n::n($plugins, '%d plugin', '%d plugins', $plugins);
        }
        if ($themes > 0) {
            $parts[] = $inactive ? I18n::n($themes, '%d inactive theme', '%d inactive themes', $themes) : I18n::n($themes, '%d theme', '%d themes', $themes);
        }
        return count($parts) > 1 ? I18n::t('%s and %s', $parts[0], $parts[1]) : (string) ($parts[0] ?? '');
    }

    /** Site address from the last integrity check, without the scheme. */
    private function siteUrl(string $root): ?string
    {
        $o = Util::readJson($this->cfg->str('state_dir') . '/sites/' . Site::idFor($root) . '/options.json');
        $home = is_string($o['home'] ?? null) ? (string) preg_replace('#^https?://#i', '', rtrim($o['home'], '/')) : '';
        return $home !== '' ? Util::oneLine($home, 100) : null;
    }

    private function headline(): string
    {
        $parts = [];
        if ($this->run['sites'] > 0) {
            $parts[] = I18n::n($this->run['sites'], '%d site checked', '%d sites checked', $this->run['sites']);
        }
        [$sites] = $this->model();
        $need = count(array_filter($sites, static function ($s) {
            return $s['level'] >= 2;
        }));
        if ($need > 0) {
            $parts[] = I18n::n($need, '%d needs action', '%d need action', $need);
        }
        return implode(' · ', $parts);
    }

    private static function since(array $r): string
    {
        return ($r['since'] ?? null) !== null ? I18n::t('still open since %s', I18n::date('M j', (int) $r['since'])) : '';
    }

    private static function updateTo(array $u): string
    {
        if ($u['fix'] !== null) {
            return $u['fix'];
        }
        if ($u['vulns'] > 0) {
            return $u['unfixed'] > 0 ? I18n::t('no fix yet') : I18n::t('latest');
        }
        return I18n::t('replace');
    }

    /** Name of an update row, with "(theme)" for themes. */
    private static function name(array $u): string
    {
        return $u['type'] === 'theme' ? I18n::t('%s (theme)', $u['name']) : $u['name'];
    }

    private static function note(array $u): string
    {
        $notes = [];
        if (!$u['active']) {
            $notes[] = $u['type'] === 'theme' ? I18n::tc('theme', 'inactive') : I18n::tc('plugin', 'inactive');
        }
        if ($u['fix'] !== null && $u['unfixed'] > 0) {
            $notes[] = I18n::n($u['unfixed'], 'no fix yet for %d issue', 'no fix yet for %d issues', $u['unfixed']);
        }
        if ($u['closed'] !== null) {
            $notes[] = $u['closed'] !== '' ? I18n::t('closed on wordpress.org (%s)', $u['closed']) : I18n::t('closed on wordpress.org');
        }
        return implode(', ', $notes);
    }

    private static function riskStyle(?string $risk): string
    {
        $r = self::RISK[$risk ?? ''] ?? 0;
        return $r >= 3 ? 'critical' : ($r === 2 ? 'warning' : 'info');
    }

    // ------------------------------------------------------------------
    // Text (terminal and the text part of the e-mail)
    // ------------------------------------------------------------------

    public function text(bool $color = false): string
    {
        [$sites, $server] = $this->model();
        $c = static function (string $style, string $s) use ($color): string {
            return $color && $s !== '' ? "\e[" . self::ANSI[$style] . "m$s\e[0m" : $s;
        };
        $run = $this->run;
        $count = $run['count'];
        $out = $c('bold', I18n::t('wp-secmon security report for %s', $run['host'])) . "\n";
        $out .= sprintf("%s · %s · %ds\n", date('Y-m-d H:i T', $run['started']), $run['checks'], $run['duration']);
        $counts = [];
        foreach (['critical', 'warning', 'info'] as $sev) {
            if ($count[$sev] > 0) {
                $counts[] = $c($sev, self::countLabel($sev, $count[$sev]));
            }
        }
        $out .= implode(' · ', array_filter([$this->headline(), implode(', ', $counts)])) . "\n";

        $rule = str_repeat('━', self::WIDTH);
        // Severity column: as wide as the longest severity name.
        $sw = 1 + max(array_map(static function (string $sev): int {
            return Util::width(self::severityName($sev));
        }, array_keys(Alerts::RANK)));
        foreach ($sites as $s) {
            $status = Util::upper(self::status($s['level']));
            $name = $s['url'] ?? $s['root'];
            $gap = max(2, self::WIDTH - Util::width($name) - Util::width($status));
            $out .= "\n$rule\n" . $c('bold', $name) . str_repeat(' ', $gap) . $c(self::STYLE[$s['level']], $status) . "\n";
            $out .= $c('dim', ($s['url'] !== null ? $s['root'] . ' · ' : '') . I18n::t('checked as %s', $s['user'])) . "\n$rule\n";
            if ($s['todo']) {
                $out .= "\n" . $c('bold', I18n::t('What to do')) . "\n";
                foreach ($s['todo'] as $i => [$sev, $text]) {
                    $out .= '  ' . $c($sev, sprintf('%2d.', $i + 1)) . ' ' . self::wrap($text, 6) . "\n";
                }
            }
            if ($s['updates']) {
                $out .= "\n" . $c('bold', I18n::t('Updates needed')) . "\n";
                $w = min(34, max(14, ...array_map(static function ($u) {
                    return Util::width(self::name($u));
                }, $s['updates'])));
                $out .= $c('dim', '  ' . self::fit(I18n::t('NAME'), $w) . '  ' . self::fit(I18n::t('INSTALLED'), 10) . '  '
                    . self::fit(I18n::t('UPDATE TO'), 10) . '  ' . self::fit(I18n::t('RISK'), 8) . '  ' . I18n::t('NOTE')) . "\n";
                foreach ($s['updates'] as $u) {
                    $risk = $u['vulns'] > 0 ? self::riskName($u['risk']) : '-';
                    $out .= '  ' . self::fit(self::name($u), $w)
                        . '  ' . self::fit($u['version'], 10) . '  ' . self::fit(self::updateTo($u), 10)
                        . '  ' . $c(self::riskStyle($u['risk']), self::fit($risk, 8)) . '  ' . self::note($u) . "\n";
                }
            }
            if ($s['findings']) {
                $out .= "\n" . $c('bold', $s['updates'] ? I18n::t('Other findings') : I18n::t('Findings')) . "\n";
                foreach ($s['findings'] as $r) {
                    $since = self::since($r);
                    $out .= '  ' . $c($r['sev'], self::fit(Util::upper(self::severityName($r['sev'])), $sw)) . ' '
                        . self::wrap($r['title'] . ($since !== '' ? " ($since)" : ''), $sw + 3) . "\n";
                }
            }
            if ($s['fixed']) {
                $out .= "\n" . $c('bold', I18n::t('Fixed since the last report')) . "\n";
                foreach ($s['fixed'] as $r) {
                    $out .= '  ' . $c('ok', '✓') . ' ' . self::wrap($r['title'], 4) . "\n";
                }
            }
        }
        if ($server) {
            $out .= "\n$rule\n" . $c('bold', I18n::t('Server notes')) . "\n";
            foreach ($server as $r) {
                $out .= '  ' . $c($r['sev'], self::fit(Util::upper(self::severityName($r['sev'])), $sw)) . ' '
                    . self::wrap(self::serverNote($r), $sw + 3) . "\n";
            }
        }
        $out .= "\n" . $c('dim', I18n::t('Details: %s · Open alerts: wp-secmon status', $run['details'])) . "\n";
        $out .= $c('dim', I18n::t('wp-secmon %s is read-only: it never modifies the sites it checks.', VERSION)) . "\n";
        return $out;
    }

    /** wordwrap() counting characters, not bytes (accents). */
    private static function wrap(string $text, int $indent): string
    {
        $lines = [];
        $line = null;
        foreach (explode(' ', $text) as $word) {
            if ($line !== null && Util::width($line) + 1 + Util::width($word) > self::WIDTH - $indent) {
                $lines[] = $line;
                $line = $word;
            } else {
                $line = $line === null ? $word : "$line $word";
            }
        }
        $lines[] = (string) $line;
        return implode("\n" . str_repeat(' ', $indent), $lines);
    }

    /** A server note, with the site it is about. */
    private static function serverNote(array $r): string
    {
        return $r['root'] !== '(server)' ? I18n::t('%s: %s', $r['root'], self::fullTitle($r)) : self::fullTitle($r);
    }

    /** $s cut or padded to $width characters. */
    private static function fit(string $s, int $width): string
    {
        if ($s === '') {
            return str_repeat(' ', $width);
        }
        $chars = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: str_split($s);
        if (count($chars) > $width) {
            $chars = array_slice($chars, 0, $width - 1);
            $chars[] = '…';
        }
        return implode('', $chars) . str_repeat(' ', max(0, $width - count($chars)));
    }

    // ------------------------------------------------------------------
    // HTML (e-mail): inline styles and tables, which every mail client renders
    // ------------------------------------------------------------------

    public function html(): string
    {
        [$sites, $server] = $this->model();
        $run = $this->run;
        $count = $run['count'];
        $pills = [];
        foreach (['critical', 'warning', 'info'] as $sev) {
            if ($count[$sev] > 0) {
                $pills[] = self::pill($sev, self::countLabel($sev, $count[$sev]));
            }
        }
        $h = '<!DOCTYPE html><html lang="' . I18n::language() . '"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light">'
            . '<title>' . self::e(I18n::t('Security report for %s', $run['host'])) . "</title></head>\n"
            . '<body style="margin:0;padding:0;background:#f2f4f7;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f2f4f7;"><tr>'
            . '<td align="center" style="padding:24px 8px;">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:680px;font-family:'
            . self::FONT . ';color:#101828;">' . "\n"
            . '<tr><td style="padding:0 4px 20px;">'
            . '<div style="font-size:13px;color:#667085;">wp-secmon · ' . self::e($run['host']) . '</div>'
            . '<div style="font-size:24px;font-weight:700;margin:4px 0 6px;">' . self::e(I18n::t('Security report')) . '</div>'
            . '<div style="font-size:14px;color:#475467;">'
            . self::e(implode(' · ', array_filter([I18n::date('F j, Y, H:i T', $run['started']), $this->headline()]))) . '</div>'
            . ($pills ? '<div style="margin-top:12px;">' . implode(' ', $pills) . '</div>' : '')
            . "</td></tr>\n";
        foreach ($sites as $s) {
            $h .= '<tr><td style="padding:0 0 16px;">' . self::htmlSite($s) . "</td></tr>\n";
        }
        if ($server) {
            $rows = '';
            foreach ($server as $r) {
                $rows .= self::htmlLine($r['sev'], self::serverNote($r), '');
            }
            $h .= '<tr><td style="padding:0 0 16px;">' . self::card('#d0d5dd',
                '<div style="font-size:15px;font-weight:700;">' . self::e(I18n::t('Server notes')) . '</div>'
                . '<div style="font-size:13px;color:#667085;margin-top:2px;">'
                . self::e(I18n::t('About the monitoring itself, for the administrator.')) . '</div>',
                self::table($rows)) . "</td></tr>\n";
        }
        $h .= '<tr><td style="padding:4px 4px 0;font-size:12px;line-height:1.6;color:#667085;">'
            . self::e(I18n::t('Full details on %s: %s · Open alerts: wp-secmon status', $run['host'], $run['details'])) . '<br>'
            . self::e(I18n::t('wp-secmon %s is read-only: it never modifies the sites it checks.', VERSION))
            . "</td></tr>\n</table></td></tr></table></body></html>\n";
        return $h;
    }

    private static function htmlSite(array $s): string
    {
        $style = self::STYLE[$s['level']];
        $head = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
            . '<td style="vertical-align:top;"><div style="font-size:17px;font-weight:700;word-break:break-word;">'
            . self::e($s['url'] ?? $s['root']) . '</div>'
            . '<div style="font-size:12px;color:#667085;margin-top:3px;word-break:break-all;">'
            . self::e(($s['url'] !== null ? $s['root'] . ' · ' : '') . I18n::t('checked as %s', $s['user'])) . '</div></td>'
            . '<td align="right" style="vertical-align:top;padding-left:12px;white-space:nowrap;">'
            . self::pill($style, self::status($s['level'])) . '</td></tr></table>';

        $body = '';
        if ($s['todo']) {
            $rows = '';
            foreach ($s['todo'] as $i => [$sev, $text]) {
                $rows .= '<tr><td style="width:30px;vertical-align:top;padding:0 0 10px;">'
                    . '<div style="width:22px;height:22px;line-height:22px;border-radius:11px;text-align:center;font-size:12px;font-weight:700;'
                    . 'color:#ffffff;background:' . self::COLOR[$sev][0] . ';">' . ($i + 1) . '</div></td>'
                    . '<td style="vertical-align:top;padding:2px 0 10px;font-size:14px;line-height:1.5;">' . self::e($text) . '</td></tr>';
            }
            $body .= self::heading(I18n::t('What to do')) . self::table($rows);
        }
        if ($s['updates']) {
            $th = 'style="padding:6px;border-bottom:1px solid #eaecf0;font-size:12px;font-weight:600;color:#475467;text-align:left;"';
            $rows = "<tr style=\"background:#f9fafb;\"><th $th>" . self::e(I18n::t('Plugin / theme')) . "</th><th $th>" . self::e(I18n::t('Installed'))
                . "</th><th $th>" . self::e(I18n::t('Update to')) . "</th><th $th>" . self::e(I18n::t('Risk')) . '</th></tr>';
            foreach ($s['updates'] as $u) {
                $td = 'style="padding:7px 6px;border-bottom:1px solid #f2f4f7;vertical-align:top;font-size:13px;word-break:break-word;"';
                $note = self::note($u);
                $rows .= "<tr><td $td>" . self::e($u['name']) . ($u['type'] === 'theme' ? ' <span style="color:#667085;">' . self::e(I18n::t('(theme)')) . '</span>' : '')
                    . ($note !== '' ? '<div style="font-size:12px;color:#667085;">' . self::e($note) . '</div>' : '') . '</td>'
                    . "<td $td>" . self::e($u['version']) . "</td><td $td><b>" . self::e(self::updateTo($u)) . '</b></td>'
                    . "<td $td>" . ($u['vulns'] > 0 ? self::pill(self::riskStyle($u['risk']), self::riskName($u['risk'])) : '') . '</td></tr>';
            }
            $body .= self::heading(I18n::t('Updates needed')) . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
                . 'style="border-collapse:collapse;margin-bottom:6px;">' . $rows . '</table>';
        }
        if ($s['findings']) {
            $rows = '';
            foreach ($s['findings'] as $r) {
                $rows .= self::htmlLine($r['sev'], $r['title'], self::since($r));
            }
            $body .= self::heading($s['updates'] ? I18n::t('Other findings') : I18n::t('Findings')) . self::table($rows);
        }
        if ($s['fixed']) {
            $rows = '';
            foreach ($s['fixed'] as $r) {
                $rows .= '<tr><td style="width:24px;vertical-align:top;padding:3px 0;color:' . self::COLOR['ok'][0] . ';font-weight:700;">✓</td>'
                    . '<td style="padding:3px 0 5px;font-size:14px;line-height:1.45;">' . self::e($r['title']) . '</td></tr>';
            }
            $body .= self::heading(I18n::t('Fixed since the last report')) . self::table($rows);
        }
        return self::card(self::COLOR[$style][0], $head, $body);
    }

    private static function card(string $accent, string $head, string $body): string
    {
        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            . 'style="background:#ffffff;border:1px solid #e4e7ec;border-top:4px solid ' . $accent . ';border-radius:8px;border-collapse:separate;">'
            . '<tr><td style="padding:16px;' . ($body !== '' ? 'border-bottom:1px solid #eaecf0;' : '') . '">' . $head . '</td></tr>'
            . ($body !== '' ? '<tr><td style="padding:6px 16px 12px;">' . $body . '</td></tr>' : '')
            . '</table>';
    }

    private static function heading(string $text): string
    {
        return '<div style="font-size:12px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:#667085;margin:14px 0 8px;">'
            . self::e($text) . '</div>';
    }

    private static function table(string $rows): string
    {
        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">' . $rows . '</table>';
    }

    private static function htmlLine(string $sev, string $text, string $note): string
    {
        return '<tr><td style="width:82px;vertical-align:top;padding:3px 0;">' . self::pill($sev, self::severityName($sev)) . '</td>'
            . '<td style="vertical-align:top;padding:3px 0 6px;font-size:14px;line-height:1.45;word-break:break-word;">' . self::e($text)
            . ($note !== '' ? ' <span style="font-size:12px;color:#667085;">· ' . self::e($note) . '</span>' : '') . '</td></tr>';
    }

    private static function pill(string $style, string $text): string
    {
        [$fg, $bg] = self::COLOR[$style];
        return '<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:600;line-height:18px;'
            . "color:$fg;background:$bg;\">" . self::e($text) . '</span>';
    }

    private static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
