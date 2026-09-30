<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * WordPress discovery and the site registry (STATE_DIR/sites.json).
 *
 * A WordPress root is a directory holding wp-load.php, wp-settings.php and
 * wp-includes/version.php, with wp-config.php in it or in its parent.
 * Discovery only lists directories as root (it reads no file contents) and
 * never follows symbolic links.
 */
final class Sites
{
    private const PRUNE = ['wp-admin', 'wp-includes', 'wp-content'];

    private Config $cfg;
    private Alerts $alerts;
    private string $file;
    private ?array $map = null;

    public function __construct(Config $cfg, Alerts $alerts)
    {
        $this->cfg = $cfg;
        $this->alerts = $alerts;
        $this->file = $cfg->str('state_dir') . '/sites.json';
    }

    public function registry(): ?array
    {
        return Util::readJson($this->file);
    }

    /** A WordPress root as the registry and --site name it. */
    public static function root(string $path): string
    {
        return rtrim((string) (realpath($path) ?: $path), '/');
    }

    /**
     * Sites to check. Runs discovery first when the registry is missing or
     * stale. $only restricts to the given roots (resolved on the fly if needed).
     * @return Site[]
     */
    public function load(array $only = []): array
    {
        $reg = $this->registry();
        if ($reg === null || time() - (int) ($reg['generated'] ?? 0) > $this->cfg->int('discovery_max_age_hours') * 3600) {
            $reg = $this->discover();
        }
        $sites = [];
        foreach ($reg['sites'] ?? [] as $a) {
            $sites[$a['root']] = Site::fromArray($a);
        }
        if (!$only) {
            return array_values($sites);
        }
        $out = [];
        foreach ($only as $path) {
            $root = self::root($path);
            if (isset($sites[$root])) {
                $out[] = $sites[$root];
                continue;
            }
            $r = $this->resolve($root);
            if ($r['site'] === null) {
                throw new \RuntimeException(I18n::t('%s: %s', $path, $r['reason']));
            }
            $out[] = $r['site'];
        }
        return $out;
    }

    /**
     * Scan, update the registry and report new, removed and skipped sites.
     * With $only, examine only these sites again (see rediscover()).
     */
    public function discover(array $only = []): array
    {
        $started = microtime(true);
        $previous = $this->registry();
        if ($only && $previous !== null) {
            return $this->rediscover($previous, $only, $started);
        }
        if ($only) {
            Log::info(I18n::t('no site list yet: searching the whole server first'));
        }
        $roots = [];
        foreach ($this->cfg->list('scan_paths') as $path) {
            $path = rtrim($path, '/');
            if (is_dir($path) && !is_link($path)) {
                $this->walk($path, 0, $roots);
            } else {
                Log::debug("scan path $path does not exist");
            }
        }
        foreach ($this->cfg->list('extra_sites') as $path) {
            $roots[rtrim($path, '/')] = true;
        }

        [$sites, $skipped, $orphans] = $this->examine(array_map('strval', array_keys($roots)));
        $this->report($previous, $sites, $skipped);

        $reg = [
            'generated' => time(),
            'sites' => $sites,
            'skipped' => $skipped,
            'orphans' => $orphans,
        ];
        Util::writeJson($this->file, $reg);
        Log::info(I18n::t('discovery: %d site(s), %d skipped, %d without wp-config.php (%.1fs)',
            count($sites), count($skipped), count($orphans), microtime(true) - $started));
        return $reg;
    }

    /**
     * Examine some sites again without searching the scan paths, so that
     * `wp-secmon all --site PATH` rescans one site quickly. Only sites found by
     * the last discovery (or in extra_sites) are updated. The list keeps its
     * date, so the next full discovery is due at the same time.
     */
    private function rediscover(array $reg, array $only, float $started): array
    {
        $extra = array_map(static function (string $path): string {
            return rtrim($path, '/');
        }, $this->cfg->list('extra_sites'));
        // Discovery keeps paths as found under scan_paths, which may go through a symbolic link.
        $known = [];
        foreach (array_merge(array_column($reg['sites'] ?? [], 'root'), array_column($reg['skipped'] ?? [], 'root'), $reg['orphans'] ?? [], $extra) as $root) {
            $known[self::root($root)] = $root;
        }
        $roots = [];
        foreach ($only as $path) {
            $root = $known[self::root($path)] ?? null;
            if ($root !== null) {
                $roots[$root] = true;
            } else {
                Log::warning(I18n::t("%s is not in the site list; run 'wp-secmon discover' to search for new sites", $path));
            }
        }
        // Discovery only finds directories that hold wp-load.php; extra_sites are always examined.
        $found = [];
        foreach (array_keys($roots) as $root) {
            if (is_file("$root/wp-load.php") || in_array($root, $extra, true)) {
                $found[] = (string) $root;
            }
        }
        [$sites, $skipped, $orphans] = $this->examine($found);
        foreach ($reg['sites'] ?? [] as $s) {
            if (!isset($roots[$s['root']])) {
                $sites[] = $s;
            }
        }
        foreach ($reg['skipped'] ?? [] as $s) {
            if (!isset($roots[$s['root']])) {
                $skipped[] = $s;
            }
        }
        foreach ($reg['orphans'] ?? [] as $root) {
            if (!isset($roots[$root])) {
                $orphans[] = $root;
            }
        }
        usort($sites, static function ($a, $b) {
            return strcmp($a['root'], $b['root']);
        });
        $this->report($reg, $sites, $skipped, array_map('strval', array_keys($roots)));

        $new = [
            'generated' => (int) ($reg['generated'] ?? 0),
            'sites' => $sites,
            'skipped' => $skipped,
            'orphans' => $orphans,
        ];
        Util::writeJson($this->file, $new);
        Log::info(I18n::n(count($roots), 'rediscovered %d site (%.1fs)', 'rediscovered %d sites (%.1fs)', count($roots), microtime(true) - $started));
        return $new;
    }

    /**
     * Sort WordPress roots into sites to check, sites that cannot be checked
     * (with the reason) and WordPress files without wp-config.php.
     * @param string[] $roots
     * @return array{0: array[], 1: array[], 2: string[]} [sites, skipped, orphans]
     */
    private function examine(array $roots): array
    {
        $sites = $skipped = $orphans = [];
        foreach ($roots as $root) {
            if (preg_match('/' . Util::CONTROL . '/', $root)) {
                $this->alerts->setContext('_global', '(server)', '-');
                $this->alerts->alert('warning', 'badpath.' . substr(hash('sha256', $root), 0, 12),
                    I18n::t('WordPress install with control characters in its path was not checked'),
                    '    ' . json_encode($root, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), 168);
                continue;
            }
            if (Util::matchAny($root, $this->cfg->list('exclude_sites'))) {
                Log::debug("$root: excluded by exclude_sites");
                continue;
            }
            $r = $this->resolve($root);
            if ($r['site'] !== null) {
                $sites[] = $r['site']->toArray();
            } elseif ($r['orphan']) {
                $orphans[] = $root;
            } else {
                $skipped[] = ['root' => $root, 'reason' => $r['reason']];
            }
        }
        usort($sites, static function ($a, $b) {
            return strcmp($a['root'], $b['root']);
        });
        return [$sites, $skipped, $orphans];
    }

    private function walk(string $dir, int $depth, array &$roots): void
    {
        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }
        if (in_array('wp-load.php', $entries, true) && is_file("$dir/wp-load.php")) {
            $roots[$dir] = true;
        }
        if ($depth >= $this->cfg->int('scan_max_depth')) {
            return;
        }
        $exclude = $this->cfg->list('scan_exclude');
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || in_array($entry, self::PRUNE, true)) {
                continue;
            }
            $path = "$dir/$entry";
            if (is_link($path) || !is_dir($path) || Util::matchAny($path, $exclude)) {
                continue;
            }
            $this->walk($path, $depth + 1, $roots);
        }
    }

    /**
     * Decide whether $root is a WordPress install we can check, and as whom.
     * @return array{site: ?Site, orphan: bool, reason: string}
     */
    public function resolve(string $root): array
    {
        $no = static function (string $reason, bool $orphan = false): array {
            return ['site' => null, 'orphan' => $orphan, 'reason' => $reason];
        };
        if (!is_file("$root/wp-includes/version.php") || !is_file("$root/wp-settings.php")) {
            return $no(I18n::t('not a WordPress root (no wp-includes/version.php)'));
        }
        $parent = dirname($root);
        if (is_file("$root/wp-config.php")) {
            $config = "$root/wp-config.php";
        } elseif (is_file("$parent/wp-config.php") && !is_file("$parent/wp-settings.php")) {
            $config = "$parent/wp-config.php";
        } else {
            return $no(I18n::t('no wp-config.php'), true);
        }

        $map = $this->userMap();
        if (isset($map[$root])) {
            $user = $map[$root];
            if ($user === '-' || $user === 'skip') {
                return $no(I18n::t('skipped in %s', $this->cfg->str('site_users_map')));
            }
            $explicit = true;
        } else {
            $st = @stat($root);
            if ($st === false) {
                return $no(I18n::t('cannot stat the directory'));
            }
            $owner = Util::passwd((int) $st['uid']);
            if ($st['uid'] === 0) {
                if ($this->cfg->str('fallback_user') === '') {
                    return $no(I18n::t('owned by root: map it in %s or set fallback_user', $this->cfg->str('site_users_map')));
                }
                $user = $this->cfg->str('fallback_user');
                $explicit = true;
            } elseif ($owner === null) {
                return $no(I18n::t('owner uid %d has no account', $st['uid']));
            } else {
                $user = $owner['name'];
                $explicit = false;
            }
        }

        $pw = Util::passwd($user);
        if ($pw === null) {
            return $no(I18n::t("account '%s' does not exist", $user));
        }
        if ($pw['uid'] === 0) {
            return $no(I18n::t('refusing to check a site as root'));
        }
        if (!$explicit && $pw['uid'] < $this->cfg->int('min_uid') && !in_array($user, $this->cfg->list('allowed_system_users'), true)) {
            return $no(I18n::t("owner '%s' (uid %d) is below min_uid; add it to allowed_system_users or map the site", $user, $pw['uid']));
        }
        if ($this->cfg->bool('skip_suspended_cpanel') && file_exists("/var/cpanel/suspended/$user")) {
            return $no(I18n::t('cPanel account suspended'));
        }
        $euid = Util::effectiveUid();
        if ($euid !== 0 && $pw['uid'] !== $euid) {
            return $no(I18n::t("owned by '%s'; run wp-secmon as root to check it", $user));
        }
        $why = RunAs::refusal($pw, $this->cfg->list('forbidden_groups'));
        if ($why !== null) {
            return $no(I18n::t("refusing to check a site as '%s': %s; map it to another account", $user, $why));
        }
        // Also checked before every run; here it keeps such sites out of the list.
        $why = RunAs::unsafePath($root, $pw);
        if ($why !== null) {
            return $no(I18n::t("%s, so the site could be swapped for code that would run as '%s'", $why, $user));
        }
        return ['site' => new Site($root, $config, $user), 'orphan' => false, 'reason' => ''];
    }

    /** site-users.map: "<wordpress root> <user>" per line; user "-" skips the site. */
    private function userMap(): array
    {
        if ($this->map !== null) {
            return $this->map;
        }
        $this->map = [];
        $file = $this->cfg->str('site_users_map');
        if ($file === '' || !is_file($file)) {
            return $this->map;
        }
        // Whoever can edit the map chooses the account site code runs as.
        if (Util::effectiveUid() === 0 && ($problem = Util::rootOnlyProblem($file)) !== null) {
            throw new \RuntimeException($problem);
        }
        foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (preg_match('/^(.+?)\s+(\S+)$/', $line, $m)) {
                $this->map[rtrim($m[1], '/')] = $m[2];
            }
        }
        return $this->map;
    }

    /** @param string[]|null $only roots whose skipped status to report (null: all) */
    private function report(?array $previous, array $sites, array $skipped, ?array $only = null): void
    {
        $now = array_column($sites, 'user', 'root');
        if ($previous !== null && $this->cfg->bool('alert_on_new_sites')) {
            $before = array_column($previous['sites'] ?? [], 'user', 'root');
            $added = array_diff_key($now, $before);
            $removed = array_diff_key($before, $now);
            $this->alerts->setSite(null);
            if ($added) {
                $lines = [];
                foreach ($added as $root => $user) {
                    $lines[] = '    ' . I18n::t('%s (checked as: %s)', $root, $user);
                }
                $this->alerts->event('info', I18n::n(count($added), '%d new WordPress install(s) found', '%d new WordPress install(s) found', count($added)),
                    $lines, ['kind' => 'sites']);
            }
            if ($removed) {
                $this->alerts->event('info', I18n::n(count($removed), '%d WordPress install(s) no longer found', '%d WordPress install(s) no longer found', count($removed)),
                    Util::listBlock('', array_keys($removed)), ['kind' => 'sites']);
            }
        }

        // Coverage gaps are worth knowing about, once a week.
        foreach ($skipped as $s) {
            if ($only !== null && !in_array($s['root'], $only, true)) {
                continue;
            }
            $this->alerts->setContext(Site::idFor($s['root']), $s['root'], '-');
            if ($this->cfg->bool('alert_on_skipped_sites')) {
                $this->alerts->alert('warning', 'skipped', I18n::t('Site is not monitored: %s', $s['reason']), '', 168);
            }
        }
        foreach ($sites as $s) {
            if ($only !== null && !in_array($s['root'], $only, true)) {
                continue;
            }
            $this->alerts->setContext($s['id'], $s['root'], $s['user']);
            $this->alerts->resolve('skipped');
        }
        $this->alerts->setSite(null);
    }
}
