<?php

declare(strict_types=1);

namespace WpSecMon\Check;

use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Site;
use WpSecMon\Util;

/**
 * integrity: changes that usually follow a compromise.
 *
 * - security-relevant options (site URL, admin e-mail, open registration...)
 * - plugins and themes installed, removed, activated or deactivated
 * - wp-config.php, .htaccess/.user.ini/php.ini, non-core PHP files in the site
 *   root and in wp-content, drop-ins and must-use plugins (sha256 baseline)
 * - executable files (PHP...) in the uploads directory, except those accepted
 *   with `wp-secmon review` and unchanged since (see Review)
 */
final class IntegrityCheck extends Check
{
    /** In the site state: executable files found in uploads by the last check, and those accepted. */
    public const UPLOADS_FOUND = 'uploads-exec.json';
    public const UPLOADS_ACCEPTED = 'uploads-accepted.json';

    /** Root files covered by `wp core verify-checksums`. */
    private const CORE_ROOT_FILES = [
        'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php',
        'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
        'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
    ];

    private const DROPINS = [
        'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php',
        'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php',
        'blog-suspended.php',
    ];

    /** category => [severity when added, modified, removed] (see label()) */
    private const CATEGORIES = [
        'config' => ['warning', 'warning', 'warning'],
        'server-config' => ['warning', 'warning', 'info'],
        'root-php' => ['critical', 'warning', 'info'],
        'content-file' => ['critical', 'warning', 'info'],
        'dropin' => ['warning', 'warning', 'info'],
        'mu-plugin' => ['critical', 'warning', 'info'],
        'uploads-config' => ['warning', 'warning', 'info'],
    ];

    /** option => severity when it changes (see changed()) */
    private const OPTIONS = [
        'siteurl' => 'critical',
        'home' => 'critical',
        'admin_email' => 'warning',
        'users_can_register' => 'warning',
        'default_role' => 'warning',
        'registration' => 'warning',
        'stylesheet' => 'info',
        'template' => 'info',
    ];

    public static function name(): string
    {
        return 'integrity';
    }

    protected function checkSite(Site $site): void
    {
        $dir = $this->ctx->siteDir($site);
        $inv = $this->ctx->inventory($site);
        if ($inv !== null) {
            $this->options($inv['options'] ?? [], $dir);
            $this->components($inv, $dir);
        }
        $this->files($site, $inv, $dir);
    }

    // ------------------------------------------------------------------

    private function options(array $options, string $dir): void
    {
        $alerts = $this->ctx->alerts;
        $old = Util::readJson("$dir/options.json");
        if ($old !== null) {
            foreach (self::diffOptions($old, $options) as [$sev, $title, $lines, $meta]) {
                $alerts->event($sev, $title, $lines, $meta);
            }
        }
        Util::writeJson("$dir/options.json", $options);

        $risk = self::registrationRisk($options, $this->ctx->cfg->list('risky_default_roles'));
        if ($risk !== null) {
            $alerts->alert('critical', 'risky-registration', $risk,
                '    ' . I18n::t('Open registration handing out a powerful role is a common way to keep access to a hacked site. See Settings > General.'),
                null, null, ['role' => (string) ($options['default_role'] ?? '')]);
        } else {
            $alerts->resolve('risky-registration');
        }
    }

    public static function diffOptions(array $old, array $new): array
    {
        $show = static function ($v): string {
            if ($v === null) {
                return I18n::t('(not set)');
            }
            if (is_string($v)) {
                return $v === '' ? I18n::t('(empty)') : Util::oneLine($v);
            }
            return Util::oneLine((string) json_encode($v));
        };
        $out = [];
        foreach (self::OPTIONS as $key => $sev) {
            if (array_key_exists($key, $old) && ($old[$key] ?? null) !== ($new[$key] ?? null)) {
                $out[] = [$sev, self::changed($key),
                    ['    ' . I18n::t('before: %s', $show($old[$key])), '    ' . I18n::t('after:  %s', $show($new[$key] ?? null))],
                    ['kind' => 'option', 'option' => $key, 'before' => $old[$key]]];
            }
        }
        return $out;
    }

    /** Title of a change to one of OPTIONS. */
    private static function changed(string $option): string
    {
        switch ($option) {
            case 'siteurl':
                return I18n::t('Site address (siteurl) changed');
            case 'home':
                return I18n::t('Home address (home) changed');
            case 'admin_email':
                return I18n::t('Administration e-mail address changed');
            case 'users_can_register':
                return I18n::t('"Anyone can register" setting changed');
            case 'default_role':
                return I18n::t('Default role for new accounts changed');
            case 'registration':
                return I18n::t('Network registration setting changed');
            case 'stylesheet':
                return I18n::t('Active theme changed');
            default:
                return I18n::t('Active parent theme changed');
        }
    }

    public static function registrationRisk(array $o, array $riskyRoles): ?string
    {
        $open = (string) ($o['users_can_register'] ?? '') === '1' || in_array($o['registration'] ?? null, ['user', 'all'], true);
        $role = (string) ($o['default_role'] ?? '');
        if ($open && in_array($role, $riskyRoles, true)) {
            return I18n::t("Anyone can register and new accounts get the '%s' role", $role);
        }
        return null;
    }

    // ------------------------------------------------------------------

    private function components(array $inv, string $dir): void
    {
        $now = ['plugins' => $inv['plugins'] ?? [], 'themes' => $inv['themes'] ?? []];
        $old = Util::readJson("$dir/components.json");
        if ($old !== null) {
            foreach (self::diffComponents($old, $now) as [$sev, $title, $lines, $meta]) {
                $this->ctx->alerts->event($sev, $title, $lines, $meta);
            }
        }
        Util::writeJson("$dir/components.json", $now);
    }

    public static function diffComponents(array $old, array $new): array
    {
        $label = static function (array $c): string {
            $name = (string) ($c['name'] ?? '') !== '' ? $c['name'] : I18n::t('(no name)');
            return Util::oneLine(sprintf('%s [%s] %s', $name, $c['slug'] ?? '?', $c['version'] ?? ''));
        };
        $out = [];
        $section = static function (string $sev, string $change, string $title, array $lines) use (&$out): void {
            if ($lines) {
                $out[] = [$sev, $title, Util::listBlock('', $lines, 50), ['kind' => 'components', 'change' => $change]];
            }
        };

        $op = array_column($old['plugins'] ?? [], null, 'file');
        $np = array_column($new['plugins'] ?? [], null, 'file');
        $added = $activated = $deactivated = $removed = $updated = [];
        foreach ($np as $file => $p) {
            if (!isset($op[$file])) {
                $added[] = !empty($p['active']) ? I18n::t('%s (active)', $label($p)) : $label($p);
                continue;
            }
            $was = $op[$file];
            if (!empty($p['active']) && empty($was['active'])) {
                $activated[] = $label($p);
            } elseif (empty($p['active']) && !empty($was['active'])) {
                $deactivated[] = $label($p);
            }
            if (($p['version'] ?? '') !== ($was['version'] ?? '')) {
                $updated[] = Util::oneLine(sprintf('%s: %s -> %s', $p['slug'] ?? $file, $was['version'] ?? '', $p['version'] ?? ''));
            }
        }
        foreach ($op as $file => $p) {
            if (!isset($np[$file])) {
                $removed[] = $label($p);
            }
        }
        $section('warning', 'plugins-installed', I18n::n(count($added), '%d plugin(s) installed', '%d plugin(s) installed', count($added)), $added);
        $section('warning', 'plugins-activated', I18n::n(count($activated), '%d plugin(s) activated', '%d plugin(s) activated', count($activated)), $activated);
        $section('warning', 'plugins-deactivated', I18n::n(count($deactivated), '%d plugin(s) deactivated', '%d plugin(s) deactivated', count($deactivated)), $deactivated);
        $section('info', 'plugins-removed', I18n::n(count($removed), '%d plugin(s) removed', '%d plugin(s) removed', count($removed)), $removed);
        $section('info', 'plugins-updated', I18n::n(count($updated), '%d plugin(s) changed version', '%d plugin(s) changed version', count($updated)), $updated);

        $ot = array_column($old['themes'] ?? [], null, 'slug');
        $nt = array_column($new['themes'] ?? [], null, 'slug');
        $added = $removed = $updated = [];
        foreach ($nt as $slug => $t) {
            if (!isset($ot[$slug])) {
                $added[] = $label($t);
            } elseif (($t['version'] ?? '') !== ($ot[$slug]['version'] ?? '')) {
                $updated[] = Util::oneLine(sprintf('%s: %s -> %s', $slug, $ot[$slug]['version'] ?? '', $t['version'] ?? ''));
            }
        }
        foreach ($ot as $slug => $t) {
            if (!isset($nt[$slug])) {
                $removed[] = $label($t);
            }
        }
        $section('warning', 'themes-installed', I18n::n(count($added), '%d theme(s) installed', '%d theme(s) installed', count($added)), $added);
        $section('info', 'themes-removed', I18n::n(count($removed), '%d theme(s) removed', '%d theme(s) removed', count($removed)), $removed);
        $section('info', 'themes-updated', I18n::n(count($updated), '%d theme(s) changed version', '%d theme(s) changed version', count($updated)), $updated);
        return $out;
    }

    // ------------------------------------------------------------------

    private function files(Site $site, ?array $inv, string $dir): void
    {
        $alerts = $this->ctx->alerts;
        $paths = $inv['paths'] ?? [];
        $content = $this->sitePath($site, $paths['content_dir'] ?? null, $site->root . '/wp-content');
        // The read-only guard hides WPMU_PLUGIN_DIR from WordPress; use the standard location.
        $mu = $content . '/mu-plugins';
        $uploads = $this->sitePath($site, $paths['uploads_dir'] ?? null, $content . '/uploads');

        $r = $this->ctx->scanFiles($site, [
            'root' => $site->root, 'content' => $content, 'mu' => $mu, 'uploads' => $uploads, 'config' => $site->config,
        ]);
        $scan = $r->json();
        if ($scan === null) {
            $alerts->siteError('files', I18n::t('file scan failed: %s', $r->reason()), $r->details());
            return;
        }
        $alerts->siteOk('files');
        foreach ($scan['errors'] ?? [] as $e) {
            Log::debug("{$site->root}: " . Util::oneLine((string) $e));
        }

        [$manifest, $found] = $this->classify($site, $scan['entries'] ?? []);

        $old = Util::readJson("$dir/files.json");
        if ($old === null) {
            Log::info(I18n::t('%s: file baseline recorded (%d files)', $site->root, count($manifest)));
        } else {
            foreach (self::diffFiles($old, $manifest) as [$sev, $title, $lines, $meta]) {
                $alerts->event($sev, $title, $lines, $meta);
            }
        }
        Util::writeJson("$dir/files.json", $manifest);

        // What `wp-secmon review` goes through.
        Util::writeJson("$dir/" . self::UPLOADS_FOUND, ['truncated' => !empty($scan['truncated']), 'files' => $found]);
        $exec = [];
        foreach (self::pendingUploads($found, Util::readJson("$dir/" . self::UPLOADS_ACCEPTED) ?? []) as $rel => $changed) {
            $f = $found[$rel];
            $line = strpos($f['hash'], 'symlink -> ') === 0 ? "$rel ({$f['hash']})"
                : I18n::n($f['size'], '%s (%d bytes)', '%s (%d bytes)', $rel, $f['size']);
            $exec[] = $changed ? I18n::t('%s, changed since it was accepted', $line) : $line;
        }

        if ($exec) {
            $lines = Util::listBlock('', $exec, 50);
            if (!empty($scan['truncated'])) {
                $lines[] = '    ' . I18n::t('(scan stopped after 2000 matches)');
            }
            $lines[] = '    ' . I18n::t('Once checked, accept the harmless ones with: wp-secmon review --site %s', $site->root);
            $alerts->alert('critical', 'uploads-exec',
                I18n::n(count($exec), '%d executable file(s) in the uploads directory (%s)', '%d executable file(s) in the uploads directory (%s)',
                    count($exec), $this->rel($site, $uploads)), $lines,
                null, null, ['count' => count($exec)]);
        } else {
            $alerts->resolve('uploads-exec');
        }
    }

    /** Only trust paths reported by the site when they stay inside its directory tree. */
    private function sitePath(Site $site, $candidate, string $default): string
    {
        $base = dirname($site->root);
        if (is_string($candidate) && $candidate !== '' && $candidate[0] === '/'
            && strpos($candidate . '/', $base . '/') === 0 && strpos($candidate, '/../') === false
            && !preg_match('/[\x00-\x1F]/', $candidate)) {
            return rtrim($candidate, '/');
        }
        return $default;
    }

    private function rel(Site $site, string $path): string
    {
        if (strpos($path, $site->root . '/') === 0) {
            return substr($path, strlen($site->root) + 1);
        }
        $parent = dirname($site->root);
        return strpos($path, $parent . '/') === 0 ? '../' . substr($path, strlen($parent) + 1) : $path;
    }

    /**
     * @return array{0: array<string, array{0: string, 1: string}>, 1: array<string, array{path: string, hash: string, size: int}>}
     *         [manifest rel => [category, hash], executables in uploads rel => file]
     */
    private function classify(Site $site, array $entries): array
    {
        $manifest = [];
        $exec = [];
        foreach ($entries as $e) {
            $path = (string) ($e['path'] ?? '');
            $rel = $this->rel($site, $path);
            $base = basename($path);
            $hash = self::fileHash($e);
            switch ($e['area'] ?? '') {
                case 'config':
                    $cat = 'config';
                    break;
                case 'root':
                    if ($base === 'wp-config.php') {
                        $cat = 'config';
                    } elseif (in_array($base, self::CORE_ROOT_FILES, true)) {
                        continue 2;
                    } else {
                        $cat = in_array($base, ['.htaccess', '.user.ini', 'php.ini'], true) ? 'server-config' : 'root-php';
                    }
                    break;
                case 'content':
                    $cat = in_array($base, self::DROPINS, true) ? 'dropin' : 'content-file';
                    break;
                case 'mu':
                    $cat = 'mu-plugin';
                    break;
                case 'uploads':
                    if (in_array($base, ['.htaccess', '.user.ini'], true)) {
                        $cat = 'uploads-config';
                        break;
                    }
                    if (empty($e['benign'])) {
                        $exec[$rel] = ['path' => $path, 'hash' => $hash, 'size' => (int) ($e['size'] ?? 0)];
                    }
                    continue 2;
                default:
                    continue 2;
            }
            $manifest[$rel] = [$cat, $hash];
        }
        ksort($manifest);
        ksort($exec);
        return [$manifest, $exec];
    }

    /** What a file is compared by: its sha256, or the target of a symbolic link (FileScanner entry or read). */
    public static function fileHash(array $e): string
    {
        $link = $e['link'] ?? null;
        return $link !== null ? 'symlink -> ' . Util::oneLine((string) $link) : (string) ($e['sha256'] ?? '');
    }

    /**
     * Executable files in uploads to report: not accepted with `wp-secmon review`, or changed since.
     * @param array<string, array{hash: string}> $found rel => file (see classify)
     * @param array<string, array{hash: string}> $accepted rel => acceptance (see Review)
     * @return array<string, bool> rel => whether it changed since it was accepted
     */
    public static function pendingUploads(array $found, array $accepted): array
    {
        $out = [];
        foreach ($found as $rel => $f) {
            $was = $accepted[$rel]['hash'] ?? null;
            if ($was !== $f['hash']) {
                $out[$rel] = $was !== null;
            }
        }
        return $out;
    }

    public static function diffFiles(array $old, array $new): array
    {
        $changes = [];
        foreach ($new as $rel => [$cat, $hash]) {
            if (!isset($old[$rel])) {
                $changes[$cat][] = ['added', $rel];
            } elseif ($old[$rel][1] !== $hash) {
                $changes[$cat][] = ['modified', $rel];
            }
        }
        foreach ($old as $rel => [$cat]) {
            if (!isset($new[$rel])) {
                $changes[$cat][] = ['removed', $rel];
            }
        }
        $rank = ['info' => 1, 'warning' => 2, 'critical' => 3];
        $out = [];
        foreach (self::CATEGORIES as $cat => [$onAdd, $onMod, $onDel]) {
            if (empty($changes[$cat])) {
                continue;
            }
            $sev = 'info';
            $counts = ['added' => 0, 'modified' => 0, 'removed' => 0];
            $lines = [];
            foreach ($changes[$cat] as [$what, $rel]) {
                $counts[$what]++;
                $s = $what === 'added' ? $onAdd : ($what === 'modified' ? $onMod : $onDel);
                if ($s === 'critical' && $what === 'added' && !preg_match('/\.(php\d?|phtml|pht|phar|inc)$/i', $rel)) {
                    $s = 'warning';
                }
                if ($rank[$s] > $rank[$sev]) {
                    $sev = $s;
                }
                $lines[] = self::change($what, 0, $rel);
            }
            $summary = [];
            foreach (array_filter($counts) as $what => $n) {
                $summary[] = self::change($what, $n);
            }
            $out[] = [$sev, I18n::t('%s: %s', self::label($cat), implode(', ', $summary)), Util::listBlock('', $lines, 40),
                ['kind' => 'files', 'category' => $cat]];
        }
        return $out;
    }

    /** One of CATEGORIES, as shown in reports. */
    private static function label(string $category): string
    {
        switch ($category) {
            case 'config':
                return 'wp-config.php';
            case 'server-config':
                return I18n::t('Server configuration in the site root (.htaccess, .user.ini, php.ini)');
            case 'root-php':
                return I18n::t('Non-core PHP files in the site root');
            case 'content-file':
                return I18n::t('PHP or configuration files directly in wp-content');
            case 'dropin':
                return I18n::t('Drop-ins (wp-content/*.php overriding core behaviour)');
            case 'mu-plugin':
                return I18n::t('Must-use plugins (loaded on every request, cannot be disabled)');
            default:
                return I18n::t('.htaccess or .user.ini files inside uploads');
        }
    }

    /** "3 added", or with $file: "added: $file". */
    private static function change(string $what, int $n, string $file = ''): string
    {
        switch ($what) {
            case 'added':
                return $file !== '' ? I18n::t('added: %s', $file) : I18n::n($n, '%d added', '%d added', $n);
            case 'modified':
                return $file !== '' ? I18n::t('modified: %s', $file) : I18n::n($n, '%d modified', '%d modified', $n);
            default:
                return $file !== '' ? I18n::t('removed: %s', $file) : I18n::n($n, '%d removed', '%d removed', $n);
        }
    }
}
