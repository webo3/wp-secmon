<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * `wp-secmon update [--check]`: installs the latest release when it is newer.
 *
 * update_url describes the latest release, in the GitHub API format. Its phar
 * is checked against the published sha256, then its own installer runs
 * (`wp-secmon.phar install`), exactly as for a manual upgrade.
 */
final class Updater
{
    /**
     * The latest release in a GitHub API response, or null.
     * @return array{version: string, phar: string, sha256: string}|null
     */
    public static function parseRelease(string $json): ?array
    {
        $release = json_decode($json, true);
        if (!is_array($release) || !preg_match('/^v(\d+\.\d+\.\d+)$/', (string) ($release['tag_name'] ?? ''), $m)) {
            return null;
        }
        $urls = [];
        foreach ((array) ($release['assets'] ?? []) as $asset) {
            $url = is_array($asset) ? (string) ($asset['browser_download_url'] ?? '') : '';
            if (preg_match('#^https?://#', $url) && in_array($asset['name'] ?? null, ['wp-secmon.phar', 'wp-secmon.phar.sha256'], true)) {
                $urls[$asset['name']] = $url;
            }
        }
        if (count($urls) !== 2) {
            return null;
        }
        return ['version' => $m[1], 'phar' => $urls['wp-secmon.phar'], 'sha256' => $urls['wp-secmon.phar.sha256']];
    }

    /** @return array{version: string, phar: string, sha256: string}|null */
    public static function latest(Config $cfg): ?array
    {
        $json = Http::get($cfg->str('update_url'), 20, $cfg->str('http_proxy'));
        return $json !== null ? self::parseRelease($json) : null;
    }

    public static function check(Config $cfg): int
    {
        $latest = self::latest($cfg);
        if ($latest === null) {
            throw new \RuntimeException(I18n::t('cannot read the latest release from %s', $cfg->str('update_url')));
        }
        fwrite(STDOUT, (version_compare($latest['version'], VERSION, '>')
            ? I18n::t('wp-secmon %s is available (this is %s): run wp-secmon update', $latest['version'], VERSION)
            : I18n::t('wp-secmon %s is up to date', VERSION)) . "\n");
        return 0;
    }

    public static function update(Config $cfg, ?string $configFile): int
    {
        if (Util::effectiveUid() !== 0) {
            throw new \RuntimeException(I18n::t('run the update as root'));
        }
        if (!is_file(Installer::BIN)) {
            throw new \RuntimeException(I18n::t('wp-secmon is not installed: download wp-secmon.phar and run php wp-secmon.phar install'));
        }
        $latest = self::latest($cfg);
        if ($latest === null) {
            throw new \RuntimeException(I18n::t('cannot read the latest release from %s', $cfg->str('update_url')));
        }
        if (version_compare($latest['version'], VERSION, '<=')) {
            fwrite(STDOUT, I18n::t('wp-secmon %s is up to date', VERSION) . "\n");
            return 0;
        }
        $phar = Http::getVerified($latest['phar'], $latest['sha256'], 'sha256', $cfg->str('http_proxy'));

        // The new installer runs with the timers' PHP and keeps it for them.
        $php = Installer::timersPhp() ?? PHP_BINARY;
        $cmd = [$php, '-d', 'disable_functions=', '-d', 'open_basedir='];
        $dir = sys_get_temp_dir() . '/wp-secmon.' . bin2hex(random_bytes(6));
        Util::mkdir($dir);
        try {
            file_put_contents("$dir/wp-secmon.phar", $phar);
            $cmd = array_merge($cmd, ["$dir/wp-secmon.phar", 'install', "--php=$php", '--lang=' . I18n::language()],
                $configFile !== null ? ["--config=$configFile"] : []);
            // The installer replaces this phar. PHP would read any class loaded
            // after that from the new file, at the old offsets: load them now.
            class_exists(Log::class);
            [$code, $out, $err] = Proc::capture($cmd, 600);
        } finally {
            Util::rmTree($dir);
        }
        fwrite(STDOUT, $out);
        fwrite(STDERR, $err);
        if ($code !== 0) {
            throw new \RuntimeException(I18n::t('the installer of wp-secmon %s failed', $latest['version']));
        }
        fwrite(STDOUT, "\n" . I18n::t('wp-secmon updated from %s to %s.', VERSION, $latest['version']) . "\n");
        return 0;
    }
}
