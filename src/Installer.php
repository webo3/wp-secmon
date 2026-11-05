<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * `wp-secmon install` / `wp-secmon uninstall`, run from the phar:
 *
 *   php wp-secmon.phar install [--php=/path/to/php] [--no-enable]
 *   wp-secmon uninstall [--purge]
 *
 * Installing copies the phar to /usr/local/bin/wp-secmon, creates the
 * configuration (existing files are kept), installs the hourly systemd timer
 * that starts the checks when they are due (see Schedule) and downloads WP-CLI
 * when wp_cli points to nothing. Running it again with a newer phar upgrades
 * in place (see also Updater).
 */
final class Installer
{
    /** In bin, not sbin: site owners run it too, for the file scan and to check their own sites. */
    public const BIN = '/usr/local/bin/wp-secmon';
    /** Where older versions installed it. An upgrade leaves a symbolic link to BIN there. */
    public const OLD_BIN = '/usr/local/sbin/wp-secmon';
    public const CONF_DIR = '/etc/wp-secmon';
    private const UNIT_DIR = '/etc/systemd/system';
    /** wp-secmon-<check>.timer: one timer per check in older versions, replaced by wp-secmon.timer. */
    private const OLD_TIMERS = ['discover', 'users', 'integrity', 'checksums', 'vulns'];
    private const WP_CLI_URL = 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar';

    private static function say(string $msg): void
    {
        fwrite(STDOUT, $msg . "\n");
    }

    private static function requireRoot(): void
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            throw new \RuntimeException(I18n::t('wp-secmon runs on Linux servers'));
        }
        if (Util::effectiveUid() !== 0) {
            throw new \RuntimeException(I18n::t('run the installer as root'));
        }
    }

    private static function systemd(): ?string
    {
        $bin = Util::which('systemctl');
        return $bin !== null && is_dir('/run/systemd/system') ? $bin : null;
    }

    private static function run(array $cmd): void
    {
        [$code, , $err] = Proc::capture($cmd, 120);
        if ($code !== 0) {
            throw new \RuntimeException(I18n::t('%s failed: %s', implode(' ', $cmd), Util::oneLine($err)));
        }
    }

    /**
     * Atomically writes a root-owned executable. Site owners run it, so
     * nobody else may be able to write to it.
     */
    private static function putExecutable(string $target, string $content): void
    {
        $tmp = $target . '.new' . getmypid();
        if (@file_put_contents($tmp, $content) !== strlen($content)) {
            @unlink($tmp);
            throw new \RuntimeException(I18n::t('cannot write %s', $target));
        }
        chown($tmp, 0);
        chgrp($tmp, 0);
        chmod($tmp, 0755);
        rename($tmp, $target);
    }

    /** The PHP binary the installed timers run, or null. */
    public static function timersPhp(): ?string
    {
        $unit = @file_get_contents(self::UNIT_DIR . '/wp-secmon@.service');
        return $unit !== false && preg_match('/^ExecStart=(\S+)/m', $unit, $m) ? $m[1] : null;
    }

    /**
     * systemctl, when the checks can run as units of wp-secmon@.service: as
     * root, with systemd running and the units installed.
     */
    public static function checkUnits(): ?string
    {
        return Util::effectiveUid() === 0 && is_file(self::UNIT_DIR . '/wp-secmon@.service') ? self::systemd() : null;
    }

    public static function install(string $php, bool $enable, Config $cfg): int
    {
        self::requireRoot();
        $phar = class_exists('Phar') ? \Phar::running(false) : '';
        if ($phar === '') {
            throw new \RuntimeException(I18n::t('install from the phar: php -d phar.readonly=0 build.php && php dist/wp-secmon.phar install'));
        }

        // The PHP binary the timers will use.
        $php = $php !== '' ? $php : PHP_BINARY;
        if (!is_file($php) || !is_executable($php)) {
            throw new \RuntimeException(I18n::t('PHP binary not found: %s', $php));
        }
        $real = (string) realpath($php);
        $problem = Util::rootOnlyProblem($real) ?? Util::rootOnlyProblem(dirname($real));
        if ($problem !== null) {
            throw new \RuntimeException(I18n::t('%s: the timers run it as root (choose another with --php=)', $problem));
        }
        $probe = 'echo PHP_VERSION_ID, " ", (int) function_exists("json_encode"), " ", (int) extension_loaded("phar"), " ",'
            . ' (int) (function_exists("curl_init") || extension_loaded("openssl")), " ", (int) function_exists("posix_getpwnam");';
        [$code, $out] = Proc::capture([$php, '-d', 'disable_functions=', '-r', $probe], 30);
        [$version, $json, $pharExt, $https, $posix] = array_map('intval', explode(' ', trim($out)) + [0, 0, 0, 0, 0]);
        if ($code !== 0 || $version < 70400) {
            throw new \RuntimeException(I18n::t('%s is not PHP 7.4 or later (choose another with --php=)', $php));
        }
        foreach (['json' => $json, 'phar' => $pharExt, 'curl or openssl' => $https] as $ext => $ok) {
            if (!$ok) {
                throw new \RuntimeException(I18n::t('%s has no %s extension', $php, $ext));
            }
        }
        if (!$posix) {
            self::say(I18n::t('note: %s has no posix extension (php-process / php-posix); getent is used instead.', $php));
        }

        self::say(I18n::t('Installing wp-secmon %s (PHP: %s)', VERSION, $php));

        // The program: a root-owned copy of this phar, executed by site owners for the file scan.
        $upgrade = is_file(self::BIN) || is_file(self::OLD_BIN);
        if (realpath($phar) !== realpath(self::BIN)) {
            self::putExecutable(self::BIN, (string) file_get_contents($phar));
        }
        if (is_file(self::OLD_BIN) && !is_link(self::OLD_BIN)) {
            // Scripts that use the old path keep working, and so does an update started from there.
            $tmp = self::OLD_BIN . '.new' . getmypid();
            @unlink($tmp);
            symlink(self::BIN, $tmp);
            rename($tmp, self::OLD_BIN);
            self::say('  ' . I18n::t('program: %s (moved from %s, which now links to it)', self::BIN, self::OLD_BIN));
        } else {
            self::say('  ' . I18n::t('program: %s', self::BIN));
        }

        Util::mkdir(self::CONF_DIR, 0700);
        foreach (['wp-secmon.ini', 'site-users.map'] as $file) {
            $target = self::CONF_DIR . "/$file";
            $content = (string) file_get_contents(Util::resource("etc/$file"));
            if (is_file($target)) {
                file_put_contents("$target.dist", $content);
                chmod("$target.dist", 0600);
                self::say('  ' . I18n::t('kept %s (current defaults in %s)', $target, "$target.dist"));
            } else {
                file_put_contents($target, $content);
                chmod($target, 0600);
                self::say('  ' . I18n::t('created %s', $target));
            }
        }
        Util::mkdir('/var/lib/wp-secmon', 0700);
        Util::mkdir('/var/log/wp-secmon', 0750);
        if (is_dir('/etc/logrotate.d')) {
            file_put_contents('/etc/logrotate.d/wp-secmon', (string) file_get_contents(Util::resource('etc/logrotate.conf')));
            chmod('/etc/logrotate.d/wp-secmon', 0644);
        }

        // WP-CLI, when wp_cli points to nothing: the official phar, checked against its published sha512.
        $wp = $cfg->str('wp_cli');
        if (file_exists($wp) || is_link($wp)) {
            self::say('  ' . I18n::t('WP-CLI: %s', $wp));
        } else {
            try {
                self::putExecutable($wp, Http::getVerified(self::WP_CLI_URL, self::WP_CLI_URL . '.sha512', 'sha512', $cfg->str('http_proxy')));
                self::say('  ' . I18n::t('WP-CLI: %s (downloaded)', $wp));
            } catch (\Exception $e) {
                self::say('  ' . I18n::t('note: WP-CLI not installed (%s); install it at %s or set wp_cli in %s',
                    $e->getMessage(), $wp, self::CONF_DIR . '/wp-secmon.ini'));
            }
        }

        $systemctl = self::systemd();
        if ($systemctl === null) {
            self::say('  ' . I18n::t('note: systemd not detected; run "%s schedule" every hour with cron instead', self::BIN));
        } else {
            $new = !is_file(self::UNIT_DIR . '/wp-secmon.timer');
            foreach (['wp-secmon@.service', 'wp-secmon.service', 'wp-secmon.timer'] as $unit) {
                $text = strtr((string) file_get_contents(Util::resource("systemd/$unit")), ['@PHP@' => $php, '@BIN@' => self::BIN]);
                file_put_contents(self::UNIT_DIR . "/$unit", $text);
                chmod(self::UNIT_DIR . "/$unit", 0644);
            }
            // Older versions had a timer per check. wp-secmon.timer now starts them as set by "timer" in wp-secmon.ini.
            $old = self::removeOldTimers($systemctl);
            self::run([$systemctl, 'daemon-reload']);
            if ($old) {
                self::say('  ' . I18n::t('replaced %s with wp-secmon.timer, which starts the checks as set by timer in %s',
                    count($old) > 1 ? 'wp-secmon-{' . implode(',', $old) . '}.timer' : "wp-secmon-{$old[0]}.timer", self::CONF_DIR . '/wp-secmon.ini'));
            }
            // Only a new timer is enabled: an upgrade leaves it enabled or disabled as it was.
            if ($new && $enable) {
                self::run([$systemctl, 'enable', '--now', 'wp-secmon.timer']);
                self::say('  ' . I18n::t('timer enabled: %s', 'wp-secmon.timer'));
            } elseif ($new) {
                self::say('  ' . I18n::t('timer installed, not enabled: %s', 'wp-secmon.timer'));
            } else {
                self::say('  ' . I18n::t('timer updated, still enabled or disabled as before: %s', 'wp-secmon.timer'));
            }
        }

        if ($upgrade) {
            return 0;
        }
        self::say("\n" . I18n::t('Next steps:'));
        self::say('  1. ' . I18n::t('Review %s (scan_paths, alert_email, language...)', self::CONF_DIR . '/wp-secmon.ini'));
        self::say('  2. wp-secmon doctor');
        self::say('  3. wp-secmon sites');
        self::say('  4. wp-secmon all --no-mail     ' . I18n::t('(records the baselines and prints the first report)'));
        return 0;
    }

    /** Disables and deletes the timers of older versions. @return string[] the checks whose timer was there */
    private static function removeOldTimers(string $systemctl): array
    {
        $old = [];
        foreach (self::OLD_TIMERS as $t) {
            if (is_file(self::UNIT_DIR . "/wp-secmon-$t.timer")) {
                Proc::capture([$systemctl, 'disable', '--now', "wp-secmon-$t.timer"], 60);
                @unlink(self::UNIT_DIR . "/wp-secmon-$t.timer");
                $old[] = $t;
            }
        }
        return $old;
    }

    public static function uninstall(Config $cfg, bool $purge): int
    {
        self::requireRoot();
        $systemctl = self::systemd();
        if ($systemctl !== null) {
            Proc::capture([$systemctl, 'disable', '--now', 'wp-secmon.timer'], 60);
            self::removeOldTimers($systemctl);
            foreach (['wp-secmon.timer', 'wp-secmon.service', 'wp-secmon@.service'] as $unit) {
                @unlink(self::UNIT_DIR . "/$unit");
            }
            Proc::capture([$systemctl, 'daemon-reload'], 60);
        }
        @unlink('/etc/logrotate.d/wp-secmon');
        @unlink(self::BIN);
        @unlink(self::OLD_BIN);

        if (!$purge) {
            self::say(I18n::t('wp-secmon removed. Kept %s, %s and %s (--purge deletes them).', self::CONF_DIR, $cfg->str('state_dir'), $cfg->str('log_dir')));
            return 0;
        }
        foreach ([self::CONF_DIR, $cfg->str('state_dir'), $cfg->str('log_dir')] as $dir) {
            // Only ever delete directories that are clearly ours.
            if (strpos(basename($dir), 'wp-secmon') !== false) {
                Util::rmTree($dir);
            } else {
                self::say('  ' . I18n::t('left %s in place (not a wp-secmon directory name)', $dir));
            }
        }
        self::say(I18n::t('wp-secmon removed, including configuration, state and logs.'));
        return 0;
    }
}
