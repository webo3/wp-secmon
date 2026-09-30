<?php

declare(strict_types=1);

namespace WpSecMon;

use WpSecMon\Check\ChecksumsCheck;
use WpSecMon\Check\IntegrityCheck;
use WpSecMon\Check\UsersCheck;
use WpSecMon\Check\VulnsCheck;

final class Cli
{
    private const CHECKS = [
        'users' => UsersCheck::class,
        'integrity' => IntegrityCheck::class,
        'checksums' => ChecksumsCheck::class,
        'vulns' => VulnsCheck::class,
    ];

    private ?string $configFile = null;
    private array $only = [];
    private bool $noMail = false;
    private bool $print;
    private ?string $lang = null;
    private Config $cfg;
    private string $tmp = '';
    private string $php = '';
    private bool $enable = true;
    private bool $purge = false;
    private bool $checkOnly = false;
    private bool $withAccepted = false;

    private static function usage(): string
    {
        return I18n::t(<<<'TXT'
Usage: wp-secmon [options] <command>

Read-only security monitoring for the WordPress sites of this server.
Alerts are e-mailed to root (see alert_email in /etc/wp-secmon/wp-secmon.ini).

Commands:
  discover    Find WordPress installs and refresh the site list
  users       Accounts created or deleted, privilege and e-mail changes
  integrity   Options, plugins/themes, wp-config.php, .htaccess, mu-plugins,
              drop-ins, non-core PHP files and executables in uploads
  checksums   Core and wordpress.org plugin files against official checksums
  vulns       Known vulnerabilities, closed plugins, outdated core
  all         discover + users + integrity + checksums + vulns
  sites       List the discovered sites and the account each one is checked
              as (runs discovery first when there is no site list yet)
  status      Show open (unresolved) alerts
  review      Go through the executable files found in uploads and accept
              the harmless ones: an accepted file is no longer reported,
              until its content changes (use --site for some sites only)
                --accepted   Also go through the files accepted before
  reset       Forget open alerts and cached vulnerability data, so the next
              run reports every problem again (baselines are kept; use
              --site to reset only some sites)
  doctor      Check requirements and configuration

  install     Install this phar as /usr/local/sbin/wp-secmon, with its
              configuration, systemd timers and WP-CLI if missing
              (upgrades in place)
                --php=PATH   PHP binary for the timers (default: this one)
                --no-enable  Install the timers without enabling them
  update      Install the latest release of wp-secmon if it is newer
                --check      Only tell whether a newer release exists
  uninstall   Remove the program and timers
                --purge      Also delete configuration, state and logs

Options:
  -c, --config FILE   Configuration file (default /etc/wp-secmon/wp-secmon.ini)
  -s, --site PATH     Only check this WordPress root (repeatable). discover
                      and all then examine only this site again instead of
                      searching the server: wp-secmon all --site PATH rescans it
  -n, --no-mail       Do not send e-mail
  -p, --print         Print the summary on stdout (default on a terminal)
      --lang CODE     Language: en or fr (default: language in wp-secmon.ini)
  -v, --verbose       Debug output
  -q, --quiet         Only warnings and errors
  -V, --version       Show the version
  -h, --help          Show this help

TXT);
    }

    public static function main(array $argv): int
    {
        // Internal: file scan run as a site owner (see Context::scanFiles). No configuration.
        if (($argv[1] ?? '') === '__scan-files') {
            $in = json_decode((string) ($argv[2] ?? ''), true);
            if (!is_array($in) || empty($in['root'])) {
                fwrite(STDERR, "usage: wp-secmon __scan-files '<json>'\n");
                return 2;
            }
            fwrite(STDOUT, json_encode(FileScanner::scan($in), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
            return 0;
        }
        // Internal: one file read as a site owner for `wp-secmon review` (see Context::readFile).
        if (($argv[1] ?? '') === '__read-file') {
            fwrite(STDOUT, json_encode(FileScanner::read((string) ($argv[2] ?? ''), max(1, (int) ($argv[3] ?? 65536))),
                JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
            return 0;
        }

        $cli = new self();
        try {
            return $cli->dispatch(array_slice($argv, 1));
        } catch (\Throwable $e) {
            Log::error($e->getMessage() . (Log::$verbosity > 0 ? ' at ' . $e->getFile() . ':' . $e->getLine() : ''));
            return 1;
        } finally {
            if ($cli->tmp !== '') {
                Util::rmTree($cli->tmp);
            }
        }
    }

    private function dispatch(array $args): int
    {
        $this->print = function_exists('posix_isatty') && posix_isatty(STDOUT);
        $command = null;
        for ($i = 0; $i < count($args); $i++) {
            $a = $args[$i];
            $value = static function () use ($args, &$i, $a): string {
                if (strpos($a, '=') !== false) {
                    return substr($a, strpos($a, '=') + 1);
                }
                if (!isset($args[$i + 1])) {
                    throw new \InvalidArgumentException(I18n::t('option %s needs a value', $a));
                }
                return $args[++$i];
            };
            if ($a === '-h' || $a === '--help') {
                fwrite(STDOUT, self::usage());
                return 0;
            } elseif ($a === '-V' || $a === '--version') {
                fwrite(STDOUT, 'wp-secmon ' . VERSION . "\n");
                return 0;
            } elseif ($a === '-c' || strncmp($a, '--config', 8) === 0) {
                $this->configFile = $value();
            } elseif ($a === '-s' || strncmp($a, '--site', 6) === 0) {
                $this->only[] = $value();
            } elseif ($a === '-n' || $a === '--no-mail') {
                $this->noMail = true;
            } elseif ($a === '-p' || $a === '--print') {
                $this->print = true;
            } elseif ($a === '-v' || $a === '--verbose') {
                Log::$verbosity = 1;
            } elseif ($a === '-q' || $a === '--quiet') {
                Log::$verbosity = -1;
            } elseif (strncmp($a, '--lang', 6) === 0) {
                $this->lang = $value();
                I18n::setLanguage($this->lang);
            } elseif (strncmp($a, '--php', 5) === 0) {
                $this->php = $value();
            } elseif ($a === '--no-enable') {
                $this->enable = false;
            } elseif ($a === '--purge') {
                $this->purge = true;
            } elseif ($a === '--check') {
                $this->checkOnly = true;
            } elseif ($a === '--accepted') {
                $this->withAccepted = true;
            } elseif ($a !== '' && $a[0] === '-') {
                throw new \InvalidArgumentException(I18n::t('unknown option %s (see --help)', $a));
            } elseif ($command === null) {
                $command = $a;
            } else {
                throw new \InvalidArgumentException(I18n::t('unexpected argument %s', $a));
            }
        }
        if ($command === null) {
            fwrite(STDERR, self::usage());
            return 2;
        }

        if ($command !== 'doctor' && !function_exists('proc_open')) {
            throw new \RuntimeException(I18n::t('proc_open is disabled in php.ini; run: %s', PHP_BINARY
                . ' -d disable_functions= ' . Util::entry() . ' ' . implode(' ', $args)));
        }
        if ($command === 'install') {
            return $this->install();
        }

        $this->cfg = Config::load($this->configFile);
        I18n::setLanguage($this->lang ?? $this->cfg->str('language'));
        switch ($command) {
            case 'uninstall':
                return Installer::uninstall($this->cfg, $this->purge);
            case 'discover':
            case 'all':
            case 'users':
            case 'integrity':
            case 'checksums':
            case 'vulns':
                return $this->runChecks($command);
            case 'sites':
                return $this->sites();
            case 'status':
                return $this->status();
            case 'review':
                return $this->review();
            case 'reset':
                return $this->reset();
            case 'doctor':
                return (new Doctor($this->cfg))->run($this->only);
            case 'update':
                return $this->checkOnly ? Updater::check($this->cfg) : Updater::update($this->cfg, $this->configFile);
            default:
                throw new \InvalidArgumentException(I18n::t("unknown command '%s' (see --help)", $command));
        }
    }

    private function init(): void
    {
        if (Util::effectiveUid() !== 0) {
            Log::warning(I18n::t('not running as root: only sites owned by the current user can be checked'));
        }
        umask(077);
        Util::mkdir($this->cfg->str('state_dir'));
        Util::mkdir($this->cfg->str('state_dir') . '/locks');
        Util::mkdir($this->cfg->str('log_dir'), 0750);
        $this->tmp = sys_get_temp_dir() . '/wp-secmon.' . bin2hex(random_bytes(6));
        Util::mkdir($this->tmp);
    }

    /** Non-blocking lock per check; the descriptor is close-on-exec so site processes never inherit it. */
    private function lock(string $name)
    {
        $fh = fopen($this->cfg->str('state_dir') . "/locks/$name.lock", 'ce');
        if ($fh === false || !flock($fh, LOCK_EX | LOCK_NB)) {
            return null;
        }
        return $fh;
    }

    /** Locks every check, so that none runs meanwhile. Fails when one is running. */
    private function lockAll(): array
    {
        $locks = [];
        try {
            foreach (array_merge(['discover'], array_keys(self::CHECKS)) as $name) {
                $lock = $this->lock($name);
                if ($lock === null) {
                    throw new \RuntimeException(I18n::t("a '%s' run is in progress; try again when it has finished", $name));
                }
                $locks[] = $lock;
            }
        } catch (\Throwable $e) {
            self::unlockAll($locks);
            throw $e;
        }
        return $locks;
    }

    private static function unlockAll(array $locks): void
    {
        foreach ($locks as $lock) {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function install(): int
    {
        // An upgrade uses the existing configuration (language, wp_cli, http_proxy), if it can be read.
        try {
            $this->cfg = Config::load($this->configFile);
        } catch (\Throwable $e) {
            Log::debug('configuration not used: ' . $e->getMessage());
            $this->cfg = Config::fromArray([]);
        }
        if ($this->lang === null) {
            I18n::setLanguage($this->cfg->str('language'));
        }
        // A check running from the old phar would fail once the file is replaced.
        $locks = Util::effectiveUid() === 0 && is_dir($this->cfg->str('state_dir') . '/locks') ? $this->lockAll() : [];
        try {
            return Installer::install($this->php, $this->enable, $this->cfg);
        } finally {
            self::unlockAll($locks);
        }
    }

    private function runChecks(string $command): int
    {
        $this->init();
        $alerts = new Alerts($this->cfg);
        $alerts->noMail = $this->noMail;
        $alerts->print = $this->print;
        $sites = new Sites($this->cfg, $alerts);

        $names = $command === 'all' ? array_merge(['discover'], array_keys(self::CHECKS)) : [$command];
        $ctx = null;
        $list = null;
        $status = 0;
        // Whatever was reported before an error is still sent: it is recorded as reported.
        try {
            foreach ($names as $name) {
                $lock = $this->lock($name);
                if ($lock === null) {
                    Log::warning(I18n::t("another '%s' run is in progress, skipped", $name));
                    $status = 75;
                    continue;
                }
                try {
                    if ($name === 'discover') {
                        $alerts->check = 'discover';
                        $alerts->checksRun[] = 'discover';
                        $sites->discover($this->only);
                        continue;
                    }
                    if ($ctx === null) {
                        if (!(new Doctor($this->cfg))->wpCliUsable()) {
                            throw new \RuntimeException(I18n::t('WP-CLI is not usable, see: wp-secmon doctor'));
                        }
                        $ctx = new Context($this->cfg, $alerts, $this->tmp);
                        Log::debug('switching users with: ' . $ctx->runAs->method());
                        $list = $sites->load($this->only);
                    }
                    $class = self::CHECKS[$name];
                    (new $class($ctx))->run($list);
                } finally {
                    flock($lock, LOCK_UN);
                    fclose($lock);
                }
            }
        } finally {
            $alerts->finish();
        }
        return $status;
    }

    private function sites(): int
    {
        $sites = new Sites($this->cfg, new Alerts($this->cfg));
        $reg = $sites->registry();
        if ($reg === null) {
            // Nothing discovered yet: discover now. The report is e-mailed as
            // usual, but not printed: the list below shows the same sites.
            Log::info(I18n::t('no site list yet: discovering the WordPress installs first'));
            $this->print = false;
            $status = $this->runChecks('discover');
            $reg = $sites->registry();
            if ($reg === null) {
                return $status !== 0 ? $status : 1;
            }
        }
        if (!$reg['sites'] && !$reg['skipped'] && !$reg['orphans']) {
            fwrite(STDOUT, I18n::t('No WordPress install found in %s.', implode(', ', $this->cfg->list('scan_paths'))) . "\n"
                . I18n::t("Add the directories that hold the sites to scan_paths in %s, then run 'wp-secmon discover'.", $this->cfg->file) . "\n");
            return 0;
        }
        $rows = [];
        foreach ($reg['sites'] as $s) {
            $rows[] = [$s['user'], $s['root']];
        }
        fwrite(STDOUT, I18n::t('Discovered %s: %d monitored, %d skipped, %d without wp-config.php',
            date('Y-m-d H:i', (int) $reg['generated']), count($reg['sites']), count($reg['skipped']), count($reg['orphans'])) . "\n\n");
        self::table([I18n::t('CHECKED AS'), I18n::t('WORDPRESS ROOT')], $rows);
        if ($reg['skipped']) {
            fwrite(STDOUT, "\n" . I18n::t('Not monitored:') . "\n");
            foreach ($reg['skipped'] as $s) {
                fwrite(STDOUT, "  {$s['root']}\n      {$s['reason']}\n");
            }
        }
        if ($reg['orphans']) {
            fwrite(STDOUT, "\n" . I18n::t('WordPress files without wp-config.php (old copies?):') . "\n");
            foreach ($reg['orphans'] as $root) {
                fwrite(STDOUT, "  $root\n");
            }
        }
        return 0;
    }

    private function status(): int
    {
        $open = Alerts::openAlerts($this->cfg->str('state_dir'));
        if (!$open) {
            fwrite(STDOUT, I18n::t('No open alerts.') . "\n");
            return 0;
        }
        $rows = [];
        foreach ($open as $a) {
            $root = (string) ($a['root'] ?? '');
            $rows[] = [Util::upper(Report::severityName((string) $a['severity'])), date('Y-m-d H:i', (int) $a['first']), (string) ($a['check'] ?? ''),
                $root === '(server)' ? I18n::t('(server)') : $root, (string) $a['title']];
        }
        self::table([I18n::t('SEVERITY'), I18n::t('SINCE'), I18n::t('CHECK'), I18n::t('SITE'), I18n::t('ALERT')], $rows);
        return 0;
    }

    /** Go through the executable files found in uploads and record the ones the admin accepts (see Review). */
    private function review(): int
    {
        $this->init();
        $reg = (new Sites($this->cfg, new Alerts($this->cfg)))->registry();
        if ($reg === null) {
            throw new \RuntimeException(I18n::t("no site list yet: run 'wp-secmon discover'"));
        }
        $sites = [];
        foreach ($reg['sites'] ?? [] as $a) {
            $sites[$a['root']] = Site::fromArray($a);
        }
        if ($this->only) {
            $picked = [];
            foreach ($this->only as $path) {
                $root = Sites::root($path);
                if (!isset($sites[$root])) {
                    throw new \RuntimeException(I18n::t("%s is not in the site list; run 'wp-secmon discover' to search for new sites", $path));
                }
                $picked[$root] = $sites[$root];
            }
            $sites = $picked;
        }
        return (new Review(new Context($this->cfg, new Alerts($this->cfg), $this->tmp), STDIN))->run(array_values($sites), $this->withAccepted);
    }

    /** Forget open alerts and cached vulnerability data, so the next run reports every problem again. */
    private function reset(): int
    {
        $state = $this->cfg->str('state_dir');
        if (!is_dir($state)) {
            fwrite(STDOUT, I18n::t('Nothing to reset: %s does not exist yet.', $state) . "\n");
            return 0;
        }
        umask(077);
        Util::mkdir("$state/locks");
        $locks = $this->lockAll();
        try {
            $ids = null;
            foreach ($this->only as $path) {
                $id = Site::idFor(Sites::root($path));
                if (!is_dir("$state/sites/$id")) {
                    Log::warning(I18n::t('%s: no monitoring state for this site (never checked?)', $path));
                }
                $ids[] = $id;
            }
            $n = Alerts::forget($state, $ids);
            Util::rmTree("$state/cache/vulndb");
            @unlink("$state/cache/version-check.json");
        } finally {
            self::unlockAll($locks);
        }
        fwrite(STDOUT, ($ids === null
            ? I18n::n($n, 'Forgot %d open alert(s) and the cached vulnerability data. Baselines are kept.',
                'Forgot %d open alert(s) and the cached vulnerability data. Baselines are kept.', $n)
            : I18n::n($n, 'Forgot %d open alert(s) on %d site(s) and the cached vulnerability data. Baselines are kept.',
                'Forgot %d open alert(s) on %d site(s) and the cached vulnerability data. Baselines are kept.', $n, count($ids)))
            . "\n" . I18n::t("Run 'wp-secmon all' to report every problem again.") . "\n");
        return 0;
    }

    public static function table(array $head, array $rows): void
    {
        $w = array_map('strlen', $head);
        foreach ($rows as $r) {
            foreach ($r as $i => $c) {
                $w[$i] = min(max($w[$i], strlen((string) $c)), $i === count($head) - 1 ? 1000 : 60);
            }
        }
        foreach (array_merge([$head], $rows) as $r) {
            $line = '';
            foreach ($r as $i => $c) {
                if ($i === count($r) - 1) {
                    $line .= $c;
                    continue;
                }
                // Padded by characters, so that accented headers line up.
                $cell = Util::oneLine((string) $c, $w[$i]);
                $line .= $cell . str_repeat(' ', max(0, $w[$i] + 2 - Util::width($cell)));
            }
            fwrite(STDOUT, rtrim($line) . "\n");
        }
    }
}
