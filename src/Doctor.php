<?php

declare(strict_types=1);

namespace WpSecMon;

/** `wp-secmon doctor`: verify requirements and configuration. */
final class Doctor
{
    private Config $cfg;
    private int $fails = 0;
    private int $warns = 0;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }

    private function line(string $status, string $msg): void
    {
        if ($status === 'FAIL') {
            $this->fails++;
        } elseif ($status === 'warn') {
            $this->warns++;
        }
        fwrite(STDOUT, sprintf("  [%-4s] %s\n", $status, $msg));
    }

    /**
     * WP-CLI is handed to every site owner, so it must not be writable by
     * anyone but root.
     */
    public function wpCliUsable(bool $quiet = true): bool
    {
        $wp = $this->cfg->str('wp_cli');
        $problem = null;
        $real = realpath($wp);
        if ($real === false || !is_file($real)) {
            $problem = I18n::t('WP-CLI not found at %s (set wp_cli)', $wp);
        } elseif ($this->cfg->str('wp_php') === '' && !is_executable($real)) {
            $problem = I18n::t('%s is not executable (chmod 755 it or set wp_php)', $real);
        } elseif (Util::effectiveUid() === 0) {
            $problem = Util::rootOnlyProblem($real) ?? Util::rootOnlyProblem(dirname($real));
        }
        if ($problem !== null && $quiet) {
            Log::error($problem);
        } elseif (!$quiet) {
            $this->line($problem === null ? 'ok' : 'FAIL', $problem ?? I18n::t('WP-CLI: %s', $real));
        }
        return $problem === null;
    }

    public function run(array $only): int
    {
        fwrite(STDOUT, 'wp-secmon ' . VERSION . " doctor\n\n" . I18n::t('Environment') . "\n");
        $this->line(PHP_VERSION_ID >= 70400 ? 'ok' : 'FAIL', 'PHP ' . PHP_VERSION . ' (' . PHP_BINARY . ')');
        $php = realpath(PHP_BINARY) ?: PHP_BINARY;
        $problem = Util::effectiveUid() === 0 ? (Util::rootOnlyProblem($php) ?? Util::rootOnlyProblem(dirname($php))) : null;
        if ($problem !== null) {
            $this->line('FAIL', I18n::t('%s: the timers run it as root', $problem));
        }
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
        $missing = array_intersect(['proc_open', 'proc_get_status', 'proc_terminate'], $disabled);
        $this->line($missing ? 'FAIL' : 'ok', $missing
            ? I18n::t('disabled in php.ini: %s (run with: %s -d disable_functions= ...)', implode(', ', $missing), PHP_BINARY)
            : I18n::t('proc_open is available'));
        $this->line(function_exists('json_encode') ? 'ok' : 'FAIL', I18n::t('json extension'));
        $this->line(function_exists('posix_getpwnam') ? 'ok' : 'warn', function_exists('posix_getpwnam')
            ? I18n::t('posix extension') : I18n::t('posix extension missing (install php-process / php-posix); falling back to getent'));
        $this->line(function_exists('token_get_all') ? 'ok' : 'warn', function_exists('token_get_all')
            ? I18n::t('tokenizer extension') : I18n::t('tokenizer extension missing: harmless PHP data files in uploads (Sucuri, dompdf fonts) are reported'));
        $this->line(function_exists('curl_init') || extension_loaded('openssl') ? 'ok' : 'FAIL', I18n::t('HTTPS client (curl or openssl extension)'));
        $this->line(ini_get('open_basedir') ? 'warn' : 'ok', ini_get('open_basedir')
            ? I18n::t('open_basedir is set for the CLI; run with -d open_basedir=') : I18n::t('no open_basedir restriction'));
        $root = Util::effectiveUid() === 0;
        $this->line($root ? 'ok' : 'warn', $root ? I18n::t('running as root') : I18n::t('not running as root: only your own sites can be checked'));
        $this->line(is_file($this->cfg->file) ? 'ok' : 'warn', is_file($this->cfg->file)
            ? I18n::t('configuration: %s', $this->cfg->file) : I18n::t('no configuration file at %s, using defaults', $this->cfg->file));
        $this->line('ok', I18n::t('language: %s', I18n::language() . ' (' . I18n::LANGUAGES[I18n::language()] . ')'));

        fwrite(STDOUT, "\n" . I18n::t('Running as site owners') . "\n");
        try {
            $runAs = new RunAs($this->cfg);
            $this->line('ok', $runAs->method() === 'setpriv'
                ? I18n::t('user switching: %s (no PAM session, no_new_privs)', $runAs->method()) : I18n::t('user switching: %s', $runAs->method()));
        } catch (\Throwable $e) {
            $this->line('FAIL', $e->getMessage());
            $runAs = null;
        }
        $this->line(Util::which('timeout') ? 'ok' : 'warn', Util::which('timeout')
            ? I18n::t('timeout(1) available') : I18n::t('timeout(1) missing; relying on the internal timeout'));
        $this->line(Util::which('prlimit') ? 'ok' : 'warn', Util::which('prlimit')
            ? I18n::t('prlimit(1) available: output capped at %d MB', $this->cfg->int('max_output_mb'))
            : I18n::t('prlimit(1) missing (util-linux): a site can fill the disk until wp_timeout'));
        $wpOk = $this->wpCliUsable(false);
        $entry = Util::entry();
        $st = @stat($entry);
        $safe = $st !== false && ($root ? $st['uid'] === 0 && !($st['mode'] & 0022) : true);
        $where = class_exists('Phar') && \Phar::running(false) !== '' ? I18n::t('%s (phar)', $entry) : I18n::t('%s (source tree)', $entry);
        $this->line($safe ? 'ok' : 'FAIL', $safe ? I18n::t('program: %s', $where)
            : I18n::t('program: %s must be owned by root and not group/world writable: site owners execute it', $where));

        fwrite(STDOUT, "\n" . I18n::t('Alerts and storage') . "\n");
        $sendmail = $this->cfg->str('sendmail');
        if (is_executable($sendmail)) {
            $this->line('ok', I18n::t('mail to %s via %s', $this->cfg->str('alert_email'), $sendmail));
        } else {
            $this->line(function_exists('mail') ? 'warn' : 'FAIL', function_exists('mail')
                ? I18n::t('%s not found, using PHP mail()', $sendmail) : I18n::t('%s not found', $sendmail));
        }
        if ($this->cfg->bool('alert_site_admins')) {
            $cc = $this->cfg->list('alert_site_admins_cc');
            $this->line('ok', $cc ? I18n::t('each site is reported to its WordPress administration address, with a copy to %s', implode(', ', $cc))
                : I18n::t('each site is reported to its WordPress administration address'));
        }
        foreach (['state_dir', 'log_dir'] as $k) {
            $dir = $this->cfg->str($k);
            $ok = is_dir($dir) ? is_writable($dir) : is_writable(dirname($dir));
            $this->line($ok ? 'ok' : 'FAIL', $ok ? "$k $dir" : I18n::t('%s %s is not writable', $k, $dir));
        }
        $vc = Http::get($this->cfg->str('wp_version_api_url'), 20, $this->cfg->str('http_proxy'));
        $this->line($vc !== null ? 'ok' : 'warn', $vc !== null
            ? I18n::t('%s reachable', 'api.wordpress.org') : I18n::t('%s unreachable (outdated core not reported)', 'api.wordpress.org'));
        $vd = Http::get(rtrim($this->cfg->str('vuln_api_url'), '/') . '/plugin/akismet/', 20, $this->cfg->str('http_proxy'));
        $this->line($vd !== null ? 'ok' : 'warn', $vd !== null
            ? I18n::t('%s reachable', $this->cfg->str('vuln_api_url')) : I18n::t('%s unreachable (vulnerabilities not reported)', $this->cfg->str('vuln_api_url')));
        $latest = Updater::latest($this->cfg);
        if ($latest === null) {
            $this->line('warn', I18n::t('cannot read the latest release from %s', $this->cfg->str('update_url')));
        } elseif (version_compare($latest['version'], VERSION, '>')) {
            $this->line('warn', I18n::t('wp-secmon %s is available (this is %s): run wp-secmon update', $latest['version'], VERSION));
        } else {
            $this->line('ok', I18n::t('wp-secmon %s is up to date', VERSION));
        }

        $systemctl = Util::which('systemctl');
        if ($systemctl !== null) {
            fwrite(STDOUT, "\n" . I18n::t('Timers') . "\n");
            foreach (['discover', 'users', 'integrity', 'checksums', 'vulns'] as $t) {
                [$code, $out] = Proc::capture([$systemctl, 'is-active', "wp-secmon-$t.timer"], 10);
                $this->line($code === 0 ? 'ok' : 'warn', "wp-secmon-$t.timer: " . trim($out));
            }
        }

        fwrite(STDOUT, "\n" . I18n::t('Sites') . "\n");
        $alerts = new Alerts($this->cfg);
        $alerts->noMail = true;
        $sites = new Sites($this->cfg, $alerts);
        $reg = $sites->registry();
        if ($reg === null && !$only) {
            $this->line('warn', I18n::t("no site list yet: run 'wp-secmon discover'"));
        } elseif ($runAs !== null && $wpOk) {
            if ($reg !== null) {
                $this->line('ok', I18n::t('%d monitored, %d skipped (see wp-secmon sites)', count($reg['sites']), count($reg['skipped'])));
            }
            $tmp = sys_get_temp_dir() . '/wp-secmon.' . bin2hex(random_bytes(6));
            Util::mkdir($tmp);
            try {
                $wp = new WpCli($this->cfg, $runAs, $tmp);
                $list = [];
                foreach ($only as $path) {
                    $r = $sites->resolve(Sites::root($path));
                    if ($r['site'] === null) {
                        $this->line('FAIL', I18n::t('%s: %s', $path, $r['reason']));
                    } else {
                        $list[] = $r['site'];
                    }
                }
                if (!$only) {
                    $list = array_map([Site::class, 'fromArray'], array_slice($reg['sites'], 0, 5));
                }
                foreach ($list as $site) {
                    $r = $wp->run($site, ['core', 'version']);
                    $this->line($r->ok() ? 'ok' : 'FAIL', I18n::t('%s as %s: %s', $site->root, $site->user,
                        $r->ok() ? 'WordPress ' . Util::oneLine(trim($r->stdout), 100) : $r->reason()));
                }
                if (!$only && count($reg['sites']) > 5) {
                    fwrite(STDOUT, '         ' . I18n::t('(first 5 sites tested; use --site PATH to test another)') . "\n");
                }
            } finally {
                Util::rmTree($tmp);
            }
        }

        fwrite(STDOUT, "\n" . I18n::t('%d problem(s), %d warning(s).', $this->fails, $this->warns) . "\n");
        return $this->fails > 0 ? 1 : 0;
    }
}
