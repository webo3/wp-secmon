<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Alerts: collection, de-duplication, digest e-mail and history log.
 *
 * - event():  a one-off change (new administrator, wp-config.php modified...).
 *             Reported once; the new state becomes the baseline.
 * - alert():  an ongoing condition identified by a key (modified core files,
 *             known vulnerability...). Reported when it appears or changes,
 *             repeated every N hours while unchanged, and reported as resolved
 *             once resolve() is called for its key.
 *
 * Everything reported during one run is mailed as a single report (see Report),
 * or as one report per site administrator with alert_site_admins (see mailings()).
 * Each alert carries a "kind" (by default the prefix of its key) and optional
 * structured "meta" that the report uses to suggest what to do.
 */
final class Alerts
{
    public const RANK = ['info' => 1, 'warning' => 2, 'critical' => 3];

    private Config $cfg;
    private string $stateDir;
    private string $logDir;
    private array $records = [];
    private string $ctxId = '_global';
    private string $ctxRoot = '(server)';
    private string $ctxUser = '-';
    private int $started;

    public string $check = 'wp-secmon';
    public array $checksRun = [];
    /** Sites checked during this run (root => true), for the report totals. */
    public array $checked = [];
    public int $errors = 0;
    public int $suppressed = 0;
    public bool $noMail = false;
    public bool $print = false;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
        $this->stateDir = $cfg->str('state_dir');
        $this->logDir = $cfg->str('log_dir');
        $this->started = time();
    }

    public function setSite(?Site $site): void
    {
        if ($site === null) {
            $this->setContext('_global', '(server)', '-');
        } else {
            $this->setContext($site->id, $site->root, $site->user);
        }
    }

    public function setContext(string $id, string $root, string $user): void
    {
        $this->ctxId = $id;
        $this->ctxRoot = $root;
        $this->ctxUser = $user;
    }

    /**
     * @param string|array $details
     * @param array $meta 'kind' (see Report) and data the report uses
     */
    public function event(string $sev, string $title, $details = '', array $meta = []): void
    {
        $this->emit($sev, $title, self::lines($details), $meta + ['kind' => 'change']);
    }

    /**
     * @param string|array $details
     * @param int|null $repeatHours null = alert_repeat_hours, 0 = never repeat
     * @param string|null $fingerprint text identifying the condition (default: title + details)
     * @param array $meta data the report uses; 'kind' defaults to the key up to the first dot
     */
    public function alert(string $sev, string $key, string $title, $details = '', ?int $repeatHours = null,
        ?string $fingerprint = null, array $meta = []): void
    {
        $details = self::lines($details);
        $repeat = $repeatHours ?? $this->cfg->int('alert_repeat_hours');
        $file = $this->stateFile($key);
        $fp = hash('sha256', $sev . "\n" . ($fingerprint ?? $title . "\n" . $details));
        $now = time();
        $old = Util::readJson($file) ?? [];

        if (($old['fp'] ?? '') === $fp && ($repeat <= 0 || $now - (int) ($old['last'] ?? 0) < $repeat * 3600)) {
            $this->suppressed++;
            Log::debug("{$this->ctxRoot}: unchanged, not repeated: $title");
            return;
        }
        Util::writeJson($file, [
            'fp' => $fp,
            'last' => $now,
            'first' => (int) ($old['first'] ?? $now),
            'severity' => $sev,
            'title' => Util::oneLine($title),
            'root' => $this->ctxRoot,
            'check' => $this->check,
        ]);
        $meta += ['kind' => explode('.', $key)[0]];
        $this->emit($sev, $title, $details, $meta, ($old['fp'] ?? '') === $fp ? (int) ($old['first'] ?? $now) : null);
    }

    public function resolve(string $key): void
    {
        $this->resolveFile($this->stateFile($key));
    }

    /** Resolve every open alert whose key starts with $prefix, except $keep. */
    public function resolveExcept(string $prefix, array $keep): void
    {
        $dir = $this->stateDir();
        $keepFiles = [];
        foreach ($keep as $k) {
            $keepFiles[self::keyFile($k)] = true;
        }
        $safePrefix = self::keyFile($prefix, false);
        foreach (glob($dir . '/' . $safePrefix . '*.json') ?: [] as $file) {
            if (!isset($keepFiles[basename($file)])) {
                $this->resolveFile($file);
            }
        }
    }

    /** A check could not run on the current site; de-duplicated on the message only. */
    public function siteError(string $key, string $message, string $details = ''): void
    {
        $this->errors++;
        Log::warning("{$this->ctxRoot}: $message");
        if ($this->cfg->bool('alert_on_errors')) {
            $this->alert('warning', "error.$key", I18n::t('Check failed: %s', $message), $details, null, $message);
        }
    }

    public function siteOk(string $key): void
    {
        $this->resolve("error.$key");
    }

    /**
     * Forget open alerts, so the next run reports them again as new. Baselines are kept.
     * @param string[]|null $siteIds null = every site and the server
     * @return int number of alerts forgotten
     */
    public static function forget(string $stateDir, ?array $siteIds = null): int
    {
        $dirs = $siteIds === null
            ? array_merge(["$stateDir/global/alerts"], glob("$stateDir/sites/*/alerts") ?: [])
            : array_map(static function (string $id) use ($stateDir): string {
                return "$stateDir/sites/$id/alerts";
            }, $siteIds);
        $n = 0;
        foreach ($dirs as $dir) {
            foreach (glob("$dir/*.json") ?: [] as $file) {
                unlink($file);
                $n++;
            }
        }
        return $n;
    }

    /** Open alerts of every site, for `wp-secmon status`. */
    public static function openAlerts(string $stateDir): array
    {
        $out = [];
        $files = array_merge(glob("$stateDir/global/alerts/*.json") ?: [], glob("$stateDir/sites/*/alerts/*.json") ?: []);
        foreach ($files as $file) {
            $a = Util::readJson($file);
            if ($a !== null) {
                $out[] = $a;
            }
        }
        usort($out, static function ($a, $b) {
            return [self::RANK[$b['severity']] ?? 0, $a['root'] ?? ''] <=> [self::RANK[$a['severity']] ?? 0, $b['root'] ?? ''];
        });
        return $out;
    }

    // ------------------------------------------------------------------

    /** @param int|null $since when a repeated alert first appeared (null: new) */
    private function emit(string $sev, string $title, string $details, array $meta, ?int $since = null): void
    {
        $r = [
            'sev' => $sev,
            'check' => $this->check,
            'root' => $this->ctxRoot,
            'user' => $this->ctxUser,
            'title' => Util::oneLine($title),
            'details' => $details,
            'kind' => (string) $meta['kind'],
            'meta' => $meta,
            'since' => $since,
        ];
        $this->records[] = $r;
        $title = Report::fullTitle($r);
        $line = sprintf("%s %s check=%s site=%s user=%s %s\n", gmdate('Y-m-d\TH:i:s\Z'), strtoupper($sev), $this->check, $this->ctxRoot, $this->ctxUser, $title);
        @file_put_contents($this->logDir . '/alerts.log', $line, FILE_APPEND | LOCK_EX);
        // A report printed on the terminal already shows every alert.
        $level = $sev === 'critical' ? 'crit' : ($sev === 'warning' ? 'warning' : 'notice');
        Log::write($this->print && !getenv('JOURNAL_STREAM') ? 'debug' : $level, "[$sev] {$this->ctxRoot}: $title");
    }

    private function resolveFile(string $file): void
    {
        $old = Util::readJson($file);
        if ($old === null) {
            return;
        }
        @unlink($file);
        if ($this->cfg->bool('alert_on_resolve')) {
            $this->emit('info', (string) ($old['title'] ?? basename($file, '.json')), '', ['kind' => 'resolved']);
        }
    }

    private function stateDir(): string
    {
        $dir = $this->ctxId === '_global' ? "{$this->stateDir}/global/alerts" : "{$this->stateDir}/sites/{$this->ctxId}/alerts";
        Util::mkdir($dir);
        return $dir;
    }

    private function stateFile(string $key): string
    {
        return $this->stateDir() . '/' . self::keyFile($key);
    }

    private static function keyFile(string $key, bool $withExt = true): string
    {
        $safe = substr((string) preg_replace('/[^A-Za-z0-9._-]/', '_', $key), 0, 200);
        if ($safe === '' || $safe[0] === '.') {
            $safe = '_' . $safe;
        }
        return $withExt ? $safe . '.json' : $safe;
    }

    /** @param string|array $details */
    private static function lines($details): string
    {
        $text = is_array($details) ? implode("\n", $details) : (string) $details;
        $out = [];
        foreach (preg_split('/\R/', Util::text($text)) ?: [] as $line) {
            $out[] = strlen($line) > 500 ? substr($line, 0, 497) . '...' : $line;
        }
        return rtrim(implode("\n", $out));
    }

    // ------------------------------------------------------------------
    // Report
    // ------------------------------------------------------------------

    public function finish(): void
    {
        $checks = $this->checksRun ? implode(', ', $this->checksRun) : 'none';
        [$count, $max] = self::tally($this->records);
        Log::info(I18n::t(
            'finished %s: %d site(s) checked, %d error(s); alerts: %d critical, %d warning, %d info (%d unchanged not repeated)',
            $checks, count($this->checked), $this->errors, $count['critical'], $count['warning'], $count['info'], $this->suppressed
        ));
        if (!$this->records) {
            return;
        }

        $run = [
            'host' => Util::hostname(),
            'checks' => $checks,
            'started' => $this->started,
            'duration' => time() - $this->started,
            'sites' => count($this->checked),
            'errors' => $this->errors,
            'count' => $count,
            'details' => $this->logDir . '/last-report-' . str_replace(', ', '-', $checks) . '.txt',
            'log' => $this->logDir . '/alerts.log',
        ];
        $report = new Report($this->records, $run, $this->cfg);
        @file_put_contents($run['details'], $report->details());
        if ($this->print) {
            $color = function_exists('posix_isatty') && posix_isatty(STDOUT) && (string) getenv('NO_COLOR') === '';
            fwrite(STDOUT, $report->text($color));
        }

        $min = self::RANK[$this->cfg->str('mail_min_severity')] ?? 2;
        if ($this->noMail || $max < $min) {
            return;
        }
        // Each e-mail has the alerts and the totals of its own sites, and is sent on its own severity.
        foreach ($this->mailings() as [$to, $cc, $records, $sites, $errors]) {
            [$partCount, $partMax] = self::tally($records);
            if ($partMax < $min) {
                continue;
            }
            $part = ['sites' => $sites, 'errors' => $errors, 'count' => $partCount] + $run;
            $partReport = new Report($records, $part, $this->cfg);
            if ($this->cfg->str('mail_format') === 'text') {
                $this->mail($to, $cc, self::subject($part, $partMax), ["Content-Type: text/plain; charset=UTF-8", 'Content-Transfer-Encoding: 8bit'],
                    $partReport->details());
            } else {
                [$headers, $body] = self::mime($partReport->text(false), $partReport->html(), 'wp-secmon-' . bin2hex(random_bytes(12)));
                $this->mail($to, $cc, self::subject($part, $partMax), $headers, $body);
            }
        }
        if ($this->cfg->str('alert_command') !== '') {
            $label = $max >= 3 ? 'CRITICAL' : ($max === 2 ? 'WARNING' : 'INFO');
            $cmd = ['/bin/sh', '-c', 'WPG_SUBJECT="$1" WPG_SEVERITY="$2" exec /bin/sh -c "$3"', 'sh', self::subject($run, $max), $label,
                $this->cfg->str('alert_command')];
            [$code, , $err] = Proc::capture($cmd, 120, $report->text(false));
            if ($code !== 0) {
                Log::error(I18n::t('alert_command failed: %s', Util::oneLine($err)));
            }
        }
    }

    /** @return array{0: array<string, int>, 1: int} [alerts per severity, rank of the most severe] */
    private static function tally(array $records): array
    {
        $count = ['critical' => 0, 'warning' => 0, 'info' => 0];
        $max = 0;
        foreach ($records as $r) {
            $count[$r['sev']] = ($count[$r['sev']] ?? 0) + 1;
            $max = max($max, self::RANK[$r['sev']] ?? 0);
        }
        return [$count, $max];
    }

    /** @param array $run see Report */
    private static function subject(array $run, int $max): string
    {
        $sev = $max >= 3 ? 'critical' : ($max === 2 ? 'warning' : 'info');
        return '[wp-secmon] ' . I18n::t('%s: %s - %s, %s (%s)', $run['host'], Util::upper(Report::severityName($sev)),
            Report::countLabel('critical', $run['count']['critical']), Report::countLabel('warning', $run['count']['warning']), $run['checks']);
    }

    /**
     * Who is e-mailed what: [recipient, copies (Cc), alerts, sites checked, check errors] per e-mail.
     *
     * Everything goes to alert_email. With alert_site_admins, each site goes
     * instead to its WordPress administration address, as read by the last
     * integrity check: one e-mail per address, whatever the number of its sites.
     * Notes about the monitoring itself, and the sites without a usable address,
     * still go to alert_email.
     * @return array<int, array{0: string, 1: string[], 2: array[], 3: int, 4: int}>
     */
    public function mailings(): array
    {
        $fallback = $this->cfg->str('alert_email');
        if (!$this->cfg->bool('alert_site_admins')) {
            return [[$fallback, [], $this->records, count($this->checked), $this->errors]];
        }
        // The address is in the hands of the site: when it changes, the report that
        // says so also goes to the previous one, so that it cannot be diverted quietly.
        $before = [];
        $roots = $this->checked;
        foreach ($this->records as $r) {
            if ($r['kind'] === 'option' && ($r['meta']['option'] ?? '') === 'admin_email') {
                $before[$r['root']] = $r['meta']['before'] ?? null;
            }
            if (!Report::isServerNote($r)) {
                $roots[$r['root']] = true;
            }
        }

        // Keyed by the address in lower case; '' is alert_email, which gets the check errors.
        $mails = ['' => [$fallback, [], [], 0, $this->errors]];
        $copies = $this->cfg->list('alert_site_admins_cc');
        $keys = [];
        foreach (array_keys($roots) as $root) {
            $root = (string) $root;
            $options = Util::readJson($this->stateDir . '/sites/' . Site::idFor($root) . '/options.json');
            foreach ([$options['admin_email'] ?? null, $before[$root] ?? null] as $address) {
                $address = self::address($address);
                if ($address === null) {
                    continue;
                }
                $key = strtolower($address);
                if (!isset($mails[$key])) {
                    // No copy to the recipient itself.
                    $cc = array_values(array_filter($copies, static function (string $copy) use ($key): bool {
                        return strtolower($copy) !== $key;
                    }));
                    $mails[$key] = [$address, $cc, [], 0, 0];
                }
                $keys[$root][$key] = true;
            }
            if (!isset($keys[$root])) {
                Log::debug("$root: no usable administration address, reported to $fallback");
                $keys[$root][''] = true;
            }
            if (isset($this->checked[$root])) {
                foreach (array_keys($keys[$root]) as $key) {
                    $mails[$key][3]++;
                }
            }
        }
        foreach ($this->records as $r) {
            foreach (Report::isServerNote($r) ? [''] : array_keys($keys[$r['root']]) as $key) {
                $mails[$key][2][] = $r;
            }
        }
        return array_values(array_filter($mails, static function (array $mail): bool {
            return $mail[2] !== [];
        }));
    }

    /**
     * An administration address as it can be written in a mail header, or null.
     * The site chooses it: anything but a plain address is refused, so that it
     * cannot add recipients or headers.
     */
    public static function address($value): ?string
    {
        return is_string($value) && strlen($value) <= 254
            && preg_match('/^[A-Za-z0-9_][A-Za-z0-9._+-]*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/D', $value) ? $value : null;
    }

    /**
     * multipart/alternative body: the text summary and the HTML report.
     * @return array{0: string[], 1: string} [MIME headers, body]
     */
    public static function mime(string $text, string $html, string $boundary): array
    {
        $body = "--$boundary\n"
            . "Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n"
            . rtrim($text) . "\n"
            . "--$boundary\n"
            . "Content-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n"
            . chunk_split(base64_encode($html), 76, "\n")
            . "--$boundary--\n";
        return [["Content-Type: multipart/alternative; boundary=\"$boundary\"", 'Content-Transfer-Encoding: 8bit'], $body];
    }

    /**
     * @param string[] $cc
     * @param string[] $mimeHeaders Content-Type and Content-Transfer-Encoding
     */
    private function mail(string $to, array $cc, string $subject, array $mimeHeaders, string $body): void
    {
        $sendmail = $this->cfg->str('sendmail');
        $copies = $cc ? 'Cc: ' . implode(', ', $cc) . "\n" : '';
        $mime = "MIME-Version: 1.0\n" . implode("\n", $mimeHeaders) . "\n";
        // Translated subjects may have accents: RFC 2047 encoded words of at most 75 characters.
        if (preg_match('/[^\x20-\x7E]/', $subject) && preg_match_all('/.{1,10}/us', $subject, $m)) {
            $subject = implode(' ', array_map(static function (string $chunk): string {
                return '=?UTF-8?B?' . base64_encode($chunk) . '?=';
            }, $m[0]));
        }
        if (is_file($sendmail) && is_executable($sendmail)) {
            $headers = "To: $to\n" . $copies;
            if ($this->cfg->str('alert_from') !== '') {
                $headers .= 'From: ' . $this->cfg->str('alert_from') . "\n";
            }
            $headers .= "Subject: $subject\nAuto-Submitted: auto-generated\nX-Mailer: wp-secmon/" . VERSION . "\n" . $mime . "\n";
            [$code, , $err] = Proc::capture([$sendmail, '-oi', '-t'], 120, $headers . $body);
            if ($code === 0) {
                Log::info(I18n::t('report sent to %s', $to));
                return;
            }
            Log::error(I18n::t('sending the report with %s failed: %s', $sendmail, Util::oneLine($err)));
        } elseif (function_exists('mail') && @mail($to, $subject, $body, str_replace("\n", "\r\n", "Auto-Submitted: auto-generated\n" . $copies . rtrim($mime)))) {
            Log::info(I18n::t('report sent to %s with mail()', $to));
            return;
        }
        Log::error(I18n::t('the report could not be e-mailed; it is kept in %s', $this->logDir));
    }
}
