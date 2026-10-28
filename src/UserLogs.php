<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * The logs of each account's own sites, copied to its home (user_log_dir,
 * such as ~/logs/wp-secmon): alerts.log and the details of the last reports.
 *
 * A run queues them in a root-only outbox, state_dir/outbox/<account>/, and
 * publish() delivers them as the account, through the hidden
 * `wp-secmon __write-logs` command (write()): root never writes in a directory
 * an account controls. Under systemd the checks see the homes read-only, so
 * the unit delivers after each check (ExecStopPost, `__deliver`).
 *
 * Nothing is copied inside a WordPress root, where the logs could be
 * downloaded, nor for accounts whose home cannot take them (such as www-data
 * with a root-owned /var/www): their outbox is discarded.
 */
final class UserLogs
{
    /** Bytes queued per account while its logs cannot be delivered, and size at which alerts.log is rotated. */
    public const MAX = 1048576;
    /** Exit codes of write(), besides 0 and 1 (write failed). */
    public const BAD_INPUT = 2;
    public const UNSAFE = 3;
    public const READ_ONLY = 75;

    private Config $cfg;
    private string $outbox;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
        $this->outbox = $cfg->str('state_dir') . '/outbox';
    }

    /** A user_log_dir value: a directory relative to the home, without "." or "..". */
    public static function validPath(string $path): bool
    {
        return (bool) preg_match('#^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$#D', $path) && !array_intersect(explode('/', $path), ['.', '..']);
    }

    /** The folder an account's logs are copied to, or null (off, unknown account, no usable home). */
    public function target(string $account): ?string
    {
        return $this->box($account) !== null ? $this->targetOf(Util::passwd($account)) : null;
    }

    /** Queue one line of alerts.log for an account. */
    public function queueLine(string $account, string $line): void
    {
        $box = $this->box($account);
        if ($box === null || (!is_dir($box) && !@mkdir($box, 0700, true) && !is_dir($box))) {
            return;
        }
        clearstatcache();
        if ((int) @filesize("$box/pending.log") < self::MAX) {
            @file_put_contents("$box/pending.log", $line, FILE_APPEND | LOCK_EX);
        }
    }

    /** Queue the details of a report (last-report-*.txt) for an account. */
    public function queueReport(string $account, string $name, string $content): void
    {
        $box = $this->box($account);
        if ($box !== null) {
            Util::writeFile("$box/$name", $content);
        }
    }

    /** Deliver every outbox to its account's home, as that account. */
    public function publish(string $tmp, ?RunAs $runAs = null): void
    {
        if (!is_dir($this->outbox)) {
            return;
        }
        if ($this->cfg->str('user_log_dir') === '') {
            Util::rmTree($this->outbox);
            return;
        }
        $boxes = array_values(array_filter(scandir($this->outbox) ?: [], function (string $entry): bool {
            return $entry !== '.' && $entry !== '..' && is_dir("{$this->outbox}/$entry");
        }));
        if (!$boxes) {
            return;
        }
        Util::mkdir($this->cfg->str('state_dir') . '/locks');
        $lock = fopen($this->cfg->str('state_dir') . '/locks/publish.lock', 'ce');
        if ($lock === false) {
            throw new \RuntimeException(I18n::t('cannot write %s', $this->cfg->str('state_dir') . '/locks/publish.lock'));
        }
        flock($lock, LOCK_EX);
        try {
            $runAs = $runAs ?? new RunAs($this->cfg);
            $roots = $this->roots();
            foreach ($boxes as $entry) {
                $this->deliver(rawurldecode($entry), "{$this->outbox}/$entry", $roots, $tmp, $runAs);
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function deliver(string $account, string $box, array $roots, string $tmp, RunAs $runAs): void
    {
        $pw = $this->box($account) !== null ? Util::passwd($account) : null;
        $target = $this->targetOf($pw);
        $why = $pw === null || $target === null ? 'no usable home directory' : self::unusable($target, $pw, $roots);
        if ($why !== null) {
            Log::debug("$account: logs not copied to its home ($why), discarded");
            Util::rmTree($box);
            return;
        }

        $pending = "$box/pending.log";
        $append = self::readLocked($pending);
        $files = $inodes = [];
        foreach (scandir($box) ?: [] as $name) {
            if (preg_match('/^last-report-[A-Za-z0-9._-]+\.txt$/D', $name)) {
                $inodes[$name] = @fileinode("$box/$name");
                $files[$name] = (string) @file_get_contents("$box/$name");
            }
        }
        if ($append === '' && !$files) {
            return;
        }
        // The account's processes cannot write files larger than max_output_mb (prlimit).
        $cap = (int) min(self::MAX, intdiv($runAs->maxOutput(), 2));
        foreach ($files as $name => $content) {
            if (strlen($content) > $cap) {
                $files[$name] = substr($content, 0, $cap - 16) . "\n[...]\n";
            }
        }

        $payload = "$tmp/user-logs-" . bin2hex(random_bytes(6));
        file_put_contents("$payload.json", (string) json_encode([
            'home' => $pw['home'], 'path' => $this->cfg->str('user_log_dir'), 'append' => $append, 'files' => $files, 'cap' => $cap,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        $cmd = [PHP_BINARY, '-d', 'open_basedir=', '-d', 'display_errors=stderr', Util::entry(), '__write-logs'];
        $code = $runAs->run($account, $cmd, "$payload.out", "$payload.err", 60, '', "$payload.json");
        $r = WpResult::fromFiles($code, "$payload.out", "$payload.err", $runAs->maxOutput());
        @unlink("$payload.json");

        if ($r->ok()) {
            self::acknowledge($pending, strlen($append));
            clearstatcache();
            foreach ($inodes as $name => $inode) {
                // Unless a newer report replaced it meanwhile.
                if (@fileinode("$box/$name") === $inode) {
                    @unlink("$box/$name");
                }
            }
            @unlink("$box/.failed");
            Log::debug("$account: logs copied to $target");
            return;
        }
        if ($r->code === self::READ_ONLY) {
            Log::debug("$account: $target is read-only here, logs kept for later");
            return;
        }
        $res = $r->json() ?? [];
        $path = (string) ($res['path'] ?? $target);
        if ($r->code === self::UNSAFE) {
            $why = I18n::t('%s must be a directory of %s that no other account can write to', $path, $account);
        } elseif ($r->code === 1 && isset($res['error'])) {
            $why = I18n::t('cannot write %s: %s', $path, Util::oneLine((string) $res['error'], 200));
        } else {
            $why = $r->reason();
        }
        // Kept for the next run; reported once until the reason changes.
        if (@file_get_contents("$box/.failed") !== $why) {
            Log::warning(I18n::t('the logs of %s could not be copied to %s: %s', $account, $target, $why));
            Util::writeFile("$box/.failed", $why);
        } else {
            Log::debug("$account: logs still not copied to $target: $why");
        }
    }

    /**
     * Why $target cannot take the logs of the account $pw, or null: it is
     * inside a WordPress root (the logs could be downloaded), or the closest
     * directory that exists on the way belongs to someone else (the account
     * could not create the rest).
     */
    public static function unusable(string $target, array $pw, array $roots): ?string
    {
        foreach ([$target, self::resolved($target)] as $path) {
            foreach ($roots as $root) {
                $root = rtrim($root, '/');
                if ($path === $root || strncmp($path, "$root/", strlen($root) + 1) === 0) {
                    return "inside the WordPress root $root";
                }
            }
        }
        for ($dir = $target; $dir !== '/' && $dir !== '.'; $dir = dirname($dir)) {
            $st = @lstat($dir);
            if ($st !== false) {
                return $st['uid'] === $pw['uid'] ? null : "$dir does not belong to {$pw['name']}";
            }
        }
        return 'no existing directory';
    }

    /**
     * Run as the account by `wp-secmon __write-logs`, with the JSON publish()
     * builds on stdin: appends to alerts.log (rotated to alerts.log.1 at the
     * cap) and replaces the reports, in home/path.
     *
     * Every directory below the home must be a real directory of the account
     * that nobody else can write to, and the home must belong to the account or
     * to root: otherwise another account (sharing its group, say) could swap
     * the folder for its own and read the logs.
     * @return array{0: int, 1: array} [exit code, result printed as JSON]
     */
    public static function write(string $json): array
    {
        umask(077);
        $in = json_decode($json, true);
        $home = rtrim((string) ($in['home'] ?? ''), '/');
        $path = (string) ($in['path'] ?? '');
        $append = $in['append'] ?? null;
        $files = $in['files'] ?? null;
        $cap = (int) ($in['cap'] ?? 0);
        $valid = $home !== '' && $home[0] === '/' && self::validPath($path) && is_string($append) && is_array($files) && $cap > 0;
        foreach (is_array($files) ? $files : [] as $name => $content) {
            $valid = $valid && is_string($content) && preg_match('/^last-report-[A-Za-z0-9._-]+\.txt$/D', (string) $name);
        }
        if (!$valid) {
            return [self::BAD_INPUT, ['error' => 'invalid input']];
        }
        $uid = Util::effectiveUid();
        // Only ever as the account (RunAs refuses root): root would pass every check below, anywhere.
        if ($uid === 0) {
            return [1, ['error' => 'refusing to write as root', 'path' => $home]];
        }

        $dir = $home;
        foreach (array_merge([''], explode('/', $path)) as $i => $part) {
            $dir = $i === 0 ? $home : "$dir/$part";
            // The home itself may be a symbolic link (set by the administrator in passwd).
            $st = $i === 0 ? @stat($dir) : @lstat($dir);
            if ($st === false && $i > 0) {
                if (!@mkdir($dir, 0700)) {
                    return self::failure($dir);
                }
                $st = @lstat($dir);
            }
            $owner = $st !== false && ($st['uid'] === $uid || ($i === 0 && $st['uid'] === 0));
            $private = $st !== false && (!($st['mode'] & 0022) || ($i === 0 && ($st['mode'] & 01000)));
            if ($st === false || ($st['mode'] & 0170000) !== 0040000 || !$owner || !$private) {
                return [self::UNSAFE, ['error' => 'unsafe', 'path' => $dir]];
            }
        }

        if ($append !== '') {
            if (strlen($append) > $cap) {
                // The most recent lines.
                $append = substr($append, -$cap);
                $append = (string) substr($append, (int) strpos($append, "\n") + 1);
            }
            $log = "$dir/alerts.log";
            $st = @lstat($log);
            if ($st !== false && ($st['mode'] & 0170000) !== 0100000) {
                if (!@unlink($log)) {
                    return self::failure($log);
                }
                $st = false;
            }
            if ($st !== false && $st['size'] + strlen($append) > $cap && !@rename($log, "$log.1")) {
                return self::failure("$log.1");
            }
            $fh = @fopen($log, 'a');
            if ($fh === false) {
                return self::failure($log);
            }
            $written = @fwrite($fh, $append);
            fclose($fh);
            if ($written !== strlen($append)) {
                return self::failure($log);
            }
        }

        foreach ($files as $name => $content) {
            $tmp = "$dir/.$name." . getmypid();
            @unlink($tmp);
            $fh = @fopen($tmp, 'x');
            if ($fh === false) {
                return self::failure($tmp);
            }
            $written = @fwrite($fh, $content);
            fclose($fh);
            if ($written !== strlen($content) || !@rename($tmp, "$dir/$name")) {
                $failure = self::failure("$dir/$name");
                @unlink($tmp);
                return $failure;
            }
        }
        return [0, ['ok' => true]];
    }

    /** Remove the first $bytes of a queue, once delivered; the lines queued meanwhile stay. */
    public static function acknowledge(string $file, int $bytes): void
    {
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return;
        }
        flock($fh, LOCK_EX);
        $rest = (string) substr((string) stream_get_contents($fh), $bytes);
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, $rest);
        flock($fh, LOCK_UN);
        fclose($fh);
    }

    // ------------------------------------------------------------------

    /** Account name => outbox directory, or null for the names that never get logs. */
    private function box(string $account): ?string
    {
        if ($this->cfg->str('user_log_dir') === '' || in_array($account, ['', '.', '..', '-', 'root'], true)) {
            return null;
        }
        return $this->outbox . '/' . rawurlencode($account);
    }

    private function targetOf(?array $pw): ?string
    {
        $home = rtrim((string) ($pw['home'] ?? ''), '/');
        return $home !== '' && $home[0] === '/' ? $home . '/' . $this->cfg->str('user_log_dir') : null;
    }

    /** Every WordPress root of the site list (sites, skipped sites, files without wp-config.php), as listed and resolved. */
    private function roots(): array
    {
        $reg = Util::readJson($this->cfg->str('state_dir') . '/sites.json') ?? [];
        $roots = [];
        foreach (array_merge(array_column($reg['sites'] ?? [], 'root'), array_column($reg['skipped'] ?? [], 'root'), $reg['orphans'] ?? []) as $root) {
            $roots[(string) $root] = true;
            $real = realpath((string) $root);
            if ($real !== false) {
                $roots[$real] = true;
            }
        }
        return array_map('strval', array_keys($roots));
    }

    /** $path with its closest existing directory resolved (symbolic links). */
    private static function resolved(string $path): string
    {
        $suffix = '';
        for ($dir = $path; $dir !== '/' && $dir !== '.'; $dir = dirname($dir)) {
            $real = realpath($dir);
            if ($real !== false) {
                return rtrim($real, '/') . $suffix;
            }
            $suffix = '/' . basename($dir) . $suffix;
        }
        return $path;
    }

    private static function readLocked(string $file): string
    {
        $fh = @fopen($file, 'r');
        if ($fh === false) {
            return '';
        }
        flock($fh, LOCK_SH);
        $data = (string) stream_get_contents($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
        return $data;
    }

    /** @return array{0: int, 1: array} write() result for a file operation that failed */
    private static function failure(string $path): array
    {
        $message = (string) (error_get_last()['message'] ?? '');
        $detail = (string) preg_replace('/^[\w:]+\(.*?\): (?:failed to open stream: )?/i', '', $message);
        return [stripos($message, 'read-only file system') !== false ? self::READ_ONLY : 1, ['error' => $detail !== '' ? $detail : 'failed', 'path' => $path]];
    }
}
