<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Runs commands as a site owner, never as root.
 *
 * The command gets a clean environment, cwd=/, no stdin, a hard timeout, a
 * cap on the size of the files it writes, and a new session without a
 * controlling terminal. With setpriv (the default when available) there is
 * no PAM session and the process runs with no_new_privs, so it cannot regain
 * privileges through setuid binaries.
 *
 * Accounts that are as good as root (primary group root, members of
 * forbidden_groups) are refused too, and so are sites whose path could be
 * swapped by another account (see unsafePath()).
 */
final class RunAs
{
    public const REFUSED = 125;
    /** Exit code when a command wrote more than max_output_mb: 128 + SIGXFSZ, as prlimit makes it. */
    public const TOO_MUCH_OUTPUT = 153;

    private string $method;
    private string $userPath;
    private ?string $env;
    private ?string $timeoutBin;
    private ?string $prlimit;
    private array $setsid = [];
    private array $forbiddenGroups;
    private int $maxOutput;
    private int $euid;

    public function __construct(Config $cfg)
    {
        $this->userPath = $cfg->str('user_path');
        $this->forbiddenGroups = $cfg->list('forbidden_groups');
        $this->maxOutput = max(1, $cfg->int('max_output_mb')) * 1048576;
        $this->euid = Util::effectiveUid();
        $this->env = Util::which('env');
        $this->timeoutBin = Util::which('timeout');
        $this->prlimit = Util::which('prlimit');
        $this->method = $this->euid === 0 ? $this->pickMethod($cfg->str('run_as_method')) : 'self';
        if ($this->method !== 'self') {
            $this->setsid = self::setsidPrefix();
        }
    }

    public function method(): string
    {
        return $this->method;
    }

    /** Bytes a command may write to each of stdout and stderr. */
    public function maxOutput(): int
    {
        return $this->maxOutput;
    }

    private function pickMethod(string $method): string
    {
        if ($method === 'auto') {
            $setpriv = Util::which('setpriv');
            if ($setpriv !== null) {
                [, $out, $err] = Proc::capture([$setpriv, '--help'], 10);
                if (strpos($out . $err, '--init-groups') !== false) {
                    return 'setpriv';
                }
            }
            foreach (['runuser', 'sudo', 'su'] as $candidate) {
                if (Util::which($candidate) !== null) {
                    return $candidate;
                }
            }
            throw new \RuntimeException(I18n::t('no way to switch users: install util-linux (setpriv/runuser), sudo or su'));
        }
        $bin = $method === 'cagefs' ? 'cagefs_enter_user' : $method;
        if (Util::which($bin) === null) {
            throw new \RuntimeException(I18n::t('run_as_method=%s but %s is not installed', $method, $bin));
        }
        return $method;
    }

    /**
     * setsid(1), so that site code runs in a new session without a controlling
     * terminal. Otherwise, when an admin runs wp-secmon by hand, site code could
     * open /dev/tty and push keystrokes into their root shell (TIOCSTI).
     */
    private static function setsidPrefix(): array
    {
        $setsid = Util::which('setsid');
        if ($setsid !== null) {
            [, $out, $err] = Proc::capture([$setsid, '--help'], 10);
            return strpos($out . $err, '--wait') !== false ? [$setsid, '--wait', '--'] : [$setsid, '--'];
        }
        $tty = @fopen('/dev/tty', 'r');
        if ($tty === false) {
            return []; // no terminal to protect (systemd timers, cron)
        }
        fclose($tty);
        throw new \RuntimeException(I18n::t('setsid(1) is required to check sites from a terminal: install util-linux, or let the systemd timers run the checks'));
    }

    /**
     * Why commands must not run as the account $pw, or null: root, primary
     * group root, or (when wp-secmon runs as root) a member of the root group or
     * of $forbiddenGroups, which are as good as root (sudo, docker, lxd...).
     */
    public static function refusal(array $pw, array $forbiddenGroups): ?string
    {
        if ($pw['uid'] === 0 || $pw['name'] === 'root') {
            return I18n::t('it is root');
        }
        if ($pw['gid'] === 0) {
            return I18n::t('its primary group is root');
        }
        if (Util::effectiveUid() !== 0) {
            return null; // commands run as the current user anyway
        }
        static $cache = [];
        $key = $pw['name'] . "\0" . implode(',', $forbiddenGroups);
        if (!array_key_exists($key, $cache)) {
            $cache[$key] = self::groupRefusal($pw['name'], $forbiddenGroups);
        }
        return $cache[$key];
    }

    private static function groupRefusal(string $name, array $forbiddenGroups): ?string
    {
        // The groups setpriv --init-groups, runuser, su and sudo would give.
        $id = Util::which('id');
        [$code, $out] = $id !== null ? Proc::capture([$id, '-G', '--', $name], 10) : [127, ''];
        if ($code !== 0) {
            return I18n::t('cannot list its groups');
        }
        $gids = array_map('intval', preg_split('/\s+/', trim($out), -1, PREG_SPLIT_NO_EMPTY) ?: []);
        if (in_array(0, $gids, true)) {
            return I18n::t('member of the root group');
        }
        $bad = array_values(array_intersect_key(self::forbiddenGids($forbiddenGroups), array_flip($gids)));
        return $bad ? I18n::t('member of %s (forbidden_groups)', implode(', ', $bad)) : null;
    }

    /** @return array<int, string> gid => name of the forbidden groups that exist here */
    private static function forbiddenGids(array $groups): array
    {
        static $cache = [];
        $key = implode(',', $groups);
        if (!isset($cache[$key])) {
            $cache[$key] = [];
            foreach ($groups as $group) {
                $gid = Util::groupId($group);
                if ($gid !== null) {
                    $cache[$key][$gid] = $group;
                }
            }
        }
        return $cache[$key];
    }

    /**
     * Why site code under $dir must not run as the account $pw, or null.
     *
     * Whoever can rename a directory on the way to $dir can swap the site for
     * their own code, which would then run as $pw. So every directory from /
     * down to $dir must be a real directory (not a symbolic link) owned by root
     * or by the account, and those above $dir must not be writable by anyone
     * else: group writes are fine for the account's own group, world writes
     * only with the sticky bit.
     */
    public static function unsafePath(string $dir, array $pw): ?string
    {
        clearstatcache(true);
        $parts = explode('/', trim($dir, '/'));
        $path = '';
        foreach ($parts as $i => $part) {
            $path .= '/' . $part;
            $st = @lstat($path);
            if ($st === false) {
                return I18n::t('cannot stat %s', $path);
            }
            if (($st['mode'] & 0170000) !== 0040000) {
                return I18n::t('%s is a symbolic link or not a directory', $path);
            }
            if ($st['uid'] !== 0 && $st['uid'] !== $pw['uid']) {
                $owner = Util::passwd((int) $st['uid']);
                return I18n::t("%s belongs to '%s'", $path, $owner['name'] ?? $st['uid']);
            }
            $above = $i < count($parts) - 1;
            $sticky = ($st['mode'] & 01000) !== 0;
            if ($above && !$sticky && (($st['mode'] & 0002) || (($st['mode'] & 0020) && $st['gid'] !== $pw['gid']))) {
                return I18n::t('%s is writable by other accounts', $path);
            }
        }
        return null;
    }

    /**
     * Run $cmd as $user; stdout/stderr go to files. $siteRoot is the site the
     * command runs code from, if any. Returns the exit code, or RunAs::REFUSED
     * when the user is root, unknown, not switchable, as good as root, or
     * when $siteRoot could be swapped by another account.
     */
    public function run(string $user, array $cmd, string $stdout, string $stderr, int $timeout, string $siteRoot = ''): int
    {
        $pw = Util::passwd($user);
        if ($pw === null) {
            file_put_contents($stderr, 'wp-secmon: ' . I18n::t("unknown user '%s'", $user) . "\n");
            return self::REFUSED;
        }
        if ($pw['uid'] === 0 || $user === 'root') {
            Log::error(I18n::t("refusing to run a command as root (user '%s')", $user));
            file_put_contents($stderr, 'wp-secmon: ' . I18n::t('refusing to run as root') . "\n");
            return self::REFUSED;
        }
        if ($this->method === 'self' && $pw['uid'] !== $this->euid) {
            file_put_contents($stderr, 'wp-secmon: ' . I18n::t("not running as root, cannot switch to '%s'", $user) . "\n");
            return self::REFUSED;
        }
        $why = self::refusal($pw, $this->forbiddenGroups) ?? ($siteRoot !== '' ? self::unsafePath($siteRoot, $pw) : null);
        if ($why !== null) {
            file_put_contents($stderr, 'wp-secmon: ' . I18n::t("refusing to run as '%s': %s", $user, $why) . "\n");
            return self::REFUSED;
        }

        $env = [
            'HOME' => $pw['home'] !== '' ? $pw['home'] : '/',
            'USER' => $pw['name'],
            'LOGNAME' => $pw['name'],
            'SHELL' => '/bin/sh',
            'PATH' => $this->userPath,
            'LC_ALL' => 'C',
            // Ignore the user's ~/.wp-cli/config.yml (it can "require" PHP files).
            'WP_CLI_CONFIG_PATH' => '/dev/null',
            'WP_CLI_DISABLE_AUTO_CHECK_UPDATE' => '1',
        ];

        // env -i K=V... prlimit ... timeout ... cmd: survives wrappers (sudo) that reset the environment.
        $inner = $cmd;
        if ($this->timeoutBin !== null) {
            $inner = array_merge([$this->timeoutBin, '-k', '10', (string) $timeout], $inner);
        }
        // Output goes to root-owned files, which the account's disk quota does not cover.
        if ($this->prlimit !== null) {
            $inner = array_merge([$this->prlimit, '--fsize=' . $this->maxOutput, '--'], $inner);
        }
        if ($this->env !== null) {
            $kv = [];
            foreach ($env as $k => $v) {
                $kv[] = "$k=$v";
            }
            $inner = array_merge([$this->env, '-i'], $kv, $inner);
        }

        switch ($this->method) {
            case 'setpriv':
                $argv = array_merge([Util::which('setpriv'), '--reuid=' . $pw['uid'], '--regid=' . $pw['gid'], '--init-groups', '--no-new-privs', '--'], $inner);
                break;
            case 'runuser':
                $argv = array_merge([Util::which('runuser'), '-u', $pw['name'], '--'], $inner);
                break;
            case 'sudo':
                $argv = array_merge([Util::which('sudo'), '-n', '-u', $pw['name'], '--'], $inner);
                break;
            case 'su':
                $argv = array_merge([Util::which('su'), '-s', '/bin/sh', '-c', 'exec "$@"', $pw['name'], 'sh'], $inner);
                break;
            case 'cagefs':
                $argv = array_merge([Util::which('cagefs_enter_user'), $pw['name']], $inner);
                break;
            default:
                $argv = $inner;
        }

        return Proc::run(array_merge($this->setsid, $argv), $stdout, $stderr, $timeout + 30, $env);
    }
}
