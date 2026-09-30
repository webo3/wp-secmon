<?php

declare(strict_types=1);

namespace WpSecMon;

final class Util
{
    private const SYSTEM_PATH = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];

    /** Path of a bundled file (works from the source tree and from the phar). */
    public static function resource(string $path): string
    {
        return dirname(__DIR__) . '/resources/' . $path;
    }

    /**
     * The wp-secmon executable itself: the phar when running from one, else
     * bin/wp-secmon. Site owners run it for the file scan, so it must stay
     * root-owned and not writable by anyone else.
     */
    public static function entry(): string
    {
        $phar = class_exists('Phar') ? \Phar::running(false) : '';
        return $phar !== '' ? $phar : (string) realpath(dirname(__DIR__) . '/bin/wp-secmon');
    }

    /** Control characters, including C1 controls encoded in UTF-8 (U+0080-U+009F, which some terminals obey). */
    public const CONTROL = '[\x00-\x1F\x7F]|\xC2[\x80-\x9F]';

    /** One line of plain text: control characters become spaces. */
    public static function oneLine(string $s, int $max = 300): string
    {
        $s = (string) preg_replace('/' . self::CONTROL . '/', ' ', $s);
        return strlen($s) > $max ? substr($s, 0, $max - 3) . '...' : $s;
    }

    /** Width of $s in characters (UTF-8). */
    public static function width(string $s): int
    {
        return (int) preg_match_all('/./us', $s) ?: strlen($s);
    }

    /** Upper case, accented letters included (mbstring is not always installed). */
    public static function upper(string $s): string
    {
        if (function_exists('mb_strtoupper')) {
            return mb_strtoupper($s, 'UTF-8');
        }
        return strtoupper(strtr($s, ['à' => 'À', 'â' => 'Â', 'ç' => 'Ç', 'é' => 'É', 'è' => 'È', 'ê' => 'Ê', 'ë' => 'Ë',
            'î' => 'Î', 'ï' => 'Ï', 'ô' => 'Ô', 'ù' => 'Ù', 'û' => 'Û', 'ü' => 'Ü']));
    }

    /** Multi-line plain text: drops control characters except tab and newline. */
    public static function text(string $s): string
    {
        return (string) preg_replace('/[\x00-\x08\x0B-\x1F\x7F]|\xC2[\x80-\x9F]/', '', $s);
    }

    /** Last lines of command output, sanitized and indented for a report. */
    public static function tail(string $s, int $lines = 5): string
    {
        $all = preg_split('/\R/', trim($s)) ?: [];
        $out = [];
        foreach (array_slice($all, -$lines) as $line) {
            if ($line !== '') {
                $out[] = '    ' . self::oneLine($line);
            }
        }
        return implode("\n", $out);
    }

    /** Indented "label: item" list capped at $max entries. */
    public static function listBlock(string $label, array $items, int $max = 40): array
    {
        $out = [];
        foreach (array_slice($items, 0, $max) as $item) {
            $out[] = '    ' . ($label !== '' ? $label . ': ' : '') . self::oneLine((string) $item);
        }
        if (count($items) > $max) {
            $out[] = '    ' . I18n::t('... and %d more', count($items) - $max);
        }
        return $out;
    }

    /** True if $value matches one of the shell globs ("*" also matches "/"). */
    public static function matchAny(string $value, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if ($pattern !== '' && fnmatch($pattern, $value)) {
                return true;
            }
        }
        return false;
    }

    /** Absolute path of a system binary, or null. */
    public static function which(string $name): ?string
    {
        foreach (self::SYSTEM_PATH as $dir) {
            if (is_file("$dir/$name") && is_executable("$dir/$name")) {
                return "$dir/$name";
            }
        }
        return null;
    }

    /** The last line of $output that is a JSON array or object (WP-CLI output can be preceded by PHP notices). */
    public static function jsonLine(string $output, string $prefix = ''): ?array
    {
        $lines = preg_split('/\R/', $output) ?: [];
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $line = trim($lines[$i]);
            if ($prefix !== '') {
                if (strncmp($line, $prefix, strlen($prefix)) !== 0) {
                    continue;
                }
                $line = substr($line, strlen($prefix));
            }
            if ($line === '' || ($line[0] !== '[' && $line[0] !== '{')) {
                continue;
            }
            $data = json_decode($line, true);
            if (is_array($data)) {
                return $data;
            }
        }
        return null;
    }

    public static function json($data): string
    {
        return (string) json_encode(
            $data,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRETTY_PRINT
        );
    }

    public static function readJson(string $file): ?array
    {
        if (!is_file($file)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($file), true);
        return is_array($data) ? $data : null;
    }

    public static function writeJson(string $file, $data): void
    {
        self::writeFile($file, self::json($data) . "\n");
    }

    /** Atomic write of a root-only file. */
    public static function writeFile(string $file, string $content): void
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $tmp = $file . '.tmp' . getmypid();
        file_put_contents($tmp, $content);
        chmod($tmp, 0600);
        rename($tmp, $file);
    }

    public static function mkdir(string $dir, int $mode = 0700): void
    {
        if (!is_dir($dir) && !@mkdir($dir, $mode, true) && !is_dir($dir)) {
            throw new \RuntimeException(I18n::t('cannot create directory %s', $dir));
        }
    }

    public static function rmTree(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
            @unlink($dir);
            return;
        }
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::rmTree("$dir/$entry");
            }
        }
        @rmdir($dir);
    }

    public static function effectiveUid(): int
    {
        if (function_exists('posix_geteuid')) {
            return posix_geteuid();
        }
        $status = @file_get_contents('/proc/self/status');
        if ($status !== false && preg_match('/^Uid:\s+\d+\s+(\d+)/m', $status, $m)) {
            return (int) $m[1];
        }
        return -1;
    }

    /**
     * passwd entry for a user name or uid: [name, uid, gid, home] or null.
     * Uses posix when available, getent otherwise (php-process is not always installed).
     */
    public static function passwd($who): ?array
    {
        if (function_exists('posix_getpwnam')) {
            $pw = is_int($who) ? posix_getpwuid($who) : posix_getpwnam($who);
            return $pw ? ['name' => $pw['name'], 'uid' => $pw['uid'], 'gid' => $pw['gid'], 'home' => $pw['dir']] : null;
        }
        $getent = self::which('getent');
        if ($getent === null) {
            return null;
        }
        [$code, $out] = Proc::capture([$getent, 'passwd', (string) $who], 10);
        $f = explode(':', trim($out));
        if ($code !== 0 || count($f) < 7) {
            return null;
        }
        return ['name' => $f[0], 'uid' => (int) $f[2], 'gid' => (int) $f[3], 'home' => $f[5]];
    }

    /** gid of a group name, or null. Uses posix when available, getent otherwise. */
    public static function groupId(string $name): ?int
    {
        if (function_exists('posix_getgrnam')) {
            $gr = posix_getgrnam($name);
            return $gr ? (int) $gr['gid'] : null;
        }
        $getent = self::which('getent');
        if ($getent === null) {
            return null;
        }
        [$code, $out] = Proc::capture([$getent, 'group', $name], 10);
        $f = explode(':', trim($out));
        return $code === 0 && count($f) >= 3 ? (int) $f[2] : null;
    }

    /** Null when $path is owned by root and not group/world writable, else the problem. */
    public static function rootOnlyProblem(string $path): ?string
    {
        $st = @stat($path);
        if ($st === false) {
            return I18n::t('cannot stat %s', $path);
        }
        if ($st['uid'] !== 0 || ($st['mode'] & 0022)) {
            return I18n::t('%s must be owned by root and not group/world writable (uid %d, mode %o)', $path, $st['uid'], $st['mode'] & 0777);
        }
        return null;
    }

    public static function hostname(): string
    {
        $h = function_exists('gethostname') ? (string) gethostname() : '';
        return $h !== '' ? $h : php_uname('n');
    }
}
