<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Hashes the files wp-secmon watches and lists executable files in uploads.
 *
 * Runs as the site owner (never root) through the hidden `wp-secmon __scan-files`
 * command, and does not load WordPress.
 */
final class FileScanner
{
    private const MAX_UPLOAD_HITS = 2000;
    private const PHP_LIKE = '/\.(php\d?|phtml|pht|phar|phps|inc)$/i';
    private const UPLOAD_EXEC = '/\.(php\d?|phtml|pht|phar|phps|shtml|cgi|pl|py|sh)$|\.(php\d?|phtml|pht|phar)\./i';
    private const SERVER_CONFIG = ['.htaccess', '.user.ini', 'php.ini'];

    /** Contents (whitespace removed, lower case) of harmless "Silence is golden" stubs. */
    private const SILENCE = [
        '', '<?php', '<?php?>', '<?php//silenceisgolden', '<?php//silenceisgolden.', '<?php//silenceisgolden?>',
        '<?php//silenceisgolden.?>', '<?php/*silenceisgolden*/', '<?php/*silenceisgolden.*/', '<?php#silenceisgolden',
        '<?php#silenceisgolden.',
    ];

    /** Start of a compiled Twig template: nothing but namespace/use statements and comments before the class. */
    private const TWIG_TEMPLATE = '#^<\?php\s+(?:(?:namespace|use)\s+[\w\\\\]+(?:\s+as\s+\w+)?\s*;\s*|/\*(?:[^*]|\*(?!/))*\*/\s*)*'
        . 'class\s+__TwigTemplate_[0-9a-f]{32,64}\w*\s+extends\s+[\w\\\\]+\s*\{#';

    /**
     * PHP that plugins generate inside uploads: path relative to uploads => regex the start of the file must match.
     * Kept narrow on purpose: web shells are often dropped in cache folders, so "cache/*" is not excluded as a whole.
     */
    private const GENERATED = [
        // Twig template cache, laid out as <2 hex>/<same 2 hex><rest of the hash>.php (WPML: cache/wpml/twig).
        '#^cache/[\w-]+/twig/([0-9a-f]{2})/\1[0-9a-f]{30}(?:[0-9a-f]{32})?\.php$#' => self::TWIG_TEMPLATE,
    ];

    private array $out = ['entries' => [], 'truncated' => false, 'errors' => []];

    /**
     * @param array{root: string, content?: string, mu?: string, uploads?: string, config?: string} $in
     * @return array{entries: array, truncated: bool, errors: string[]}
     */
    public static function scan(array $in): array
    {
        return (new self())->run($in);
    }

    private function run(array $in): array
    {
        $s = $this;
        $root = rtrim((string) $in['root'], '/');
        $s->shallow('root', $root);

        $content = (string) ($in['content'] ?? '');
        if ($content !== '' && is_dir($content)) {
            $s->shallow('content', $content);
        }

        $mu = (string) ($in['mu'] ?? '');
        if ($mu !== '' && is_dir($mu)) {
            $s->walk($mu, function (string $path): bool {
                $this->entry('mu', $path);
                return true;
            });
        }

        $uploads = (string) ($in['uploads'] ?? '');
        if ($uploads !== '' && is_dir($uploads)) {
            $hits = 0;
            $s->walk($uploads, function (string $path) use (&$hits, $uploads): bool {
                $name = basename($path);
                if (!preg_match(self::UPLOAD_EXEC, $name) && !in_array($name, self::SERVER_CONFIG, true)) {
                    return true;
                }
                if (++$hits > self::MAX_UPLOAD_HITS) {
                    $this->out['truncated'] = true;
                    return false;
                }
                $this->entry('uploads', $path, substr($path, strlen($uploads) + 1));
                return true;
            });
        }

        $config = (string) ($in['config'] ?? '');
        if ($config !== '' && strpos($config, $root . '/') !== 0) {
            $s->entry('config', $config);
        }
        return $s->out;
    }

    /** @param string|null $inUploads path relative to uploads: harmless files there are flagged "benign" */
    private function entry(string $area, string $path, ?string $inUploads = null): void
    {
        $st = @lstat($path);
        if ($st === false) {
            return;
        }
        $e = ['area' => $area, 'path' => $path, 'size' => $st['size'], 'sha256' => null, 'link' => null, 'benign' => false];
        if (is_link($path)) {
            $e['link'] = (string) @readlink($path);
        } else {
            $hash = @hash_file('sha256', $path);
            $e['sha256'] = $hash === false ? 'unreadable' : $hash;
            if ($inUploads !== null) {
                $e['benign'] = self::benign($path, $inUploads, (int) $st['size']);
            }
        }
        $this->out['entries'][] = $e;
    }

    /** "Silence is golden" stubs and files plugins generate (see GENERATED). */
    private static function benign(string $path, string $inUploads, int $size): bool
    {
        if ($size <= 256 && strtolower(basename($path)) === 'index.php') {
            $content = strtolower((string) preg_replace('/\s+/', '', (string) @file_get_contents($path)));
            return in_array($content, self::SILENCE, true);
        }
        foreach (self::GENERATED as $where => $head) {
            if (preg_match($where, $inUploads)) {
                return (bool) preg_match($head, (string) @file_get_contents($path, false, null, 0, 8192));
            }
        }
        return false;
    }

    /** Files directly in $dir that are PHP-like or server configuration. */
    private function shallow(string $area, string $dir): void
    {
        $names = @scandir($dir);
        if ($names === false) {
            $this->out['errors'][] = "cannot read $dir";
            return;
        }
        foreach ($names as $name) {
            $path = "$dir/$name";
            if ($name === '.' || $name === '..' || (is_dir($path) && !is_link($path))) {
                continue;
            }
            if (preg_match(self::PHP_LIKE, $name) || in_array($name, self::SERVER_CONFIG, true)) {
                $this->entry($area, $path);
            }
        }
    }

    /** Recursive walk; symlinked directories are not followed. */
    private function walk(string $dir, callable $visit): void
    {
        try {
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_PATHNAME),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($it as $path) {
                if ($visit((string) $path) === false) {
                    break;
                }
            }
        } catch (\Throwable $e) {
            $this->out['errors'][] = "cannot walk $dir: " . $e->getMessage();
        }
    }
}
