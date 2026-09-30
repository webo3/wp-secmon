<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Hashes the files wp-secmon watches and lists executable files in uploads.
 *
 * Runs as the site owner (never root) through the hidden `wp-secmon __scan-files`
 * and `__read-file` commands, and does not load WordPress.
 */
final class FileScanner
{
    private const MAX_UPLOAD_HITS = 2000;
    /** Largest PHP file in uploads read whole to check that it only returns a value (see inert). */
    private const MAX_INERT = 4194304;
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

    /**
     * One file to review (see Review): its size, sha256 and first $max bytes, from a single read,
     * so that what is shown is what gets accepted. Symbolic links are not followed.
     * @return array{size?: int, mtime?: int, sha256?: ?string, link?: ?string, head?: string, truncated?: bool, error?: string}
     *         error: missing, unreadable or changed (replaced while being opened)
     */
    public static function read(string $path, int $max = 65536): array
    {
        $st = @lstat($path);
        if ($st === false) {
            return ['error' => 'missing'];
        }
        if (is_link($path)) {
            return ['size' => $st['size'], 'mtime' => $st['mtime'], 'sha256' => null, 'link' => (string) @readlink($path),
                'head' => '', 'truncated' => false];
        }
        $fh = is_file($path) ? @fopen($path, 'rb') : false;
        if ($fh === false) {
            return ['error' => 'unreadable'];
        }
        $fst = fstat($fh);
        if ($fst === false || $fst['ino'] !== $st['ino'] || $fst['dev'] !== $st['dev']) {
            fclose($fh);
            return ['error' => 'changed'];
        }
        $hash = hash_init('sha256');
        $head = '';
        $size = 0;
        while (!feof($fh)) {
            $chunk = @fread($fh, 65536);
            if ($chunk === false) {
                fclose($fh);
                return ['error' => 'unreadable'];
            }
            hash_update($hash, $chunk);
            $size += strlen($chunk);
            if (strlen($head) < $max) {
                $head .= substr($chunk, 0, $max - strlen($head));
            }
        }
        fclose($fh);
        return ['size' => $size, 'mtime' => $st['mtime'], 'sha256' => hash_final($hash), 'link' => null,
            'head' => $head, 'truncated' => $size > strlen($head)];
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

    /** "Silence is golden" stubs, files plugins generate (see GENERATED) and PHP files that cannot run code (see inert). */
    private static function benign(string $path, string $inUploads, int $size): bool
    {
        if ($size <= 256 && strtolower(basename($path)) === 'index.php') {
            $content = strtolower((string) preg_replace('/\s+/', '', (string) @file_get_contents($path)));
            if (in_array($content, self::SILENCE, true)) {
                return true;
            }
        }
        foreach (self::GENERATED as $where => $head) {
            if (preg_match($where, $inUploads) && preg_match($head, (string) @file_get_contents($path, false, null, 0, 8192))) {
                return true;
            }
        }
        if (!preg_match('/\.php$/i', $inUploads)) {
            return false;
        }
        // An exit comes first, so the start of the file is enough; a returned value is checked whole.
        $code = (string) @file_get_contents($path, false, null, 0, 65536);
        if (self::inert($code, strlen($code) < 65536)) {
            return true;
        }
        if (strlen($code) < 65536 || $size > self::MAX_INERT) {
            return false;
        }
        $code = (string) @file_get_contents($path, false, null, 0, self::MAX_INERT + 1);
        return self::inert($code, strlen($code) <= self::MAX_INERT);
    }

    /**
     * PHP that cannot run anything, whether requested or included, whatever its path:
     * - an unconditional exit before any other statement, the rest being data
     *   (Sucuri keeps its logs and settings this way);
     * - "return" of a literal value (arrays, strings, numbers, true/false/null)
     *   and nothing else (dompdf caches font metrics as var_export() output).
     * Read with PHP's own tokenizer, so that comments and "?>" end where PHP ends them.
     * @param bool $complete false when $code is only the start of the file
     */
    public static function inert(string $code, bool $complete): bool
    {
        // The file must start with the tag: text before it could hide short tags ("<?") that this PHP ignores.
        if (!function_exists('token_get_all') || !preg_match('/^<\?php\s/i', $code)) {
            return false;
        }
        try {
            $all = @token_get_all($code);
        } catch (\Throwable $e) {
            return false;
        }
        $t = [];
        foreach ($all as $tok) {
            if (!is_array($tok) || !in_array($tok[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $t[] = is_array($tok) ? $tok : [$tok, $tok];
            }
        }
        if (($t[0][0] ?? null) !== T_OPEN_TAG || !isset($t[1])) {
            return false;
        }
        $end = [';', T_CLOSE_TAG];

        // exit, exit(), exit(0), exit('text'), die... then ";" or a closing tag.
        if ($t[1][0] === T_EXIT) {
            $i = 2;
            if (($t[$i][0] ?? null) === '(') {
                $i++;
                if (in_array($t[$i][0] ?? null, [T_LNUMBER, T_CONSTANT_ENCAPSED_STRING], true)) {
                    $i++;
                }
                if (($t[$i][0] ?? null) !== ')') {
                    return false;
                }
                $i++;
            }
            return in_array($t[$i][0] ?? null, $end, true);
        }

        // return <literal>; and nothing after it.
        if ($t[1][0] !== T_RETURN || !$complete) {
            return false;
        }
        $constants = ['true', 'false', 'null', 'inf', 'nan'];
        $depth = 0;
        for ($i = 2; $i < count($t); $i++) {
            [$id, $text] = $t[$i];
            if ($id === ';' && $depth === 0) {
                $rest = array_slice($t, $i + 1);
                return $rest === [] || ($rest[0][0] === T_CLOSE_TAG && (count($rest) === 1
                    || (count($rest) === 2 && $rest[1][0] === T_INLINE_HTML && trim($rest[1][1]) === '')));
            }
            if ($id === '(' || $id === '[') {
                // "(" only opens array(...): anywhere else it could call a function.
                if ($id === '(' && $t[$i - 1][0] !== T_ARRAY) {
                    return false;
                }
                $depth++;
            } elseif ($id === ')' || $id === ']') {
                if (--$depth < 0) {
                    return false;
                }
            } elseif ($id === T_ARRAY) {
                if (($t[$i + 1][0] ?? null) !== '(') {
                    return false;
                }
            } elseif ($id === T_STRING) {
                if (!in_array(strtolower($text), $constants, true)) {
                    return false;
                }
            } elseif (!in_array($id, [T_LNUMBER, T_DNUMBER, T_CONSTANT_ENCAPSED_STRING, T_DOUBLE_ARROW, ',', '-', '+', '.'], true)) {
                return false;
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
