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
    /** Largest PHP file in uploads read whole to check that it only returns a value (see inert) or is a Twig template (see twigTemplate). */
    private const MAX_INERT = 4194304;
    /** Largest wp-config.php taken apart into its constants (see constants). */
    private const MAX_CONFIG = 1048576;
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
     * Twig template caches inside uploads (path relative to uploads), laid out as <2 hex>/<same 2 hex><rest of the hash>.php
     * (WPML: cache/wpml/twig, MailPoet: mailpoet/cache and mailpoet-premium/cache). Their files must also be templates (see twigTemplate).
     * Kept narrow on purpose: web shells are often dropped in cache folders, so "cache/*" is not excluded as a whole.
     */
    private const TWIG_CACHE = '#^(?:cache/[\w-]+/twig|mailpoet(?:-premium)?/cache)/([0-9a-f]{2})/\1[0-9a-f]{30}(?:[0-9a-f]{32})?\.php$#';

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
        } elseif ($area === 'config' || ($area === 'root' && basename($path) === 'wp-config.php')) {
            // Read once, so that the constants are those of the content hashed.
            $code = $st['size'] <= self::MAX_CONFIG ? @file_get_contents($path, false, null, 0, self::MAX_CONFIG + 1) : false;
            if ($code !== false && strlen($code) <= self::MAX_CONFIG) {
                $e['sha256'] = hash('sha256', $code);
                $e['constants'] = self::constants($code);
            } else {
                $hash = @hash_file('sha256', $path);
                $e['sha256'] = $hash === false ? 'unreadable' : $hash;
            }
        } else {
            $hash = @hash_file('sha256', $path);
            $e['sha256'] = $hash === false ? 'unreadable' : $hash;
            if ($inUploads !== null) {
                $e['benign'] = self::benign($path, $inUploads, (int) $st['size']);
            }
        }
        $this->out['entries'][] = $e;
    }

    /** "Silence is golden" stubs, Twig template caches (see TWIG_CACHE) and PHP files that cannot run code (see inert). */
    private static function benign(string $path, string $inUploads, int $size): bool
    {
        if ($size <= 256 && strtolower(basename($path)) === 'index.php') {
            $content = strtolower((string) preg_replace('/\s+/', '', (string) @file_get_contents($path)));
            if (in_array($content, self::SILENCE, true)) {
                return true;
            }
        }
        if (preg_match(self::TWIG_CACHE, $inUploads) && $size <= self::MAX_INERT) {
            $code = (string) @file_get_contents($path, false, null, 0, self::MAX_INERT + 1);
            if (strlen($code) <= self::MAX_INERT && self::twigTemplate($code)) {
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
     * A whole compiled Twig template: namespace/use statements and comments, the template's class (see TWIG_TEMPLATE),
     * and nothing after it. Requested, the file only declares a class: its code runs when Twig renders the template.
     * Read with PHP's own tokenizer, so that strings and comments cannot hide where the class ends.
     */
    public static function twigTemplate(string $code): bool
    {
        if (!function_exists('token_get_all') || !preg_match(self::TWIG_TEMPLATE, $code)) {
            return false;
        }
        try {
            $all = @token_get_all($code);
        } catch (\Throwable $e) {
            return false;
        }
        // Nothing but use statements and comments comes before the class (TWIG_TEMPLATE): its "{" is the first one.
        $depth = 0;
        $closed = false;
        foreach (array_slice($all, 1) as $tok) {
            $id = is_array($tok) ? $tok[0] : $tok;
            if (in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            // Code after the class, or text out of PHP, would run when the file is requested.
            if ($closed || in_array($id, [T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO, T_CLOSE_TAG, T_INLINE_HTML], true)) {
                return false;
            }
            if ($id === '{' || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
                $depth++;
            } elseif ($id === '}') {
                $closed = --$depth === 0;
            }
        }
        return $closed;
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

    /**
     * Fingerprint of a wp-config.php that tells which constants changed, without their values:
     * - code: the file with the value of each plain define() blanked;
     * - other: the file without its plain define() statements;
     * - values: name => sha256 of its value, in the order of the file.
     * A plain define() is a statement define('NAME', <one literal>). code and other are hashed
     * from the tokens, without blank space and comments, which cannot run anything. Null when
     * the file cannot be taken apart: without the tokenizer, or with a namespace or a "use",
     * which could make define() call a function of the file.
     * @return array{code: string, other: string, values: array<string, string>}|null
     */
    public static function constants(string $code): ?array
    {
        if (!function_exists('token_get_all')) {
            return null;
        }
        try {
            $all = @token_get_all($code);
        } catch (\Throwable $e) {
            return null;
        }
        $t = [];
        foreach ($all as $tok) {
            if (!is_array($tok)) {
                $t[] = [$tok, $tok];
            } elseif (in_array($tok[0], [T_NAMESPACE, T_USE], true)) {
                return null;
            } elseif (in_array($tok[0], [T_OPEN_TAG, T_CLOSE_TAG], true)) {
                $t[] = [$tok[0], trim($tok[1])];
            } elseif (!in_array($tok[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $t[] = [$tok[0], $tok[1]];
            }
        }
        $literal = static function (array $tok): bool {
            return in_array($tok[0], [T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER], true)
                || ($tok[0] === T_STRING && in_array(strtolower($tok[1]), ['true', 'false', 'null'], true));
        };
        $blank = $drop = $values = [];
        foreach ($t as $i => [$id, $text]) {
            // define ( 'NAME' , <literal> ) ; as a statement of its own: not a method, a declaration...
            if ($id !== T_STRING || strtolower($text) !== 'define'
                || !in_array($i > 0 ? $t[$i - 1][0] : T_OPEN_TAG, [';', '{', '}', ')', ':', T_OPEN_TAG, T_ELSE], true)
                || ($t[$i + 1][0] ?? null) !== '(' || ($t[$i + 2][0] ?? null) !== T_CONSTANT_ENCAPSED_STRING
                || ($t[$i + 3][0] ?? null) !== ',' || !isset($t[$i + 4]) || !$literal($t[$i + 4])
                || ($t[$i + 5][0] ?? null) !== ')' || !in_array($t[$i + 6][0] ?? null, [';', T_CLOSE_TAG], true)) {
                continue;
            }
            $name = substr($t[$i + 2][1], 1, -1);
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $name)) {
                continue;
            }
            $values[$name][] = $t[$i + 4][1];
            $blank[$i + 4] = true;
            // A closing tag ends the statement but stays: it leaves PHP.
            for ($j = $i, $end = $t[$i + 6][0] === ';' ? $i + 6 : $i + 5; $j <= $end; $j++) {
                $drop[$j] = true;
            }
        }
        $blanked = $other = [];
        foreach ($t as $i => [, $text]) {
            $blanked[] = isset($blank[$i]) ? "''" : $text;
            if (!isset($drop[$i])) {
                $other[] = $text;
            }
        }
        // serialize(): tokens may hold any byte, so no separator would be unambiguous.
        $hashes = [];
        foreach ($values as $name => $list) {
            $hashes[$name] = hash('sha256', serialize($list));
        }
        return ['code' => hash('sha256', serialize($blanked)), 'other' => hash('sha256', serialize($other)), 'values' => $hashes];
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
