<?php

declare(strict_types=1);

namespace WpSecMon;

use WpSecMon\Check\IntegrityCheck;

/**
 * wp-secmon review: goes through the executable files the last integrity check
 * found in uploads, and records the ones the admin accepts with their sha256.
 * The integrity check stops reporting the files of the site that have an accepted
 * content (see IntegrityCheck::acceptedContent): a file is reported again once it
 * changes, unless its new content is accepted too.
 *
 * Files are read as the site owner (FileScanner::read), never as root, and the
 * sha256 accepted is the one of the content shown.
 */
final class Review
{
    /** Lines shown before asking, out of the first PREVIEW_BYTES; "c" shows up to CAT_BYTES. */
    private const PREVIEW_LINES = 15;
    private const PREVIEW_BYTES = 65536;
    private const CAT_BYTES = 4194304;

    private Context $ctx;
    /** @var resource */
    private $in;
    private int $accepted = 0;
    private int $withdrawn = 0;
    /**
     * @var array<string, string> content accepted once it was shown, on any site: hash => path. The files with the
     * same content are accepted with it; not symbolic links (see IntegrityCheck::acceptedContent).
     */
    private array $same = [];
    /** @var array<string, int> files still to go through, by hash at the last check */
    private array $left = [];

    /** @param resource $in where the answers come from */
    public function __construct(Context $ctx, $in)
    {
        $this->ctx = $ctx;
        $this->in = $in;
    }

    /**
     * @param Site[] $sites
     * @param bool $all also go through the files accepted before (answer n to have them reported again)
     */
    public function run(array $sites, bool $all): int
    {
        $queue = [];
        foreach ($sites as $site) {
            $dir = $this->dir($site);
            $found = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_FOUND)['files'] ?? [];
            $accepted = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_ACCEPTED) ?? [];
            $files = array_map('strval', array_keys($all ? $found : IntegrityCheck::pendingUploads($found, $accepted)));
            if ($files) {
                $queue[] = [$site, $files, $found, $accepted];
            }
            foreach ($files as $rel) {
                $hash = (string) ($found[$rel]['hash'] ?? '');
                $this->left[$hash] = ($this->left[$hash] ?? 0) + 1;
            }
        }
        if (!$queue) {
            self::say(I18n::t('Nothing to review: the last integrity check found no executable file to accept in uploads.'));
            return 0;
        }
        foreach ($queue as [$site, $files, $found, $accepted]) {
            if (!$this->site($site, $files, $found, $accepted)) {
                break;
            }
        }
        if ($this->accepted + $this->withdrawn > 0) {
            self::say("\n" . I18n::n($this->accepted, '%d file accepted', '%d files accepted', $this->accepted) . ', '
                . I18n::n($this->withdrawn, '%d no longer accepted', '%d no longer accepted', $this->withdrawn) . '.');
            // An account's decisions stay in its own state (see Config::forAccount).
            self::say(Util::effectiveUid() === 0
                ? I18n::t("The next integrity check takes this into account (hourly, or now with 'wp-secmon integrity').")
                : I18n::t("Your next 'wp-secmon integrity' takes this into account. The server's own checks still report these files to its administrator."));
        }
        return 0;
    }

    /** @return bool false when the admin quits */
    private function site(Site $site, array $files, array $found, array $accepted): bool
    {
        self::say("\n" . I18n::n(count($files), '%s (read as %s): %d file to review', '%s (read as %s): %d files to review',
            $site->root, $site->user, count($files)));
        $folder = null;
        foreach ($files as $i => $rel) {
            self::say(sprintf("\n[%d/%d] %s", $i + 1, count($files), Util::oneLine($rel)));
            $this->left[(string) ($found[$rel]['hash'] ?? '')]--;
            $path = (string) ($found[$rel]['path'] ?? '');
            $file = $this->read($site, $path, self::PREVIEW_BYTES);
            if (is_string($file)) {
                self::say('  ' . $file);
                continue;
            }
            if ($folder === dirname($rel)) {
                $accepted = $this->decide($site, $rel, $file, true);
                self::say('  ' . I18n::t('accepted with the rest of its folder'));
                continue;
            }
            $hash = IntegrityCheck::fileHash($file);
            if (isset($this->same[$hash])) {
                // Relative to this site when it is one of its files, in full when it is another site's.
                $from = $this->same[$hash];
                $from = strpos($from, $site->root . '/') === 0 ? substr($from, strlen($site->root) + 1) : $from;
                $accepted = $this->decide($site, $rel, $file, true);
                self::say('  ' . I18n::t('accepted: same content as %s', Util::oneLine($from)));
                continue;
            }
            $was = self::acceptance($accepted, $rel, $hash);
            $this->about($file, $was);
            $this->content($file, false);
            $others = $file['link'] === null ? ($this->left[$hash] ?? 0) : 0;
            if ($others > 0) {
                self::say('  ' . I18n::n($others, '%d other file to review has the same content: accepting this one accepts it too',
                    '%d other files to review have the same content: accepting this one accepts them too', $others));
            }
            while (true) {
                $answer = $this->ask(I18n::t('Accept this file? [y]es, [n]o, [a]ll of this folder, [c]at the whole file, [q]uit, Enter: skip'));
                if ($answer === null || $answer === 'q') {
                    return false;
                }
                if ($answer === 'c') {
                    $file = $this->cat($site, $path, $file, $was);
                    continue;
                }
                if (in_array($answer, ['y', 'o', 'a'], true)) {
                    $accepted = $this->decide($site, $rel, $file, true);
                    self::say('  ' . I18n::t('accepted'));
                    $folder = $answer === 'a' ? dirname($rel) : $folder;
                    // $file is what was shown last ("c" reads it again).
                    if ($file['link'] === null) {
                        $this->same[IntegrityCheck::fileHash($file)] = $path;
                    }
                } elseif ($answer === 'n' && $was !== null) {
                    // Its content is no longer accepted for the other files of the site either.
                    $hash = IntegrityCheck::fileHash($file);
                    $others = 0;
                    if (isset(IntegrityCheck::acceptedContent($accepted)[$hash])) {
                        foreach ($found as $r => $f) {
                            $others += (string) $r !== $rel && ($f['hash'] ?? null) === $hash ? 1 : 0;
                        }
                    }
                    $accepted = $this->decide($site, $rel, $file, false);
                    self::say('  ' . ($others > 0 ? I18n::n($others, 'no longer accepted: it will be reported again, with %d other file with the same content',
                        'no longer accepted: it will be reported again, with %d other files with the same content', $others)
                        : I18n::t('no longer accepted: it will be reported again')));
                } elseif ($answer !== '' && $answer !== 'n') {
                    continue;
                }
                break;
            }
        }
        return true;
    }

    /** @return array|string the file as its owner reads it (FileScanner::read), or why it cannot be read */
    private function read(Site $site, string $path, int $max)
    {
        $r = $this->ctx->readFile($site, $path, $max);
        $file = $r->json();
        if ($file === null) {
            return I18n::t('cannot read it: %s', $r->reason());
        }
        switch ($file['error'] ?? null) {
            case null:
                return $file;
            case 'missing':
                return I18n::t('no longer there');
            case 'changed':
                return I18n::t('it changed while being read: review it again');
            default:
                return I18n::t("'%s' cannot read it", $site->user);
        }
    }

    /**
     * "c": the whole file, read again. What gets accepted is what was shown last,
     * so a version that changed since the preview replaces it.
     */
    private function cat(Site $site, string $path, array $file, ?array $was): array
    {
        $whole = $this->read($site, $path, self::CAT_BYTES);
        if (is_string($whole)) {
            self::say('  ' . $whole);
            return $file;
        }
        if (IntegrityCheck::fileHash($whole) !== IntegrityCheck::fileHash($file)) {
            self::say('  ' . I18n::t('it changed since it was shown; its current version:'));
            $this->about($whole, $was);
        }
        $this->content($whole, true);
        return $whole;
    }

    /** Size, sha256, date, and when it was accepted (see acceptance). */
    private function about(array $file, ?array $was): void
    {
        $about = $file['link'] !== null ? I18n::t('symbolic link to %s', Util::oneLine((string) $file['link']))
            : I18n::n((int) $file['size'], '%d byte', '%d bytes', (int) $file['size']) . ', sha256 ' . Util::oneLine((string) $file['sha256']);
        self::say('  ' . I18n::t('%s, modified %s', $about, date('Y-m-d H:i', (int) $file['mtime'])));
        if ($was === null) {
            return;
        }
        $on = date('Y-m-d H:i', (int) ($was['accepted'] ?? 0));
        $unchanged = ($was['hash'] ?? '') === IntegrityCheck::fileHash($file);
        if (!isset($was['same'])) {
            self::say('  ' . ($unchanged ? I18n::t('accepted on %s', $on) : I18n::t('accepted on %s, changed since', $on)));
        } elseif ($unchanged) {
            self::say('  ' . I18n::t('accepted on %s: same content as %s', $on, Util::oneLine((string) $was['same'])));
        }
    }

    /**
     * What a file's acceptance is (see IntegrityCheck::pendingUploads): its own, that of another file with
     * the same content ('same' => that file), or its own for a content it no longer has. Null when none.
     */
    private static function acceptance(array $accepted, string $rel, string $hash): ?array
    {
        $own = $accepted[$rel] ?? null;
        if (($own['hash'] ?? null) !== $hash && isset(IntegrityCheck::acceptedContent($accepted)[$hash])) {
            foreach ($accepted as $r => $a) {
                if (($a['hash'] ?? null) === $hash) {
                    return $a + ['same' => (string) $r];
                }
            }
        }
        return $own;
    }

    /** The first lines of the file, or all that was read ($whole). */
    private function content(array $file, bool $whole): void
    {
        if ($file['link'] !== null) {
            return;
        }
        $lines = self::preview((string) $file['head'], $whole ? 0 : 160);
        $shown = $whole ? $lines : array_slice($lines, 0, self::PREVIEW_LINES);
        foreach ($shown ?: [I18n::t('(empty)')] as $line) {
            self::say('  | ' . $line);
        }
        $more = count($lines) - count($shown);
        if ($whole) {
            if (!empty($file['truncated'])) {
                self::say('  ' . I18n::t('... only the first %d MB are shown', intdiv(self::CAT_BYTES, 1048576)));
            }
        } elseif (!empty($file['truncated'])) {
            self::say('  ' . I18n::t('... (c: cat the whole file)'));
        } elseif ($more > 0) {
            self::say('  ' . I18n::n($more, '... %d more line (c: cat the whole file)', '... %d more lines (c: cat the whole file)', $more));
        }
    }

    /**
     * Lines of a file for the terminal: control characters (escape sequences...)
     * neutralized, lines cut at $width characters (0: not cut). Binary files are not shown.
     * @return string[]
     */
    public static function preview(string $content, int $width): array
    {
        if (strpos($content, "\0") !== false) {
            return [I18n::t('(binary content, not shown)')];
        }
        $lines = $content === '' ? [] : preg_split('/\r?\n/', $content);
        if ($lines && end($lines) === '') {
            array_pop($lines);
        }
        return array_map(static function (string $line) use ($width): string {
            return rtrim(Util::oneLine($line, $width > 0 ? $width : strlen($line) + 1));
        }, $lines ?: []);
    }

    /**
     * Records the decision on $rel at once, so that quitting keeps it: accepted as $file, or no longer accepted,
     * its content with it (see IntegrityCheck::acceptedContent).
     * @return array the acceptances of the site now
     */
    private function decide(Site $site, string $rel, array $file, bool $accept): array
    {
        $dir = $this->dir($site);
        $accepted = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_ACCEPTED) ?? [];
        $hash = IntegrityCheck::fileHash($file);
        if ($accept) {
            $accepted[$rel] = ['hash' => $hash, 'size' => (int) $file['size'], 'accepted' => time()];
            $this->accepted++;
        } else {
            foreach ($accepted as $r => $a) {
                if ((string) $r === $rel || ($file['link'] === null && ($a['hash'] ?? null) === $hash)) {
                    unset($accepted[$r]);
                }
            }
            $this->withdrawn++;
        }
        // Files gone at the last check are forgotten, unless that scan stopped early or another file still has their content.
        $found = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_FOUND);
        if ($found !== null && empty($found['truncated'])) {
            $files = $found['files'] ?? [];
            $kept = array_intersect_key(IntegrityCheck::acceptedContent($accepted), array_flip(array_column($files, 'hash')));
            foreach ($accepted as $r => $a) {
                if (!isset($files[$r]) && !isset($kept[$a['hash'] ?? ''])) {
                    unset($accepted[$r]);
                }
            }
        }
        ksort($accepted);
        Util::writeJson("$dir/" . IntegrityCheck::UPLOADS_ACCEPTED, $accepted);
        return $accepted;
    }

    private function dir(Site $site): string
    {
        return $this->ctx->cfg->str('state_dir') . '/sites/' . $site->id;
    }

    /** The answer in lower case, or null at the end of the input. */
    private function ask(string $question): ?string
    {
        fwrite(STDOUT, $question . ' ');
        $line = fgets($this->in);
        if ($line === false) {
            fwrite(STDOUT, "\n");
            return null;
        }
        return strtolower(trim($line));
    }

    private static function say(string $text): void
    {
        fwrite(STDOUT, $text . "\n");
    }
}
