<?php

declare(strict_types=1);

namespace WpSecMon;

use WpSecMon\Check\IntegrityCheck;

/**
 * wp-secmon review: goes through the executable files the last integrity check
 * found in uploads, and records the ones the admin accepts with their sha256.
 * The integrity check stops reporting an accepted file until its content changes.
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
            self::say(I18n::t("The next integrity check takes this into account (hourly, or now with 'wp-secmon integrity')."));
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
            $path = (string) ($found[$rel]['path'] ?? '');
            $file = $this->read($site, $path, self::PREVIEW_BYTES);
            if (is_string($file)) {
                self::say('  ' . $file);
                continue;
            }
            if ($folder === dirname($rel)) {
                $this->decide($site, $rel, $file);
                self::say('  ' . I18n::t('accepted with the rest of its folder'));
                continue;
            }
            $was = $accepted[$rel] ?? null;
            $this->about($file, $was);
            $this->content($file, false);
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
                    $this->decide($site, $rel, $file);
                    self::say('  ' . I18n::t('accepted'));
                    $folder = $answer === 'a' ? dirname($rel) : $folder;
                } elseif ($answer === 'n' && $was !== null) {
                    $this->decide($site, $rel, null);
                    self::say('  ' . I18n::t('no longer accepted: it will be reported again'));
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

    /** Size, sha256, date, and when it was accepted. */
    private function about(array $file, ?array $was): void
    {
        $about = $file['link'] !== null ? I18n::t('symbolic link to %s', Util::oneLine((string) $file['link']))
            : I18n::n((int) $file['size'], '%d byte', '%d bytes', (int) $file['size']) . ', sha256 ' . $file['sha256'];
        self::say('  ' . I18n::t('%s, modified %s', $about, date('Y-m-d H:i', (int) $file['mtime'])));
        if ($was !== null) {
            $on = date('Y-m-d H:i', (int) ($was['accepted'] ?? 0));
            self::say('  ' . (($was['hash'] ?? '') === IntegrityCheck::fileHash($file)
                ? I18n::t('accepted on %s', $on) : I18n::t('accepted on %s, changed since', $on)));
        }
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

    /** Records the decision on $rel at once, so that quitting keeps it: accepted as $file, or not accepted (null). */
    private function decide(Site $site, string $rel, ?array $file): void
    {
        $dir = $this->dir($site);
        $accepted = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_ACCEPTED) ?? [];
        if ($file === null) {
            unset($accepted[$rel]);
            $this->withdrawn++;
        } else {
            $accepted[$rel] = ['hash' => IntegrityCheck::fileHash($file), 'size' => (int) $file['size'], 'accepted' => time()];
            $this->accepted++;
        }
        // Files gone at the last check are forgotten, unless that scan stopped early.
        $found = Util::readJson("$dir/" . IntegrityCheck::UPLOADS_FOUND);
        if ($found !== null && empty($found['truncated'])) {
            $accepted = array_intersect_key($accepted, $found['files'] ?? []);
        }
        ksort($accepted);
        Util::writeJson("$dir/" . IntegrityCheck::UPLOADS_ACCEPTED, $accepted);
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
