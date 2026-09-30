<?php

declare(strict_types=1);

namespace WpSecMon\Check;

use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Site;
use WpSecMon\Util;

/**
 * checksums: compare WordPress core and wordpress.org plugins with the
 * official checksums (`wp core verify-checksums`, `wp plugin verify-checksums`).
 * Plugins that are not hosted on wordpress.org cannot be verified and are
 * only logged.
 */
final class ChecksumsCheck extends Check
{
    public static function name(): string
    {
        return 'checksums';
    }

    protected function checkSite(Site $site): void
    {
        $this->core($site);
        $this->plugins($site);
    }

    private function core(Site $site): void
    {
        $alerts = $this->ctx->alerts;
        for ($attempt = 1; ; $attempt++) {
            $r = $this->ctx->wp->run($site, ['core', 'verify-checksums']);
            $parsed = self::parseCore($r->stdout . "\n" . $r->stderr, $this->ctx->cfg->list('core_checksum_ignore'));
            // One retry when api.wordpress.org could not be reached.
            if ($attempt > 1 || $parsed['error'] === null || !preg_match("/Failed to get url|cURL error|Couldn't get checksums/i", $parsed['error'])) {
                break;
            }
            Log::debug("{$site->root}: checksum download failed, retrying");
            sleep(5);
        }

        $found = count($parsed['modified']) + count($parsed['extra']) + count($parsed['missing']);
        if ($parsed['error'] !== null || (!$r->ok() && $found === 0 && !$parsed['success'])) {
            $alerts->siteError('core-checksums', I18n::t('wp core verify-checksums failed: %s', $parsed['error'] ?? $r->reason()), $r->details());
            return;
        }
        $alerts->siteOk('core-checksums');
        if ($found === 0) {
            $alerts->resolve('core-checksums');
            return;
        }
        $lines = array_merge(
            Util::listBlock(I18n::t('modified'), $parsed['modified']),
            Util::listBlock(I18n::t('should not exist'), $parsed['extra']),
            Util::listBlock(I18n::t('missing'), $parsed['missing'])
        );
        $sev = $parsed['modified'] || $parsed['extra'] ? 'critical' : 'warning';
        $alerts->alert($sev, 'core-checksums', I18n::t(
            'WordPress core files do not match the official checksums: %d modified, %d unexpected, %d missing',
            count($parsed['modified']), count($parsed['extra']), count($parsed['missing'])
        ), $lines, null, null, ['modified' => count($parsed['modified']), 'extra' => count($parsed['extra']), 'missing' => count($parsed['missing'])]);
    }

    /** Parse the plain-text output of `wp core verify-checksums`. */
    public static function parseCore(string $output, array $ignore = []): array
    {
        $res = ['modified' => [], 'extra' => [], 'missing' => [], 'success' => false, 'error' => null];
        foreach (preg_split('/\R/', $output) ?: [] as $line) {
            $line = trim($line);
            if (preg_match("/^Warning:\s+File doesn't verify against checksum: (.+)$/", $line, $m)) {
                $kind = 'modified';
            } elseif (preg_match('/^Warning:\s+File should not exist: (.+)$/', $line, $m)) {
                $kind = 'extra';
            } elseif (preg_match("/^Warning:\s+File doesn't exist: (.+)$/", $line, $m)) {
                $kind = 'missing';
            } elseif (preg_match('/^Success:\s/', $line)) {
                $res['success'] = true;
                continue;
            } elseif (preg_match("/^Error:\s+(?!WordPress installation doesn't verify)(.+)$/", $line, $m)) {
                $res['error'] = Util::oneLine($m[1], 200);
                continue;
            } else {
                continue;
            }
            if (!Util::matchAny($m[1], $ignore)) {
                $res[$kind][] = $m[1];
            }
        }
        return $res;
    }

    private function plugins(Site $site): void
    {
        $cfg = $this->ctx->cfg;
        $alerts = $this->ctx->alerts;
        $args = ['plugin', 'verify-checksums', '--all', '--format=json'];
        if ($cfg->bool('plugin_checksum_strict')) {
            $args[] = '--strict';
        }
        if ($cfg->list('plugin_checksum_exclude')) {
            $args[] = '--exclude=' . implode(',', $cfg->list('plugin_checksum_exclude'));
        }
        $r = $this->ctx->wp->run($site, $args);
        $errors = $r->json();
        // With failures WP-CLI exits 1 with "Only verified N of M plugins" / "No plugins verified".
        if ($errors === null && !$r->ok()) {
            if (!preg_match('/(Only verified|No plugins verified)/', $r->stderr)) {
                $alerts->siteError('plugin-checksums', I18n::t('wp plugin verify-checksums failed: %s', $r->reason()), $r->details());
                return;
            }
            $errors = [];
        }
        $alerts->siteOk('plugin-checksums');

        if (preg_match_all('/Could not retrieve the checksums for version (\S+) of plugin (\S+?),/', $r->stderr, $m)) {
            Log::debug(sprintf('%s: %d plugin(s) not verifiable (not on wordpress.org): %s', $site->root, count($m[2]), implode(', ', $m[2])));
        }

        $byPlugin = self::groupPluginErrors($errors ?? [], $cfg->list('plugin_checksum_ignore'));
        $keys = [];
        foreach ($byPlugin as $slug => $files) {
            $key = "plugin-checksums.$slug";
            $keys[] = $key;
            $critical = false;
            $lines = [];
            foreach ($files as [$message, $file]) {
                if ($message !== 'File was added' || preg_match('/\.(php\d?|phtml|phar|inc)$/i', $file)) {
                    $critical = $critical || $message !== 'File is missing';
                }
                $lines[] = self::problem($message) . ": $file";
            }
            $alerts->alert($critical ? 'critical' : 'warning', $key,
                I18n::n(count($files), "Plugin '%s' does not match the wordpress.org checksums (%d file(s))",
                    "Plugin '%s' does not match the wordpress.org checksums (%d file(s))", $slug, count($files)),
                Util::listBlock('', $lines, 30), null, null, ['slug' => $slug]);
        }
        $alerts->resolveExcept('plugin-checksums.', $keys);
    }

    /** A WP-CLI checksum message, in lower case and translated when known. */
    private static function problem(string $message): string
    {
        switch ($message) {
            case 'Checksum does not match':
                return I18n::t('checksum does not match');
            case 'File was added':
                return I18n::t('file was added');
            case 'File is missing':
                return I18n::t('file is missing');
            default:
                return strtolower($message);
        }
    }

    /** @return array<string, array<int, array{0: string, 1: string}>> slug => [[message, file]] */
    public static function groupPluginErrors(array $errors, array $ignore = []): array
    {
        $out = [];
        foreach ($errors as $e) {
            if (!is_array($e)) {
                continue;
            }
            $slug = Util::oneLine((string) ($e['plugin_name'] ?? '?'), 100);
            $file = Util::oneLine((string) ($e['file'] ?? ''));
            if (Util::matchAny("$slug/$file", $ignore)) {
                continue;
            }
            $out[$slug][] = [Util::oneLine((string) ($e['message'] ?? 'Checksum does not match'), 100), $file];
        }
        ksort($out);
        return $out;
    }
}
