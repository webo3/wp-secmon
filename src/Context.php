<?php

declare(strict_types=1);

namespace WpSecMon;

/** Services shared by the checks of one run. */
final class Context
{
    public Config $cfg;
    public Alerts $alerts;
    public RunAs $runAs;
    public WpCli $wp;
    public string $tmp;
    private array $inventory = [];
    private string $inventoryCode;
    private int $seq = 0;

    public function __construct(Config $cfg, Alerts $alerts, string $tmp)
    {
        $this->cfg = $cfg;
        $this->alerts = $alerts;
        $this->tmp = $tmp;
        $this->runAs = new RunAs($cfg);
        $this->wp = new WpCli($cfg, $this->runAs, $tmp);
        $this->inventoryCode = WpCli::phpSnippet(Util::resource('wordpress/inventory.php'));
    }

    /** Per-site state directory (baselines, open alerts). */
    public function siteDir(Site $site): string
    {
        $dir = $this->cfg->str('state_dir') . '/sites/' . $site->id;
        if (!is_file("$dir/site.json")) {
            Util::writeJson("$dir/site.json", $site->toArray());
        }
        return $dir;
    }

    /**
     * Snapshot of core version, key options, paths, plugins and themes, taken
     * once per run with `wp eval` (see resources/wordpress/inventory.php).
     */
    public function inventory(Site $site): ?array
    {
        if (!array_key_exists($site->id, $this->inventory)) {
            $r = $this->wp->run($site, ['eval', $this->inventoryCode]);
            $data = $r->json('WPSECMON-JSON:');
            if ($data === null) {
                $this->alerts->siteError('inventory', I18n::t('cannot read the WordPress inventory: %s', $r->reason()), $r->details());
            } else {
                $this->alerts->siteOk('inventory');
            }
            $this->inventory[$site->id] = $data;
        }
        return $this->inventory[$site->id];
    }

    /** File scan of a site (FileScanner), run as the site owner through `wp-secmon __scan-files`. */
    public function scanFiles(Site $site, array $paths): WpResult
    {
        return $this->helper($site, ['__scan-files', (string) json_encode($paths, JSON_UNESCAPED_SLASHES)]);
    }

    /** One file of a site and its first $max bytes (FileScanner::read), read as the site owner through `wp-secmon __read-file`. */
    public function readFile(Site $site, string $path, int $max): WpResult
    {
        return $this->helper($site, ['__read-file', $path, (string) $max]);
    }

    private function helper(Site $site, array $args): WpResult
    {
        $cmd = array_merge([PHP_BINARY, '-d', 'open_basedir=', '-d', 'display_errors=stderr', Util::entry()], $args);
        $base = sprintf('%s/helper-%s-%d', $this->tmp, $site->id, ++$this->seq);
        $code = $this->runAs->run($site->user, $cmd, "$base.out", "$base.err", $this->cfg->int('wp_timeout'), $site->root);
        return WpResult::fromFiles($code, "$base.out", "$base.err", $this->runAs->maxOutput());
    }
}
