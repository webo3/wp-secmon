<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * WP-CLI, always run as the site owner with:
 *   --skip-plugins --skip-themes  no plugin or theme code is loaded
 *   --skip-packages               no WP-CLI packages from the user's home
 *   --no-color                    plain output (without posix, WP-CLI assumes a terminal)
 *   --exec=<readonly-guard>       SQL writes, WP-Cron and HTTP are blocked
 * plus WP_CLI_CONFIG_PATH=/dev/null (see RunAs).
 */
final class WpCli
{
    private Config $cfg;
    private RunAs $runAs;
    private string $tmp;
    private string $guard;
    private int $seq = 0;

    public function __construct(Config $cfg, RunAs $runAs, string $tmp)
    {
        $this->cfg = $cfg;
        $this->runAs = $runAs;
        $this->tmp = $tmp;
        $this->guard = self::phpSnippet(Util::resource('wordpress/readonly-guard.php'));
    }

    /** PHP file contents without the opening tag, for --exec and eval. */
    public static function phpSnippet(string $file): string
    {
        $code = @file_get_contents($file);
        if ($code === false) {
            throw new \RuntimeException(I18n::t('cannot read %s', $file));
        }
        return (string) preg_replace('/^<\?php\s*/', '', $code);
    }

    public function run(Site $site, array $args): WpResult
    {
        $cmd = $this->cfg->str('wp_php') !== ''
            ? array_merge([$this->cfg->str('wp_php')], $this->cfg->list('wp_php_args'), [$this->cfg->str('wp_cli')])
            : [$this->cfg->str('wp_cli')];
        $cmd = array_merge($cmd, [
            '--path=' . $site->root,
            '--skip-plugins',
            '--skip-themes',
            '--skip-packages',
            '--no-color',
            '--exec=' . $this->guard,
        ], $args);

        $base = sprintf('%s/wp-%s-%d', $this->tmp, $site->id, ++$this->seq);
        $code = $this->runAs->run($site->user, $cmd, "$base.out", "$base.err", $this->cfg->int('wp_timeout'), $site->root);
        $result = WpResult::fromFiles($code, "$base.out", "$base.err", $this->runAs->maxOutput());
        Log::debug(sprintf('%s: wp %s -> exit %d', $site->root, implode(' ', array_slice($args, 0, 3)), $code));
        return $result;
    }
}
