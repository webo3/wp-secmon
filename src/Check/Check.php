<?php

declare(strict_types=1);

namespace WpSecMon\Check;

use WpSecMon\Context;
use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Site;

abstract class Check
{
    protected Context $ctx;
    /** Site ids checked during this process (for the report totals). */
    public static array $seen = [];

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    abstract public static function name(): string;

    /** @param Site[] $sites */
    public function run(array $sites): void
    {
        $alerts = $this->ctx->alerts;
        $alerts->check = static::name();
        $alerts->checksRun[] = static::name();
        $alerts->setSite(null);
        $this->before();
        foreach ($sites as $site) {
            if (!is_dir($site->root)) {
                Log::info(I18n::t('%s: no longer exists, skipped until the next discovery', $site->root));
                continue;
            }
            $alerts->setSite($site);
            try {
                $this->checkSite($site);
            } catch (\Throwable $e) {
                $alerts->siteError(static::name(), I18n::t('internal error: %s', $e->getMessage()));
            }
            if (!isset(self::$seen[$site->id])) {
                self::$seen[$site->id] = true;
                $alerts->sitesChecked++;
            }
        }
        $alerts->setSite(null);
        $this->after($sites);
    }

    protected function before(): void
    {
    }

    protected function after(array $sites): void
    {
    }

    abstract protected function checkSite(Site $site): void;
}
