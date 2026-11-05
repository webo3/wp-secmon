<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * When each check runs, as set by "timer" in its section of wp-secmon.ini.
 *
 * `wp-secmon schedule` runs every hour (wp-secmon.timer, or cron) and starts
 * the checks that are due: those not started since their last slot. Hourly
 * slots are at the top of each hour; the others at a fixed hour of the night,
 * every day, on Sundays or on the 1st of the month, in the server's time zone.
 * A slot missed while the server was down is caught up at the next run. The
 * time each check was started is kept in state_dir/schedule.json.
 */
final class Schedule
{
    /** In the order they start: the discovery first, so that the checks use the new site list. */
    public const CHECKS = ['discover', 'users', 'integrity', 'checksums', 'vulns'];
    /** Hour of the daily, weekly and monthly slots. */
    private const HOURS = ['discover' => 2, 'checksums' => 3, 'integrity' => 4, 'users' => 5, 'vulns' => 6];

    private Config $cfg;
    private string $file;
    private \DateTimeZone $zone;
    /** @var array<string, int> check => when it was last started */
    private array $started;

    public function __construct(Config $cfg, ?\DateTimeZone $zone = null)
    {
        $this->cfg = $cfg;
        $this->file = $cfg->str('state_dir') . '/schedule.json';
        $this->zone = $zone ?? self::zone();
        $this->started = array_map('intval', array_filter((array) (Util::readJson($this->file) ?? []), 'is_int'));
    }

    /**
     * The checks due at $now. A check never started before is not: it waits
     * for its next slot, as after a new install, where the admin has just run
     * them all by hand.
     * @return string[]
     */
    public function due(int $now): array
    {
        $due = [];
        $new = false;
        foreach (self::CHECKS as $check) {
            if (!isset($this->started[$check])) {
                $this->started[$check] = $now;
                $new = true;
                continue;
            }
            $timer = $this->cfg->str("{$check}_timer");
            if ($timer !== 'disabled' && $this->started[$check] < self::slots($timer, self::HOURS[$check], $now, $this->zone)[0]) {
                $due[] = $check;
            }
        }
        if ($new) {
            Util::writeJson($this->file, $this->started);
        }
        return $due;
    }

    /** Notes that $checks were started at $now. */
    public function started(array $checks, int $now): void
    {
        foreach ($checks as $check) {
            $this->started[$check] = $now;
        }
        Util::writeJson($this->file, $this->started);
    }

    public function lastStarted(string $check): ?int
    {
        return $this->started[$check] ?? null;
    }

    /** When $check is due next: $now when it is due already, null when its timer is disabled. */
    public function next(string $check, int $now): ?int
    {
        $timer = $this->cfg->str("{$check}_timer");
        if ($timer === 'disabled') {
            return null;
        }
        [$last, $next] = self::slots($timer, self::HOURS[$check], $now, $this->zone);
        return isset($this->started[$check]) && $this->started[$check] < $last ? $now : $next;
    }

    /** $time in the time zone of the schedule. */
    public function format(int $time): string
    {
        return (new \DateTimeImmutable('@' . $time))->setTimezone($this->zone)->format('Y-m-d H:i');
    }

    /** "timer" of $check, in words. */
    public static function describe(string $check, string $timer): string
    {
        $at = sprintf('%02d:00', self::HOURS[$check]);
        switch ($timer) {
            case 'hourly':
                return I18n::t('hourly');
            case 'daily':
                return I18n::t('daily at %s', $at);
            case 'weekly':
                return I18n::t('weekly on Sundays at %s', $at);
            case 'monthly':
                return I18n::t('monthly on the 1st at %s', $at);
        }
        return I18n::t('disabled');
    }

    /**
     * The last slot of $timer at or before $now, and the next one after it.
     * @return array{0: int, 1: int}
     */
    public static function slots(string $timer, int $hour, int $now, \DateTimeZone $zone): array
    {
        $t = (new \DateTimeImmutable('@' . $now))->setTimezone($zone);
        if ($timer === 'hourly') {
            $last = $t->setTime((int) $t->format('G'), 0)->getTimestamp();
            return [$last, $last + 3600];
        }
        if ($timer === 'daily') {
            [$slot, $step] = [$t->setTime($hour, 0), '1 day'];
        } elseif ($timer === 'weekly') {
            [$slot, $step] = [$t->modify('-' . $t->format('w') . ' days')->setTime($hour, 0), '7 days'];
        } elseif ($timer === 'monthly') {
            [$slot, $step] = [$t->modify('first day of this month')->setTime($hour, 0), '1 month'];
        } else {
            throw new \InvalidArgumentException("unknown timer '$timer'");
        }
        return $slot > $t
            ? [$slot->modify("-$step")->getTimestamp(), $slot->getTimestamp()]
            : [$slot->getTimestamp(), $slot->modify("+$step")->getTimestamp()];
    }

    /**
     * The server's time zone, which systemd timers and cron use too. Not PHP's:
     * it is UTC unless php.ini sets date.timezone, and ini_get() cannot tell.
     */
    public static function zone(): \DateTimeZone
    {
        $names = [ltrim((string) getenv('TZ'), ':')];
        $link = @readlink('/etc/localtime');
        if ($link !== false && preg_match('#zoneinfo/(?:posix/|right/)?(.+)$#', $link, $m)) {
            $names[] = $m[1];
        }
        if (is_readable('/etc/timezone')) {
            $names[] = trim((string) @file_get_contents('/etc/timezone'));
        }
        $names[] = date_default_timezone_get();
        foreach ($names as $name) {
            try {
                if ($name !== '') {
                    return new \DateTimeZone($name);
                }
            } catch (\Exception $e) {
                // Not a zone PHP knows: try the next one.
            }
        }
        return new \DateTimeZone('UTC');
    }
}
