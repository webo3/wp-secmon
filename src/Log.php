<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Logging to stderr. Under systemd the journal gets proper priorities through
 * "<N>" prefixes; on a terminal each line gets a timestamp.
 */
final class Log
{
    /** -1 quiet, 0 normal, 1 debug */
    public static int $verbosity = 0;

    private const PRIORITY = ['crit' => 2, 'error' => 3, 'warning' => 4, 'notice' => 5, 'info' => 6, 'debug' => 7];

    public static function write(string $level, string $message): void
    {
        if (($level === 'debug' && self::$verbosity < 1) || ($level === 'info' && self::$verbosity < 0)) {
            return;
        }
        $message = Util::oneLine($message, 2000);
        if (getenv('JOURNAL_STREAM')) {
            fwrite(STDERR, '<' . (self::PRIORITY[$level] ?? 6) . '>' . $message . "\n");
        } else {
            fwrite(STDERR, date('Y-m-d H:i:s') . ' ' . str_pad($level, 7) . ' ' . $message . "\n");
        }
    }

    public static function debug(string $m): void
    {
        self::write('debug', $m);
    }

    public static function info(string $m): void
    {
        self::write('info', $m);
    }

    public static function notice(string $m): void
    {
        self::write('notice', $m);
    }

    public static function warning(string $m): void
    {
        self::write('warning', $m);
    }

    public static function error(string $m): void
    {
        self::write('error', $m);
    }
}
