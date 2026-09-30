<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Translations of what wp-secmon says to people: reports, alerts and command
 * output. Debug logging stays in English.
 *
 * Messages are written in English in the code, as sprintf() formats.
 * resources/lang/<code>.php maps each one to its translation, which may
 * reorder the arguments with %1$s, %2$s... A plural message (n()) maps its
 * English singular to [singular, plural]. A missing translation falls back to
 * English; tests/unit.php checks that every message has one.
 */
final class I18n
{
    public const LANGUAGES = ['en' => 'English', 'fr' => 'français'];

    private static string $language = 'en';
    /** @var array<string, string|string[]> */
    private static array $messages = [];

    public static function setLanguage(string $code): void
    {
        if (!isset(self::LANGUAGES[$code])) {
            throw new \InvalidArgumentException(self::t('unknown language %s (expected %s)', $code, implode(', ', array_keys(self::LANGUAGES))));
        }
        self::$messages = $code === 'en' ? [] : (array) require Util::resource("lang/$code.php");
        self::$language = $code;
    }

    public static function language(): string
    {
        return self::$language;
    }

    /** $message translated, with $args formatted into it. */
    public static function t(string $message, ...$args): string
    {
        $text = self::$messages[$message] ?? $message;
        return self::format(is_array($text) ? $text[0] : $text, $args);
    }

    /**
     * t() for a message that needs a different translation depending on
     * $context (e.g. an adjective for a plugin or for a theme). The catalog
     * key is "$context\x04$message", as in gettext.
     */
    public static function tc(string $context, string $message, ...$args): string
    {
        $text = self::$messages["$context\x04$message"] ?? $message;
        return self::format(is_array($text) ? $text[0] : $text, $args);
    }

    /** The singular or plural form for $n, translated, with $args formatted into it. */
    public static function n(int $n, string $one, string $many, ...$args): string
    {
        $forms = self::$messages[$one] ?? [$one, $many];
        $forms = is_array($forms) ? $forms : [$forms, $forms];
        // French uses the singular for 0 and 1.
        $plural = self::$language === 'fr' ? $n > 1 : $n !== 1;
        return self::format($forms[$plural ? 1 : 0], $args);
    }

    /** date() with a translated format and month names. */
    public static function date(string $format, int $time): string
    {
        $text = date(self::t($format), $time);
        if (self::$language === 'en') {
            return $text;
        }
        $months = [];
        for ($m = 1; $m <= 12; $m++) {
            $t = mktime(12, 0, 0, $m, 1, 2000);
            $months[date('F', $t)] = self::t(date('F', $t));
            $months[date('M', $t)] = self::t(date('M', $t));
        }
        return strtr($text, $months);
    }

    private static function format(string $text, array $args): string
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
