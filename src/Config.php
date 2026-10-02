<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Configuration: built-in defaults overridden by /etc/wp-secmon/wp-secmon.ini.
 * Sections in the INI file are only for readability; keys are global.
 */
final class Config
{
    public const DEFAULT_FILE = '/etc/wp-secmon/wp-secmon.ini';

    private const DEFAULTS = [
        'language' => 'en',

        // WP-CLI
        'wp_cli' => '/usr/local/bin/wp',
        'wp_php' => '',
        'wp_php_args' => [],
        'wp_timeout' => 300,
        'max_output_mb' => 32,
        'user_path' => '/usr/local/bin:/usr/bin:/bin',
        'run_as_method' => 'auto',

        // Discovery
        'scan_paths' => ['/home'],
        'scan_max_depth' => 6,
        'scan_exclude' => [
            '/home/virtfs', '/home/cagefs-skeleton', '/home/cpeasyapache',
            '*/.cagefs', '*/.trash', '*/mail', '*/.cpanel', '*/.cache',
            '*/.git', '*/node_modules', '*/.wp-cli',
        ],
        'extra_sites' => [],
        'exclude_sites' => [],
        'discovery_max_age_hours' => 26,

        // Which account each site is checked as
        'site_users_map' => '/etc/wp-secmon/site-users.map',
        'min_uid' => 1000,
        'allowed_system_users' => ['www-data', 'nginx', 'apache'],
        'fallback_user' => '',
        'forbidden_groups' => ['wheel', 'sudo', 'admin', 'docker', 'lxd', 'incus-admin', 'libvirt', 'disk', 'shadow'],
        'skip_suspended_cpanel' => true,

        // Storage
        'state_dir' => '/var/lib/wp-secmon',
        'log_dir' => '/var/log/wp-secmon',

        // Alerting
        'alert_email' => 'root',
        'alert_site_admins' => false,
        'alert_site_admins_cc' => [],
        'alert_from' => '',
        'sendmail' => '/usr/sbin/sendmail',
        'mail_min_severity' => 'warning',
        'mail_format' => 'html',
        'alert_command' => '',
        'alert_repeat_hours' => 24,
        'alert_on_resolve' => true,
        'alert_on_errors' => true,
        'alert_on_skipped_sites' => true,
        'alert_on_new_sites' => true,

        // users check
        'privileged_roles' => ['administrator'],
        'users_alert_new' => 'privileged',
        'users_new_severity' => 'warning',

        // integrity check
        'risky_default_roles' => ['administrator', 'editor', 'author', 'shop_manager'],

        // checksums check
        'core_checksum_ignore' => ['*/error_log'],
        'plugin_checksum_strict' => false,
        'plugin_checksum_exclude' => [],
        'plugin_checksum_ignore' => ['*/error_log'],

        // vulns check
        'vuln_api_url' => 'https://www.wpvulnerability.net',
        'wp_version_api_url' => 'https://api.wordpress.org/core/version-check/1.7/',
        'vuln_cache_hours' => 12,
        'vuln_repeat_hours' => 168,
        'vuln_request_delay_ms' => 200,
        'vuln_include_inactive' => true,
        'http_proxy' => '',

        // wp-secmon update
        'update_url' => 'https://api.github.com/repos/webo3/wp-secmon/releases/latest',
    ];

    private const CHOICES = [
        'language' => ['en', 'fr'],
        'run_as_method' => ['auto', 'setpriv', 'runuser', 'sudo', 'su', 'cagefs'],
        'mail_min_severity' => ['info', 'warning', 'critical'],
        'mail_format' => ['html', 'text'],
        'users_alert_new' => ['all', 'privileged'],
        'users_new_severity' => ['info', 'warning', 'critical'],
    ];

    private array $values;
    public string $file;

    private function __construct(array $values, string $file)
    {
        $this->values = $values;
        $this->file = $file;
    }

    public static function load(?string $file): self
    {
        $explicit = $file !== null;
        $file = $file ?? self::DEFAULT_FILE;
        $values = self::DEFAULTS;

        if (!is_file($file)) {
            if ($explicit) {
                throw new \RuntimeException(I18n::t('configuration file not found: %s', $file));
            }
            Log::debug("no configuration at $file, using defaults");
            return new self($values, $file);
        }

        if (Util::effectiveUid() === 0 && ($problem = Util::rootOnlyProblem($file)) !== null) {
            throw new \RuntimeException($problem);
        }

        $ini = @parse_ini_file($file, true, INI_SCANNER_TYPED);
        if ($ini === false) {
            $err = error_get_last();
            throw new \RuntimeException(I18n::t('cannot parse %s: %s', $file, $err['message'] ?? I18n::t('syntax error')));
        }
        foreach ($ini as $key => $value) {
            if (is_array($value) && !array_key_exists($key, self::DEFAULTS)) {
                // [section]
                foreach ($value as $k => $v) {
                    self::set($values, (string) $k, $v, $file);
                }
            } else {
                self::set($values, (string) $key, $value, $file);
            }
        }
        return new self($values, $file);
    }

    private static function set(array &$values, string $key, $value, string $file): void
    {
        if (!array_key_exists($key, self::DEFAULTS)) {
            Log::warning(I18n::t("%s: unknown setting '%s' ignored", $file, $key));
            return;
        }
        $default = self::DEFAULTS[$key];
        if (is_array($default)) {
            $list = is_array($value) ? array_values($value) : [$value];
            $value = array_values(array_filter(array_map('strval', $list), static function ($v) {
                return $v !== '';
            }));
        } elseif (is_bool($default)) {
            $value = is_bool($value) ? $value : in_array(strtolower((string) $value), ['1', 'yes', 'true', 'on'], true);
        } elseif (is_int($default)) {
            $value = (int) $value;
        } else {
            $value = is_bool($value) ? ($value ? 'yes' : '') : (string) ($value ?? '');
        }
        if (isset(self::CHOICES[$key]) && !in_array($value, self::CHOICES[$key], true)) {
            throw new \RuntimeException(I18n::t('%s: invalid value for %s (expected %s)', $file, $key, implode(', ', self::CHOICES[$key])));
        }
        $values[$key] = $value;
    }

    public function str(string $key): string
    {
        return (string) $this->values[$key];
    }

    public function int(string $key): int
    {
        return (int) $this->values[$key];
    }

    public function bool(string $key): bool
    {
        return (bool) $this->values[$key];
    }

    public function list(string $key): array
    {
        return (array) $this->values[$key];
    }

    /** The defaults with $overrides: for tests, and for install when the configuration cannot be read. */
    public static function fromArray(array $overrides): self
    {
        $values = self::DEFAULTS;
        foreach ($overrides as $k => $v) {
            self::set($values, $k, $v, 'overrides');
        }
        return new self($values, '(memory)');
    }
}
