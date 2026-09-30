<?php
/**
 * wp-secmon read-only guard.
 *
 * Passed to every WP-CLI call with `--exec`, so it runs before WordPress
 * loads. It keeps WP-CLI from changing anything while wp-secmon inspects a site:
 *
 * - must-use plugins are not loaded (--skip-plugins does not cover them, and
 *   a malicious one could hide accounts or files from WP-CLI); wp-secmon
 *   watches their files instead;
 * - SQL statements that are not reads are dropped (WordPress core would
 *   otherwise write transients, cron locks or options while booting);
 * - WP-Cron is not triggered by the WP-CLI process;
 * - outgoing HTTP through the WordPress HTTP API is refused (WP-CLI's own
 *   checksum downloads do not use it and are unaffected).
 */
if ( ! defined( 'WPMU_PLUGIN_DIR' ) ) {
	define( 'WPMU_PLUGIN_DIR', '/nonexistent/wp-secmon-does-not-load-mu-plugins' );
}

if ( class_exists( 'WP_CLI' ) && method_exists( 'WP_CLI', 'add_wp_hook' ) ) {
	WP_CLI::add_wp_hook(
		'query',
		function ( $query ) {
			if ( preg_match( '/^\s*\(?\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|SET)\b/i', (string) $query ) ) {
				return $query;
			}
			return '';
		},
		PHP_INT_MAX
	);

	WP_CLI::add_wp_hook(
		'init',
		function () {
			remove_action( 'init', 'wp_cron' );
		},
		0
	);

	WP_CLI::add_wp_hook(
		'pre_http_request',
		function () {
			return new WP_Error( 'wp_secmon_readonly', 'HTTP requests are disabled by wp-secmon.' );
		},
		PHP_INT_MAX
	);
}
