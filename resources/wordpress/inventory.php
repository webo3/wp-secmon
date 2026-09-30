<?php
/**
 * wp-secmon inventory snapshot, run with `wp eval` (plugins and themes are not
 * loaded). Read-only: prints a single line "WPSECMON-JSON:{...}".
 */
if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$wpg_active  = (array) get_option( 'active_plugins', array() );
$wpg_network = is_multisite() ? (array) get_site_option( 'active_sitewide_plugins', array() ) : array();

$wpg_plugins = array();
foreach ( get_plugins() as $wpg_file => $wpg_data ) {
	$wpg_plugins[] = array(
		'slug'    => false === strpos( $wpg_file, '/' ) ? basename( $wpg_file, '.php' ) : dirname( $wpg_file ),
		'file'    => $wpg_file,
		'name'    => $wpg_data['Name'],
		'version' => $wpg_data['Version'],
		'active'  => in_array( $wpg_file, $wpg_active, true ) || isset( $wpg_network[ $wpg_file ] ),
	);
}

$wpg_stylesheet = get_option( 'stylesheet' );
$wpg_template   = get_option( 'template' );
$wpg_themes     = array();
foreach ( wp_get_themes() as $wpg_slug => $wpg_theme ) {
	$wpg_themes[] = array(
		'slug'    => (string) $wpg_slug,
		'name'    => $wpg_theme->get( 'Name' ),
		'version' => $wpg_theme->get( 'Version' ),
		'parent'  => $wpg_theme->get_template() !== $wpg_slug ? $wpg_theme->get_template() : '',
		'active'  => $wpg_slug === $wpg_stylesheet || $wpg_slug === $wpg_template,
	);
}

$wpg_uploads = wp_upload_dir( null, false );

echo 'WPSECMON-JSON:' . wp_json_encode(
	array(
		'core'    => array(
			'version'   => $GLOBALS['wp_version'],
			'locale'    => get_locale(),
			'multisite' => is_multisite(),
			'php'       => PHP_VERSION,
		),
		'options' => array(
			'siteurl'            => get_option( 'siteurl' ),
			'home'               => get_option( 'home' ),
			'admin_email'        => get_option( 'admin_email' ),
			'users_can_register' => (string) get_option( 'users_can_register' ),
			'default_role'       => get_option( 'default_role' ),
			'registration'       => is_multisite() ? get_site_option( 'registration' ) : null,
			'template'           => $wpg_template,
			'stylesheet'         => $wpg_stylesheet,
		),
		'paths'   => array(
			'content_dir' => WP_CONTENT_DIR,
			'uploads_dir' => isset( $wpg_uploads['basedir'] ) ? $wpg_uploads['basedir'] : '',
		),
		'plugins' => $wpg_plugins,
		'themes'  => $wpg_themes,
	)
) . "\n";
