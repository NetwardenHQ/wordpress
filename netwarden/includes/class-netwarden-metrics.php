<?php
/**
 * Netwarden Metrics Class
 *
 * Collects various metrics from the WordPress installation
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Netwarden_Metrics {

	/**
	 * Collect all metrics
	 *
	 * @return array Array of metrics in Netwarden format
	 */
	public static function collect_all() {
		$metrics = array();

		// Collect all metric types
		$metrics = array_merge( $metrics, self::collect_database_metrics() );
		$metrics = array_merge( $metrics, self::collect_disk_metrics() );
		$metrics = array_merge( $metrics, self::collect_wordpress_version_metrics() );
		$metrics = array_merge( $metrics, self::collect_agent_status_metrics() );
		$metrics = array_merge( $metrics, self::collect_security_metrics() );
		$metrics = array_merge( $metrics, self::collect_performance_metrics() );
		$metrics = array_merge( $metrics, self::collect_user_activity_metrics() );
		$metrics = array_merge( $metrics, self::collect_database_performance_metrics() );
		$metrics = array_merge( $metrics, self::collect_integration_metrics() );
		$metrics = array_merge( $metrics, self::collect_predictive_metrics() );

		// Track historical data for trend analysis (run after collecting metrics)
		self::track_historical_data( $metrics );

		return $metrics;
	}

	/**
	 * Collect database health and size metrics
	 *
	 * @return array
	 */
	private static function collect_database_metrics() {
		global $wpdb;
		$metrics = array();

		// Database response time (query latency)
		$start = microtime( true );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Testing database latency with simple query
		$wpdb->get_var( 'SELECT 1' );
		$latency_ms = round( ( microtime( true ) - $start ) * 1000, 2 );

		$metrics[] = array(
			'metric_name' => 'database_latency_ms',
			'value'       => $latency_ms,
			'labels'      => array( 'type' => 'mysql' ),
		);

		// Database size (cached for 5 minutes to reduce overhead)
		$db_name = DB_NAME;
		$db_size = get_transient( 'netwarden_db_size' );

		if ( false === $db_size ) {
			// Cache miss - query database
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Querying information_schema for database size
			$db_size = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT SUM(data_length + index_length) AS size
                 FROM information_schema.tables
                 WHERE table_schema = %s',
					$db_name
				)
			);

			if ( $db_size ) {
				// Cache for 5 minutes
				set_transient( 'netwarden_db_size', $db_size, 5 * MINUTE_IN_SECONDS );
			} elseif ( $wpdb->last_error ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
				error_log( 'Netwarden: Failed to query database size - ' . $wpdb->last_error );
			}
		}

		if ( $db_size ) {
			$metrics[] = array(
				'metric_name' => 'database_size_bytes',
				'value'       => (float) $db_size,
				'labels'      => array( 'database' => $db_name ),
			);
		}

		// Database connection status
		$metrics[] = array(
			'metric_name' => 'database_status',
			'value'       => 1, // 1 = connected, 0 = disconnected
			'labels'      => array( 'type' => 'mysql' ),
		);

		return $metrics;
	}

	/**
	 * Collect disk usage metrics
	 *
	 * @return array
	 */
	private static function collect_disk_metrics() {
		$metrics = array();

		// The filesystem the WordPress root lives on. ABSPATH always exists
		// while WordPress is running, so the calls below need no silencing.
		$wp_path = ABSPATH;
        // phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_disk_total_space, WordPress.WP.AlternativeFunctions.file_system_operations_disk_free_space -- Disk monitoring is core functionality
		$disk_total = disk_total_space( $wp_path );
		$disk_free  = disk_free_space( $wp_path );
        // phpcs:enable

		if ( false === $disk_total || false === $disk_free ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: Failed to retrieve disk space information for ' . $wp_path );
			return $metrics;
		}

		$disk_used = $disk_total - $disk_free;

		if ( $disk_total && false !== $disk_free ) {
			// Use metric naming convention matching Go agent (mountpoint in metric name)
			$mount = '/';

			$metrics[] = array(
				'metric_name' => 'disk_total_bytes:' . $mount,
				'value'       => (float) $disk_total,
				'labels'      => array(),
			);

			$metrics[] = array(
				'metric_name' => 'disk_used_bytes:' . $mount,
				'value'       => (float) $disk_used,
				'labels'      => array(),
			);

			$metrics[] = array(
				'metric_name' => 'disk_free_bytes:' . $mount,
				'value'       => (float) $disk_free,
				'labels'      => array(),
			);

			// Calculate disk usage percentage
			$disk_used_percent = ( $disk_used / $disk_total ) * 100;
			$metrics[]         = array(
				'metric_name' => 'disk_usage_percent:' . $mount,
				'value'       => round( $disk_used_percent, 2 ),
				'labels'      => array(),
			);
		}

		return $metrics;
	}

	/**
	 * Collect WordPress version metrics (compare with latest)
	 *
	 * @return array
	 */
	private static function collect_wordpress_version_metrics() {
		$metrics = array();

		// Get current WordPress version
		$current_version = get_bloginfo( 'version' );

		// Get latest WordPress version from API (cached for 12 hours)
		$latest_version = get_transient( 'netwarden_latest_wp_version' );

		if ( false === $latest_version ) {
			$response = wp_remote_get( 'https://api.wordpress.org/core/version-check/1.7/' );

			if ( is_wp_error( $response ) ) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
				error_log( 'Netwarden: Failed to fetch WordPress version info - ' . $response->get_error_message() );
			} elseif ( wp_remote_retrieve_response_code( $response ) === 200 ) {
				$body = wp_remote_retrieve_body( $response );
				$data = json_decode( $body );

				// Check if JSON decode succeeded
				if ( null === $data && json_last_error() !== JSON_ERROR_NONE ) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
					error_log( 'Netwarden: Failed to decode WordPress.org version API response - ' . json_last_error_msg() );
				} elseif ( $data && isset( $data->offers ) && is_array( $data->offers ) && count( $data->offers ) > 0 ) {
					$latest_version = $data->offers[0]->version;
					set_transient( 'netwarden_latest_wp_version', $latest_version, 12 * HOUR_IN_SECONDS );
				} else {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
					error_log( 'Netwarden: Invalid response format from WordPress.org version API' );
				}
			} else {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
				error_log( 'Netwarden: WordPress.org version API returned status ' . wp_remote_retrieve_response_code( $response ) );
			}
		}

		// Compare versions to determine if updates are available
		$updates_available = 0;
		$security_updates  = 0;

		if ( $latest_version && version_compare( $current_version, $latest_version, '<' ) ) {
			$updates_available = 1;

			// WordPress ships security fixes as point releases of the current
			// branch (6.8 -> 6.8.1), never only as a new major. So a pending
			// point release on the SAME major.minor is a security/maintenance
			// update; a pending new major.minor is a feature release. The old
			// logic had this backwards and flagged every feature release as a
			// security update.
			$current_parts = explode( '.', $current_version );
			$latest_parts  = explode( '.', $latest_version );
			if ( count( $current_parts ) >= 2 && count( $latest_parts ) >= 2
				&& $current_parts[0] === $latest_parts[0]
				&& $current_parts[1] === $latest_parts[1] ) {
				$security_updates = 1;
			}
		}

		$metrics[] = array(
			'metric_name' => 'system_updates_available_count',
			'value'       => $updates_available,
			'labels'      => array( 'type' => 'wordpress' ),
		);

		$metrics[] = array(
			'metric_name' => 'system_security_updates_count',
			'value'       => $security_updates,
			'labels'      => array( 'type' => 'wordpress' ),
		);

		// Plugin updates available
		// Read from WordPress's automatically maintained transient cache
		// WordPress updates this transient via wp_version_check cron (runs every 12 hours)
		// No need to force update checks or load admin files
		$update_plugins       = get_site_transient( 'update_plugins' );
		$plugin_updates_count = 0;

		if ( $update_plugins && isset( $update_plugins->response ) && is_array( $update_plugins->response ) ) {
			$plugin_updates_count = count( $update_plugins->response );
		}

		$metrics[] = array(
			'metric_name' => 'plugin_updates_available_count',
			'value'       => $plugin_updates_count,
			'labels'      => array( 'type' => 'wordpress' ),
		);

		// Theme updates available
		// Read from WordPress's automatically maintained transient cache
		// WordPress updates this transient via wp_version_check cron (runs every 12 hours)
		// No need to force update checks or load admin files
		$update_themes       = get_site_transient( 'update_themes' );
		$theme_updates_count = 0;

		if ( $update_themes && isset( $update_themes->response ) && is_array( $update_themes->response ) ) {
			$theme_updates_count = count( $update_themes->response );
		}

		$metrics[] = array(
			'metric_name' => 'theme_updates_available_count',
			'value'       => $theme_updates_count,
			'labels'      => array( 'type' => 'wordpress' ),
		);

		// WordPress version as a number: major.minor only ("6.4.2" -> 6.4),
		// so it sorts and compares; the full string rides in the labels.
		$version_numeric = 0.0;
		if ( $current_version ) {
			$parts = explode( '.', $current_version );
			if ( count( $parts ) >= 2 ) {
				// Major.Minor format (e.g., 6.4)
				$version_numeric = floatval( $parts[0] . '.' . $parts[1] );
			} elseif ( count( $parts ) === 1 ) {
				// Just major version
				$version_numeric = floatval( $parts[0] );
			}
		}

		$metrics[] = array(
			'metric_name' => 'wordpress_version_info',
			'value'       => $version_numeric,
			'labels'      => array(
				'current_version' => $current_version,
				'latest_version'  => $latest_version ? $latest_version : 'unknown',
			),
		);

		return $metrics;
	}

	/**
	 * Collect agent status metrics
	 *
	 * @return array
	 */
	private static function collect_agent_status_metrics() {
		$metrics = array();

		// Agent status (always 1 if we're running)
		$metrics[] = array(
			'metric_name' => 'agent_status',
			'value'       => 1,
			'labels'      => array( 'type' => 'wordpress' ),
		);

		// Note: agent_latency is sent in the payload root level, not in metrics array
		// The backend creates the agent_latency metric from payload.agent_latency

		// Cron working status
		// Check if cron is enabled and scheduled
		$next_scheduled = wp_next_scheduled( 'netwarden_collect_metrics' );
		$cron_enabled   = ! defined( 'DISABLE_WP_CRON' ) || ! DISABLE_WP_CRON;
		$cron_working   = ( $cron_enabled && false !== $next_scheduled ) ? 1 : 0;

		$metrics[] = array(
			'metric_name' => 'cron_working',
			'value'       => $cron_working,
			'labels'      => array(
				'cron_enabled'   => $cron_enabled ? 'true' : 'false',
				'next_scheduled' => $next_scheduled ? 'true' : 'false',
			),
		);

		return $metrics;
	}

	/**
	 * Collect security-related metrics
	 *
	 * @return array
	 */
	private static function collect_security_metrics() {
		$metrics = array();

		// 1. Failed logins in the current 24-hour window
		$failed_logins = netwarden_failed_logins_24h();
		$metrics[]     = array(
			'metric_name' => 'security_failed_logins',
			'value'       => $failed_logins,
			'labels'      => array( 'period' => '24h' ),
		);

		// 2. Admin user count (security risk if excessive). count_users() is
		// core's own role tally: one aggregate query, no user objects loaded.
		$metrics[] = array(
			'metric_name' => 'security_admin_users',
			'value'       => self::count_users_with_role( 'administrator' ),
			'labels'      => array(),
		);

		// 3. SSL certificate expiry monitoring
		$ssl_info = self::get_ssl_expiry();
		if ( null !== $ssl_info ) {
			$metrics[] = array(
				'metric_name' => 'ssl_days_remaining',
				'value'       => (int) $ssl_info['days_remaining'],
				'labels'      => array(
					'issuer'  => $ssl_info['issuer'],
					'expires' => $ssl_info['expiry_date'],
				),
			);
		}

		return $metrics;
	}

	/**
	 * Get SSL certificate expiry information
	 *
	 * @return array|null Array with days_remaining, issuer, expiry_date or null if not available
	 */
	private static function get_ssl_expiry() {
		// Whether the SITE is served over HTTPS, not whether this request
		// is: under a system cron or WP-CLI, is_ssl() is false for an HTTPS
		// site and the certificate would never be checked.
		if ( wp_parse_url( home_url(), PHP_URL_SCHEME ) !== 'https' ) {
			return null;
		}

		// Cache result for 12 hours to reduce overhead
		$cached = get_transient( 'netwarden_ssl_expiry' );
		if ( false !== $cached ) {
			return $cached;
		}

		try {
			$url = wp_parse_url( home_url(), PHP_URL_HOST );
			if ( ! $url ) {
				return null;
			}

			// A host that refuses the connection is a reading ("could not
			// check"), not a PHP warning worth a log line per cycle.
            // phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged -- Connection refusal is an expected outcome here and is handled below
			$stream = @stream_context_create(
				array(
					'ssl' => array(
						'capture_peer_cert' => true,
						'verify_peer'       => false,
						'verify_peer_name'  => false,
					),
				)
			);

			// Connect to get certificate
			$socket = @stream_socket_client(
				"ssl://{$url}:443",
				$errno,
				$errstr,
				10,
				STREAM_CLIENT_CONNECT,
				$stream
			);
            // phpcs:enable

			if ( ! $socket ) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
				error_log( "Netwarden: Failed to connect to {$url}:443 for SSL check: {$errstr}" );
				return null;
			}

			$params = stream_context_get_params( $socket );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Using fclose() for socket resource, not file operations
			fclose( $socket );

			if ( ! isset( $params['options']['ssl']['peer_certificate'] ) ) {
				return null;
			}

			// Parse certificate
			$cert_info = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
			if ( ! $cert_info ) {
				return null;
			}

			$expiry_timestamp = $cert_info['validTo_time_t'];
			$days_remaining   = floor( ( $expiry_timestamp - time() ) / 86400 );

			$result = array(
				'days_remaining' => $days_remaining,
				'issuer'         => isset( $cert_info['issuer']['O'] ) ? $cert_info['issuer']['O'] : 'Unknown',
				'expiry_date'    => gmdate( 'Y-m-d', $expiry_timestamp ),
			);

			// Cache for 12 hours
			set_transient( 'netwarden_ssl_expiry', $result, 12 * HOUR_IN_SECONDS );

			return $result;

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: SSL check failed - ' . $e->getMessage() );
			return null;
		}
	}



	/**
	 * Collect performance metrics
	 *
	 * @return array
	 */
	private static function collect_performance_metrics() {
		global $wpdb;
		$metrics = array();

		// 1. PHP Memory Usage
		$memory_usage = memory_get_usage( true );
		$memory_limit = wp_convert_hr_to_bytes( ini_get( 'memory_limit' ) );

		$metrics[] = array(
			'metric_name' => 'php_memory_usage_bytes',
			'value'       => (float) $memory_usage,
			'labels'      => array(),
		);

		$metrics[] = array(
			'metric_name' => 'php_memory_limit_bytes',
			'value'       => (float) $memory_limit,
			'labels'      => array(),
		);

		// A percentage of an unlimited memory_limit (-1) is not a number; the
		// series is absent rather than a zero that reads as "no memory used".
		if ( $memory_limit > 0 ) {
			$metrics[] = array(
				'metric_name' => 'php_memory_usage_percent',
				'value'       => round( ( $memory_usage / $memory_limit ) * 100, 2 ),
				'labels'      => array(),
			);
		}

		// 2. Database query count (current request)
		$metrics[] = array(
			'metric_name' => 'database_queries_count',
			'value'       => (int) $wpdb->num_queries,
			'labels'      => array( 'context' => 'cron' ),
		);

		// 3. Homepage load time, sampled every 5 minutes. A fetch that fails
		// produces no reading: 0 ms would claim the fastest page on earth.
		$page_load_ms = get_transient( 'netwarden_page_load_time' );
		if ( false === $page_load_ms ) {
			$start      = microtime( true );
			$response   = wp_remote_get(
				home_url(),
				array(
					'timeout'     => 10,
					'sslverify'   => false, // the certificate is measured separately; a bad one must not hide the load time
					'user-agent'  => 'Netwarden-WordPress/' . NETWARDEN_VERSION,
					'redirection' => 5,
				)
			);
			$elapsed_ms = round( ( microtime( true ) - $start ) * 1000, 2 );

			if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
				set_transient( 'netwarden_page_load_time', $elapsed_ms, 5 * MINUTE_IN_SECONDS );
				$page_load_ms = $elapsed_ms;
			} else {
				$page_load_ms = null;
			}
		}

		if ( null !== $page_load_ms ) {
			$metrics[] = array(
				'metric_name' => 'page_load_time',
				'value'       => (float) $page_load_ms,
				'labels'      => array(
					'url'    => 'homepage',
					'method' => 'internal',
				),
			);
		}

		// 4. PHP version info
		// Convert PHP version to numeric for value (e.g., "8.2.17" -> 8.217)
		// This allows numeric comparisons while keeping full version in labels
		$php_version_numeric = (float) ( PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . PHP_RELEASE_VERSION );

		$metrics[] = array(
			'metric_name' => 'php_version_info',
			'value'       => $php_version_numeric,
			'labels'      => array(
				'version' => PHP_VERSION,
				'major'   => (string) PHP_MAJOR_VERSION,
				'minor'   => (string) PHP_MINOR_VERSION,
				'release' => (string) PHP_RELEASE_VERSION,
			),
		);

		// 5. PHP max execution time
		$max_execution_time = (int) ini_get( 'max_execution_time' );
		$metrics[]          = array(
			'metric_name' => 'php_max_execution_time',
			'value'       => $max_execution_time,
			'labels'      => array(),
		);

		return $metrics;
	}

	/**
	 * Collect user activity metrics
	 *
	 * @return array
	 */
	private static function collect_user_activity_metrics() {
		$metrics = array();

		// Cache result for 30 minutes to reduce overhead
		$cached = get_transient( 'netwarden_user_activity' );
		if ( false !== $cached ) {
			return $cached;
		}

		try {
			global $wpdb;

			// 1. Total users count
			// Use direct SQL query instead of loading wp-includes/user.php
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Counting total users for metrics, results cached via transient
			$total_users = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );

			$metrics[] = array(
				'metric_name' => 'users_total',
				'value'       => (int) ( $total_users ? $total_users : 0 ),
				'labels'      => array(),
			);

			// 2. Active users (logged in within the past 7 days). One COUNT
			// over usermeta; get_users() would hydrate every matching user.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Aggregate count, cached via transient by the caller
			$active_users = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta}
                 WHERE meta_key = %s AND CAST(meta_value AS UNSIGNED) > %d",
					'netwarden_last_login',
					time() - ( 7 * DAY_IN_SECONDS )
				)
			);

			$metrics[] = array(
				'metric_name' => 'users_active_7d',
				'value'       => (int) $active_users,
				'labels'      => array( 'period' => '7d' ),
			);

			// 3. Role distribution, from core's aggregate tally. The old code
			// pulled every capabilities row and unserialized each one, which
			// on a large membership site was the plugin's heaviest query.
			$role_counts = self::role_counts();

			$role_map = array(
				'administrator' => 'users_role_admin',
				'editor'        => 'users_role_editor',
				'author'        => 'users_role_author',
				'contributor'   => 'users_role_contributor',
				'subscriber'    => 'users_role_subscriber',
			);

			foreach ( $role_map as $wp_role => $metric_name ) {
				$metrics[] = array(
					'metric_name' => $metric_name,
					'value'       => isset( $role_counts[ $wp_role ] ) ? (int) $role_counts[ $wp_role ] : 0,
					'labels'      => array( 'role' => $wp_role ),
				);
			}

			// Cache for 30 minutes
			set_transient( 'netwarden_user_activity', $metrics, 30 * MINUTE_IN_SECONDS );

			return $metrics;

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: User activity collection failed - ' . $e->getMessage() );
			return array();
		}
	}

	/**
	 * Collect database performance metrics
	 *
	 * @return array
	 */
	private static function collect_database_performance_metrics() {
		global $wpdb;
		$metrics = array();

		// Cache result for 5 minutes to reduce overhead
		$cached = get_transient( 'netwarden_db_performance' );
		if ( false !== $cached ) {
			return $cached;
		}

		try {
			// 1. Count active plugins (performance indicator)
			// Use WordPress option directly instead of loading admin files
			$active_plugins = get_option( 'active_plugins', array() );
			$active_count   = count( $active_plugins );

			// Count total installed plugins by scanning plugin directory
			$plugin_dir      = WP_PLUGIN_DIR;
			$total_installed = 0;
			if ( is_dir( $plugin_dir ) ) {
				$plugins         = array_filter( glob( $plugin_dir . '/*' ), 'is_dir' );
				$total_installed = count( $plugins );
			}

			$metrics[] = array(
				'metric_name' => 'plugins_active_count',
				'value'       => (int) $active_count,
				'labels'      => array(
					'total_installed' => (string) $total_installed,
				),
			);

			// 2. Slow query detection (if SAVEQUERIES is enabled or during cron)
			$slow_query_count = 0;
			$slowest_query_ms = 0;

			// Check if we can access query data
			if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES && isset( $wpdb->queries ) && is_array( $wpdb->queries ) ) {
				foreach ( $wpdb->queries as $query ) {
					// $query format: [SQL, execution_time, backtrace]
					if ( isset( $query[1] ) ) {
						$query_time_ms = $query[1] * 1000; // Convert to milliseconds

						if ( $query_time_ms > 1000 ) { // > 1 second
							++$slow_query_count;
						}

						if ( $query_time_ms > $slowest_query_ms ) {
							$slowest_query_ms = $query_time_ms;
						}
					}
				}

				$metrics[] = array(
					'metric_name' => 'database_slow_queries_count',
					'value'       => (int) $slow_query_count,
					'labels'      => array( 'threshold_ms' => '1000' ),
				);

				$metrics[] = array(
					'metric_name' => 'database_slowest_query_ms',
					'value'       => round( $slowest_query_ms, 2 ),
					'labels'      => array(),
				);
			}

			// Cache for 5 minutes
			set_transient( 'netwarden_db_performance', $metrics, 5 * MINUTE_IN_SECONDS );

			return $metrics;

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: Database performance collection failed - ' . $e->getMessage() );
			return array();
		}
	}

	/**
	 * Collect integration metrics from popular plugins
	 *
	 * @return array
	 */
	private static function collect_integration_metrics() {
		global $wpdb;
		$metrics = array();

		// Cache result for 30 minutes to reduce overhead
		$cached = get_transient( 'netwarden_integrations' );
		if ( false !== $cached ) {
			return $cached;
		}

		try {
			// 1. WooCommerce
			if ( class_exists( 'WooCommerce' ) ) {
				$metrics = array_merge( $metrics, self::collect_woocommerce_metrics() );
			}

			// 2. Yoast SEO Integration
			if ( defined( 'WPSEO_VERSION' ) ) {
				// Average SEO score across all posts
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Querying Yoast SEO scores for metrics
				$avg_score = $wpdb->get_var(
					"
                    SELECT AVG(CAST(meta_value AS UNSIGNED))
                    FROM {$wpdb->postmeta}
                    WHERE meta_key = '_yoast_wpseo_linkdex'
                    AND meta_value != ''
                    AND meta_value REGEXP '^[0-9]+$'
                "
				);

				$metrics[] = array(
					'metric_name' => 'seo_score_average',
					'value'       => round( (float) ( $avg_score ? $avg_score : 0 ), 2 ),
					'labels'      => array( 'plugin' => 'yoast' ),
				);
			}

			// 3. Backup Plugin Integration (UpdraftPlus)
			if ( class_exists( 'UpdraftPlus' ) ) {
				$last_backup = get_option( 'updraft_last_backup' );
				if ( $last_backup && isset( $last_backup['backup_time'] ) ) {
					$hours_since = floor( ( time() - $last_backup['backup_time'] ) / 3600 );

					$metrics[] = array(
						'metric_name' => 'backup_status',
						'value'       => (int) $hours_since,
						'labels'      => array( 'plugin' => 'updraftplus' ),
					);
				}
			}

			// 4. Contact Form 7 Integration
			if ( defined( 'WPCF7_VERSION' ) ) {
				// Count active forms
				$forms_count = wp_count_posts( 'wpcf7_contact_form' );

				$metrics[] = array(
					'metric_name' => 'contact_forms_count',
					'value'       => (int) ( isset( $forms_count->publish ) ? $forms_count->publish : 0 ),
					'labels'      => array( 'plugin' => 'cf7' ),
				);
			}

			// Cache for 30 minutes
			set_transient( 'netwarden_integrations', $metrics, 30 * MINUTE_IN_SECONDS );

			return $metrics;

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: Integration metrics collection failed - ' . $e->getMessage() );
			return array();
		}
	}

	/**
	 * WooCommerce: revenue, order counts and inventory.
	 *
	 * Orders live in one of two places. Since WooCommerce 8.2 new stores use
	 * High-Performance Order Storage (the wc_orders table); older stores keep
	 * orders as shop_order posts with meta. Reading only postmeta on an HPOS
	 * store returns nothing and used to report "$0 in sales, 0 orders" as if
	 * it were true. Revenue counts paid orders only — a cancelled or failed
	 * order is not a sale.
	 *
	 * @return array
	 */
	private static function collect_woocommerce_metrics() {
		global $wpdb;
		$metrics       = array();
		$since         = gmdate( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS );
		$paid_statuses = array( 'wc-completed', 'wc-processing' );

		$hpos = class_exists( 'Automattic\WooCommerce\Utilities\OrderUtil' )
			&& \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();

		if ( $hpos ) {
			$orders_table = $wpdb->prefix . 'wc_orders';
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is the WooCommerce HPOS table (prefix + constant); results cached via transient by the caller
			$sales = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT SUM(total_amount) FROM {$orders_table}
                 WHERE type = 'shop_order' AND status IN (%s, %s) AND date_created_gmt > %s",
					$paid_statuses[0],
					$paid_statuses[1],
					$since
				)
			);
            // phpcs:enable
		} else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Legacy order storage; results cached via transient by the caller
			$sales = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT SUM(pm.meta_value)
                 FROM {$wpdb->postmeta} pm
                 JOIN {$wpdb->posts} p ON pm.post_id = p.ID
                 WHERE pm.meta_key = '_order_total'
                 AND p.post_type = 'shop_order'
                 AND p.post_status IN (%s, %s)
                 AND p.post_date_gmt > %s",
					$paid_statuses[0],
					$paid_statuses[1],
					$since
				)
			);
		}

		$metrics[] = array(
			'metric_name' => 'woocommerce_sales_30d',
			'value'       => (float) ( $sales ? $sales : 0 ),
			'labels'      => array(
				'currency' => function_exists( 'get_woocommerce_currency' ) ? get_woocommerce_currency() : 'USD',
				'statuses' => 'completed,processing',
			),
		);

		// Order counts by status. wc_orders_count() reads whichever storage
		// is active; it exists since WooCommerce 3.x.
		$count_orders = function ( $status ) {
			if ( function_exists( 'wc_orders_count' ) ) {
				return (int) wc_orders_count( $status );
			}
			$counts = wp_count_posts( 'shop_order' );
			$key    = 'wc-' . $status;
			return (int) ( isset( $counts->{$key} ) ? $counts->{$key} : 0 );
		};
		$metrics[]    = array(
			'metric_name' => 'woocommerce_orders_pending',
			'value'       => $count_orders( 'pending' ),
			'labels'      => array(),
		);
		$metrics[]    = array(
			'metric_name' => 'woocommerce_orders_processing',
			'value'       => $count_orders( 'processing' ),
			'labels'      => array(),
		);

		$product_counts = wp_count_posts( 'product' );
		$metrics[]      = array(
			'metric_name' => 'woocommerce_products_total',
			'value'       => (int) ( isset( $product_counts->publish ) ? $product_counts->publish : 0 ),
			'labels'      => array(),
		);

		// Out-of-stock products from the product lookup table (WooCommerce
		// 3.6+), which is indexed for exactly this; postmeta as the fallback.
		$lookup_table = $wpdb->prefix . 'wc_product_meta_lookup';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Existence check for an optional WooCommerce table
		$has_lookup = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lookup_table ) ) === $lookup_table;
		if ( $has_lookup ) {
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is the WooCommerce lookup table (prefix + constant); results cached via transient by the caller
			$out_of_stock = $wpdb->get_var(
				"SELECT COUNT(*) FROM {$lookup_table} l
                 JOIN {$wpdb->posts} p ON p.ID = l.product_id
                 WHERE l.stock_status = 'outofstock' AND p.post_status = 'publish'"
			);
            // phpcs:enable
		} else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Legacy stock status in postmeta; results cached via transient by the caller
			$out_of_stock = $wpdb->get_var(
				"SELECT COUNT(*)
                 FROM {$wpdb->postmeta} pm
                 JOIN {$wpdb->posts} p ON pm.post_id = p.ID
                 WHERE pm.meta_key = '_stock_status'
                 AND pm.meta_value = 'outofstock'
                 AND p.post_type = 'product'
                 AND p.post_status = 'publish'"
			);
		}
		$metrics[] = array(
			'metric_name' => 'woocommerce_products_out_of_stock',
			'value'       => (int) ( $out_of_stock ? $out_of_stock : 0 ),
			'labels'      => array(),
		);

		return $metrics;
	}

	/**
	 * Collect predictive metrics (Phase 4: AI & Automation)
	 *
	 * @return array
	 */
	private static function collect_predictive_metrics() {
		$metrics = array();

		// Cache result for 6 hours (predictions don't need real-time updates)
		$cached = get_transient( 'netwarden_predictive_metrics' );
		if ( false !== $cached ) {
			return $cached;
		}

		try {
			// NOTE: These predictions require backend to store historical data
			// Plugin can't query metrics_ts directly (it's in the backend database)
			// So we'll use WordPress options to track trends locally

			// 1. Disk space exhaustion prediction
			$disk_prediction = self::predict_disk_exhaustion();
			if ( $disk_prediction ) {
				$metrics[] = $disk_prediction;
			}

			// 2. Database growth prediction
			$db_prediction = self::predict_database_growth();
			if ( $db_prediction ) {
				$metrics[] = $db_prediction;
			}

			// 3. Health score
			$health_score = self::calculate_health_score();
			if ( null !== $health_score ) {
				$metrics[] = array(
					'metric_name' => 'health_score',
					'value'       => $health_score['score'],
					'labels'      => array(
						'grade'                 => $health_score['grade'],
						'security_deduction'    => (string) $health_score['deductions']['security'],
						'performance_deduction' => (string) $health_score['deductions']['performance'],
						'updates_deduction'     => (string) $health_score['deductions']['updates'],
						'capacity_deduction'    => (string) $health_score['deductions']['capacity'],
						'maintenance_deduction' => (string) $health_score['deductions']['maintenance'],
					),
				);
			}

			// Cache for 6 hours
			set_transient( 'netwarden_predictive_metrics', $metrics, 6 * HOUR_IN_SECONDS );

			return $metrics;

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: Predictive metrics collection failed - ' . $e->getMessage() );
			return array();
		}
	}

	/**
	 * Predict disk space exhaustion using linear regression
	 *
	 * @return array|null
	 */
	private static function predict_disk_exhaustion() {
		$history = get_option( 'netwarden_disk_usage_history', array() );
		if ( ! self::history_spans( $history, 7 * DAY_IN_SECONDS ) ) {
			return null; // a week of data is the least a trend can be read from
		}

		// Calculate trend (linear slope)
		$slope = self::calculate_linear_slope( $history );

		if ( $slope <= 0 ) {
			return null; // Disk usage stable or decreasing
		}

		// Get current usage
		$current_usage = end( $history )['value'];

		// Calculate days until 95% full
		$days_until_full = ( 95 - $current_usage ) / $slope;

		// Only alert if within 60 days
		if ( $days_until_full > 0 && $days_until_full < 60 ) {
			return array(
				'metric_name' => 'prediction_disk_exhaustion_days',
				'value'       => round( $days_until_full ),
				'labels'      => array(
					'current_usage_percent' => (string) round( $current_usage, 1 ),
					'daily_growth_percent'  => (string) round( $slope, 3 ),
					'threshold_percent'     => '95',
				),
			);
		}

		return null;
	}

	/**
	 * Predict database growth
	 *
	 * @return array|null
	 */
	private static function predict_database_growth() {
		$history = get_option( 'netwarden_db_size_history', array() );
		if ( ! self::history_spans( $history, 7 * DAY_IN_SECONDS ) ) {
			return null; // a week of data is the least a trend can be read from
		}

		// Calculate trend (linear slope in bytes per day)
		$slope = self::calculate_linear_slope( $history );

		if ( $slope <= 0 ) {
			return null; // Database stable or shrinking
		}

		// Convert to MB per day
		$growth_mb_per_day = $slope / ( 1024 * 1024 );

		// Only report if significant growth (>10MB/day)
		if ( $growth_mb_per_day > 10 ) {
			return array(
				'metric_name' => 'prediction_database_growth_mb_per_day',
				'value'       => round( $growth_mb_per_day, 2 ),
				'labels'      => array(
					'current_size_mb' => (string) round( end( $history )['value'] / ( 1024 * 1024 ), 2 ),
				),
			);
		}

		return null;
	}

	/**
	 * Calculate linear slope (growth rate) from time series data
	 *
	 * @param array $history Array of ['timestamp' => int, 'value' => float]
	 * @return float Slope (change per day)
	 */
	private static function calculate_linear_slope( $history ) {
		$n = count( $history );
		if ( $n < 2 ) {
			return 0;
		}

		// Convert to x,y coordinates (x = days since start, y = value)
		$first_timestamp = $history[0]['timestamp'];
		$sum_x           = 0;
		$sum_y           = 0;
		$sum_xy          = 0;
		$sum_x2          = 0;

		foreach ( $history as $point ) {
			$x = ( $point['timestamp'] - $first_timestamp ) / DAY_IN_SECONDS; // Days since start
			$y = $point['value'];

			$sum_x  += $x;
			$sum_y  += $y;
			$sum_xy += $x * $y;
			$sum_x2 += $x * $x;
		}

		// Calculate slope: (n*Σxy - Σx*Σy) / (n*Σx² - (Σx)²)
		$denominator = ( $n * $sum_x2 ) - ( $sum_x * $sum_x );

		if ( 0.0 === (float) $denominator ) {
			return 0;
		}

		$slope = ( ( $n * $sum_xy ) - ( $sum_x * $sum_y ) ) / $denominator;

		return $slope;
	}


	/**
	 * Calculate overall health score (0-100)
	 *
	 * @return array|null ['score' => int, 'grade' => string, 'deductions' => array], or null when it cannot be computed
	 */
	private static function calculate_health_score() {
		$score      = 100; // Start perfect
		$deductions = array(
			'security'    => 0,
			'performance' => 0,
			'updates'     => 0,
			'capacity'    => 0,
			'maintenance' => 0,
		);

		try {
			// Security deductions (max -30 points)
			$failed_logins = netwarden_failed_logins_24h();
			if ( $failed_logins > 100 ) {
				$deductions['security'] += 20;
			} elseif ( $failed_logins > 50 ) {
				$deductions['security'] += 15;
			} elseif ( $failed_logins > 20 ) {
				$deductions['security'] += 10;
			}

			$admin_count = self::count_users_with_role( 'administrator' );
			if ( $admin_count > 10 ) {
				$deductions['security'] += 10;
			} elseif ( $admin_count > 5 ) {
				$deductions['security'] += 5;
			}

			// Performance deductions (max -25 points)
			$active_plugins = count( get_option( 'active_plugins', array() ) );
			if ( $active_plugins > 50 ) {
				$deductions['performance'] += 15;
			} elseif ( $active_plugins > 30 ) {
				$deductions['performance'] += 10;
			} elseif ( $active_plugins > 20 ) {
				$deductions['performance'] += 5;
			}

			// Updates deductions (max -20 points)
			$total_updates = (int) get_transient( 'netwarden_total_updates_count' );
			if ( $total_updates > 50 ) {
				$deductions['updates'] += 20;
			} elseif ( $total_updates > 20 ) {
				$deductions['updates'] += 15;
			} elseif ( $total_updates > 10 ) {
				$deductions['updates'] += 10;
			} elseif ( $total_updates > 5 ) {
				$deductions['updates'] += 5;
			}

			// Capacity deductions (max -15 points)
			$disk_usage_history = get_option( 'netwarden_disk_usage_history', array() );
			if ( ! empty( $disk_usage_history ) ) {
				$current_disk = end( $disk_usage_history )['value'];
				if ( $current_disk > 95 ) {
					$deductions['capacity'] += 15;
				} elseif ( $current_disk > 85 ) {
					$deductions['capacity'] += 10;
				} elseif ( $current_disk > 75 ) {
					$deductions['capacity'] += 5;
				}
			}

			// Maintenance deductions (max -10 points)
			if ( class_exists( 'UpdraftPlus' ) ) {
				$last_backup = get_option( 'updraft_last_backup' );
				if ( $last_backup && isset( $last_backup['backup_time'] ) ) {
					$hours_since = floor( ( time() - $last_backup['backup_time'] ) / 3600 );
					if ( $hours_since > 336 ) { // >14 days
						$deductions['maintenance'] += 10;
					} elseif ( $hours_since > 168 ) { // >7 days
						$deductions['maintenance'] += 5;
					}
				}
			} else {
				$deductions['maintenance'] += 10; // No backup plugin
			}

			// Calculate final score
			$total_deductions = array_sum( $deductions );
			$final_score      = max( 0, $score - $total_deductions );

			// Determine grade
			$grade = self::score_to_grade( $final_score );

			return array(
				'score'      => $final_score,
				'grade'      => $grade,
				'deductions' => $deductions,
			);

		} catch ( Exception $e ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden: Health score calculation failed - ' . $e->getMessage() );
			// No score is better than an invented one: a "C" nobody computed
			// would sit on the dashboard looking like a verdict.
			return null;
		}
	}

	/**
	 * Convert numeric score to letter grade
	 *
	 * @param int $score
	 * @return string
	 */
	private static function score_to_grade( $score ) {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 75 ) {
			return 'B';
		}
		if ( $score >= 60 ) {
			return 'C';
		}
		if ( $score >= 40 ) {
			return 'D';
		}
		return 'F';
	}

	/**
	 * How often a trend sample is kept, and how long. Sampling every cycle
	 * used to append a point per MINUTE to a 30-day window — 43,000 points,
	 * ~1.7 MB of serialized option read, unserialized and rewritten on
	 * every run. One point an hour (720 over 30 days) is more than the
	 * regression needs and costs a write an hour instead of a minute.
	 */
	const HISTORY_SAMPLE_INTERVAL = HOUR_IN_SECONDS;
	const HISTORY_RETENTION       = 30 * DAY_IN_SECONDS;

	/**
	 * Track historical data for trend analysis
	 * Stores key metrics locally for predictions
	 *
	 * @param array $metrics Current metrics array
	 * @return void
	 */
	private static function track_historical_data( $metrics ) {
		$tracked = array(
			'disk_usage_percent:/' => 'netwarden_disk_usage_history',
			'database_size_bytes'  => 'netwarden_db_size_history',
		);
		foreach ( $metrics as $metric ) {
			if ( isset( $tracked[ $metric['metric_name'] ] ) ) {
				self::append_history( $tracked[ $metric['metric_name'] ], (float) $metric['value'] );
			}
		}

		// Store update counts for recommendations
		foreach ( $metrics as $metric ) {
			if ( 'system_updates_available_count' === $metric['metric_name'] ) {
				set_transient( 'netwarden_wp_updates_count', $metric['value'], 6 * HOUR_IN_SECONDS );
			}
			if ( 'plugin_updates_available_count' === $metric['metric_name'] ) {
				set_transient( 'netwarden_plugin_updates_count', $metric['value'], 6 * HOUR_IN_SECONDS );
			}
			if ( 'theme_updates_available_count' === $metric['metric_name'] ) {
				set_transient( 'netwarden_theme_updates_count', $metric['value'], 6 * HOUR_IN_SECONDS );
			}
		}

		// Calculate and store total updates count
		$wp      = (int) get_transient( 'netwarden_wp_updates_count' );
		$plugins = (int) get_transient( 'netwarden_plugin_updates_count' );
		$themes  = (int) get_transient( 'netwarden_theme_updates_count' );
		set_transient( 'netwarden_total_updates_count', $wp + $plugins + $themes, 6 * HOUR_IN_SECONDS );
	}

	/**
	 * Users per role, via count_users(). Cached for the request so the
	 * several callers in one cycle share a single query.
	 *
	 * @return array role => count
	 */
	private static function role_counts() {
		static $counts = null;
		if ( null === $counts ) {
			$tally  = count_users();
			$counts = isset( $tally['avail_roles'] ) && is_array( $tally['avail_roles'] ) ? $tally['avail_roles'] : array();
		}
		return $counts;
	}

	/**
	 * Number of users holding one role.
	 *
	 * @param string $role
	 * @return int
	 */
	private static function count_users_with_role( $role ) {
		$counts = self::role_counts();
		return isset( $counts[ $role ] ) ? (int) $counts[ $role ] : 0;
	}

	/**
	 * Append one sample to a history option, at most once per
	 * HISTORY_SAMPLE_INTERVAL, keeping HISTORY_RETENTION of samples.
	 *
	 * @param string $option
	 * @param float  $value
	 */
	private static function append_history( $option, $value ) {
		$now     = time();
		$history = get_option( $option, array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}

		$last = end( $history );
		if ( $last && isset( $last['timestamp'] ) && ( $now - (int) $last['timestamp'] ) < self::HISTORY_SAMPLE_INTERVAL ) {
			return; // sampled recently; nothing to write
		}

		$history[] = array(
			'timestamp' => $now,
			'value'     => $value,
		);
		$history   = array_values(
			array_filter(
				$history,
				function ( $point ) use ( $now ) {
					return isset( $point['timestamp'] ) && $point['timestamp'] > ( $now - self::HISTORY_RETENTION );
				}
			)
		);
		update_option( $option, $history, false );
	}

	/**
	 * Whether a history covers at least the given span of time. Predictions
	 * need a week of data; counting samples said nothing about that once
	 * sampling stopped being one-per-minute.
	 *
	 * @param array $history
	 * @param int   $span_seconds
	 * @return bool
	 */
	private static function history_spans( $history, $span_seconds ) {
		if ( count( $history ) < 2 ) {
			return false;
		}
		$first = reset( $history );
		$last  = end( $history );
		return isset( $first['timestamp'], $last['timestamp'] )
			&& ( $last['timestamp'] - $first['timestamp'] ) >= $span_seconds;
	}

	/**
	 * Format a single metric into Netwarden API format
	 *
	 * @param array $metric Raw metric data
	 * @return array Formatted metric
	 */
	public static function format_metric( $metric ) {
		return array(
			'host_id'     => self::get_hostname(),
			'metric_name' => $metric['metric_name'],
			'value'       => $metric['value'],
			'timestamp'   => self::get_rfc3339_timestamp(),
			'labels'      => isset( $metric['labels'] ) ? $metric['labels'] : array(),
		);
	}

	/**
	 * The identity this site reports under: the site URL's host, which is
	 * what a person recognises, with a stable hash as the fallback.
	 *
	 * @return string
	 */
	public static function get_hostname() {
		// Use site URL as hostname identifier
		$site_url = get_site_url();
		$parsed   = wp_parse_url( $site_url );

		if ( isset( $parsed['host'] ) && ! empty( $parsed['host'] ) ) {
			return $parsed['host'];
		}

		// Create unique fallback using database name and site URL hash
		$unique_id = substr( md5( DB_NAME . $site_url ), 0, 12 );
		return 'wp-' . $unique_id;
	}

	/**
	 * Get current timestamp in RFC3339 format
	 *
	 * @return string
	 */
	private static function get_rfc3339_timestamp() {
		return gmdate( 'Y-m-d\TH:i:s\Z' );
	}
}
