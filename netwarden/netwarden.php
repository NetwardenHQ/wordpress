<?php
/**
 * Plugin Name: Netwarden
 * Plugin URI: https://netwarden.com/wordpress
 * Description: Enterprise-grade infrastructure monitoring for WordPress sites with predictive alerts, automated recommendations, and health scoring. Monitor everything: database, security, performance, plugins, backups, and more.
 * Version: 1.0.0
 * Author: Netwarden
 * Author URI: https://netwarden.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: netwarden
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants (with guards to prevent redefinition)
if (!defined('NETWARDEN_VERSION')) {
    define('NETWARDEN_VERSION', '1.0.0');
}
if (!defined('NETWARDEN_PLUGIN_DIR')) {
    define('NETWARDEN_PLUGIN_DIR', plugin_dir_path(__FILE__));
}
if (!defined('NETWARDEN_PLUGIN_URL')) {
    define('NETWARDEN_PLUGIN_URL', plugin_dir_url(__FILE__));
}
if (!defined('NETWARDEN_PLUGIN_BASENAME')) {
    define('NETWARDEN_PLUGIN_BASENAME', plugin_basename(__FILE__));
}

// Require class files
require_once NETWARDEN_PLUGIN_DIR . 'includes/class-netwarden-db.php';
require_once NETWARDEN_PLUGIN_DIR . 'includes/class-netwarden-metrics.php';
require_once NETWARDEN_PLUGIN_DIR . 'includes/class-netwarden-api.php';
require_once NETWARDEN_PLUGIN_DIR . 'includes/class-netwarden-admin.php';
require_once NETWARDEN_PLUGIN_DIR . 'includes/class-netwarden-security.php';

/**
 * Activation hook - runs when plugin is activated
 */
function netwarden_activate() {
    // Check for required PHP extensions
    if (!function_exists('openssl_encrypt')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            '<h1>' . esc_html__('Netwarden Plugin Error', 'netwarden') . '</h1>' .
            '<p>' . esc_html__('The Netwarden plugin requires the OpenSSL PHP extension, which is not available on this server.', 'netwarden') . '</p>' .
            '<p>' . esc_html__('Please contact your hosting provider to enable the OpenSSL extension.', 'netwarden') . '</p>' .
            '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('Return to Plugins', 'netwarden') . '</a></p>',
            esc_html__('Missing Required Extension', 'netwarden'),
            array('response' => 500)
        );
    }

    // Check for WordPress Multisite (warn but allow activation)
    if (is_multisite()) {
        // Set persistent option to show multisite warning
        update_option('netwarden_multisite_warning', true);
    }

    // Create database table and verify success
    if (!Netwarden_DB::create_table()) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            '<h1>' . esc_html__('Netwarden Plugin Error', 'netwarden') . '</h1>' .
            '<p>' . esc_html__('Failed to create the required database table. This could be due to insufficient database permissions.', 'netwarden') . '</p>' .
            '<p>' . esc_html__('Please check your WordPress database user has CREATE TABLE privileges.', 'netwarden') . '</p>' .
            '<p><a href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('Return to Plugins', 'netwarden') . '</a></p>',
            esc_html__('Database Table Creation Failed', 'netwarden'),
            array('response' => 500)
        );
    }

    // Schedule cron event for metric collection
    // Clear any existing schedules first to prevent race conditions and duplicates
    wp_clear_scheduled_hook('netwarden_collect_metrics');
    // Schedule every minute (custom interval)
    wp_schedule_event(time(), 'netwarden_1min', 'netwarden_collect_metrics');

    // Set flag to show welcome screen
    set_transient('netwarden_activation_redirect', true, 30);
}
register_activation_hook(__FILE__, 'netwarden_activate');

/**
 * Deactivation hook - runs when plugin is deactivated
 */
function netwarden_deactivate() {
    // Clear ALL scheduled cron events for this hook
    // Using wp_clear_scheduled_hook() instead of wp_unschedule_event()
    // to remove all instances (prevents duplicate cron jobs)
    wp_clear_scheduled_hook('netwarden_collect_metrics');
}
register_deactivation_hook(__FILE__, 'netwarden_deactivate');

/**
 * Uninstall hook - runs when plugin is deleted
 */
function netwarden_uninstall() {
    // Clear ALL scheduled cron events for this hook
    wp_clear_scheduled_hook('netwarden_collect_metrics');

    // Remove database table
    Netwarden_DB::drop_table();

    // Remove all options
    delete_option('netwarden_last_submission');
    delete_option('netwarden_consecutive_errors');
    delete_option('netwarden_last_error');
    delete_option('netwarden_multisite_warning');

    // Remove all transients
    delete_transient('netwarden_activation_redirect');
    delete_transient('netwarden_latest_wp_version');
    delete_transient('netwarden_last_latency_ms');
    delete_transient('netwarden_db_size');

    // Remove user meta for all users (error dismissal, cron dismissal)
    delete_metadata('user', 0, 'netwarden_error_dismissed', '', true);
    delete_metadata('user', 0, 'netwarden_cron_dismissed', '', true);

    // Clean up rate limiting transients (they expire naturally, but clean up for completeness)
    // Note: Transients clean themselves up, so we don't need to manually remove rate limit transients
}
register_uninstall_hook(__FILE__, 'netwarden_uninstall');

/**
 * Add custom cron interval (1 minute)
 */
function netwarden_add_cron_interval($schedules) {
    $schedules['netwarden_1min'] = array(
        'interval' => 60,
        'display'  => esc_html__('Every Minute', 'netwarden')
    );
    return $schedules;
}
add_filter('cron_schedules', 'netwarden_add_cron_interval');

/**
 * Cron job handler - collect and send metrics
 */
function netwarden_collect_and_send_metrics() {
    try {
        // Check if credentials are configured
        $credentials = Netwarden_DB::get_credentials();
        if (!$credentials) {
            return;
        }

        // Collect metrics
        $metrics = Netwarden_Metrics::collect_all();

        if (empty($metrics)) {
            return;
        }

        // Send to API
        $api = new Netwarden_API($credentials['tenant_id'], $credentials['api_key']);
        $result = $api->send_metrics($metrics);

        // Update last submission timestamp and error tracking
        if ($result['success']) {
            update_option('netwarden_last_submission', time());
            delete_option('netwarden_consecutive_errors');
            delete_option('netwarden_last_error');
        } else {
            // Track consecutive failures
            $error_count = (int) get_option('netwarden_consecutive_errors', 0);
            $error_count++;
            update_option('netwarden_consecutive_errors', $error_count);
            update_option('netwarden_last_error', $result['message']);

            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log(sprintf(
                'Netwarden: Metric submission failed (%d consecutive failures): %s',
                $error_count,
                $result['message']
            ));
        }
    } catch (Throwable $e) {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
        error_log('Netwarden: Exception in cron job - ' . get_class($e) . ': ' . $e->getMessage());

        // Track error
        $error_count = (int) get_option('netwarden_consecutive_errors', 0);
        update_option('netwarden_consecutive_errors', $error_count + 1);
        update_option('netwarden_last_error', $e->getMessage());
    }
}
add_action('netwarden_collect_metrics', 'netwarden_collect_and_send_metrics');

/**
 * Load plugin textdomain for translations
 * Note: For plugins in the WordPress.org directory, WordPress automatically handles translations
 * from translate.wordpress.org, so load_plugin_textdomain() is no longer necessary.
 */
// Removed load_plugin_textdomain() as it's discouraged for plugins in the WordPress.org directory since WP 4.6
// WordPress will automatically load translations from translate.wordpress.org

/**
 * Ensure cron is scheduled - defensive check on every load
 * This handles cases where cron schedule was lost or has wrong interval
 */
function netwarden_ensure_cron_scheduled() {
    $next_scheduled = wp_next_scheduled('netwarden_collect_metrics');

    // Check if cron exists and has correct interval
    if ($next_scheduled) {
        $cron = _get_cron_array();
        $found_correct_interval = false;

        // Check if the scheduled event has the correct interval (60 seconds)
        foreach ($cron as $timestamp => $cron_array) {
            foreach ($cron_array as $hook => $events) {
                if ($hook === 'netwarden_collect_metrics') {
                    foreach ($events as $event) {
                        if (isset($event['schedule']) && $event['schedule'] === 'netwarden_1min') {
                            $found_correct_interval = true;
                            break 3;
                        }
                    }
                }
            }
        }

        // If interval is wrong, clear and reschedule
        if (!$found_correct_interval) {
            wp_clear_scheduled_hook('netwarden_collect_metrics');
            wp_schedule_event(time(), 'netwarden_1min', 'netwarden_collect_metrics');
        }
    } else {
        // No cron scheduled - create it
        wp_schedule_event(time(), 'netwarden_1min', 'netwarden_collect_metrics');
    }
}
add_action('init', 'netwarden_ensure_cron_scheduled', 5);

/**
 * Initialize admin interface
 */
function netwarden_init_admin() {
    if (is_admin()) {
        new Netwarden_Admin();
    }
}
add_action('plugins_loaded', 'netwarden_init_admin');

/**
 * Enqueue admin scripts and styles
 */
function netwarden_enqueue_admin_scripts($hook) {
    // Only load on admin pages
    if (!is_admin()) {
        return;
    }

    // Enqueue admin scripts
    wp_enqueue_script(
        'netwarden-admin-scripts',
        NETWARDEN_PLUGIN_URL . 'admin/js/admin-scripts.js',
        array('jquery'),
        NETWARDEN_VERSION,
        true
    );

    // Localize script with nonces for notice dismissal
    wp_localize_script(
        'netwarden-admin-scripts',
        'netwardenNotices',
        array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'multisiteNonce' => wp_create_nonce('netwarden_dismiss_multisite'),
            'cronNonce' => wp_create_nonce('netwarden_dismiss_cron'),
            'errorNonce' => wp_create_nonce('netwarden_dismiss_error'),
        )
    );
}
add_action('admin_enqueue_scripts', 'netwarden_enqueue_admin_scripts');

/**
 * Redirect to welcome page on activation
 */
function netwarden_activation_redirect() {
    if (get_transient('netwarden_activation_redirect')) {
        delete_transient('netwarden_activation_redirect');
        // Only redirect if not bulk activation (sanitize GET parameter)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking WordPress core parameter during activation
        $is_bulk = isset($_GET['activate-multi']) && sanitize_key($_GET['activate-multi']);
        if (!$is_bulk) {
            wp_safe_redirect(admin_url('admin.php?page=netwarden-settings&welcome=1'));
            exit;
        }
    }
}
add_action('admin_init', 'netwarden_activation_redirect');

/**
 * Display admin notice for multisite installations
 */
function netwarden_admin_multisite_notice() {
    // Only show if multisite warning flag is set
    if (!get_option('netwarden_multisite_warning')) {
        return;
    }

    // Only show to admins
    if (!current_user_can('manage_options') || !is_admin()) {
        return;
    }

    ?>
    <div class="notice notice-warning is-dismissible" data-netwarden-notice="multisite">
        <p>
            <strong>Netwarden:</strong> This plugin is not fully tested on WordPress Multisite installations.
        </p>
        <p>
            Metrics may be inaccurate or incomplete. For best results, install Netwarden on individual WordPress sites.
        </p>
    </div>
    <?php
}
add_action('admin_notices', 'netwarden_admin_multisite_notice');

/**
 * Handle multisite notice dismissal
 */
function netwarden_handle_dismiss_multisite_notice() {
    check_ajax_referer('netwarden_dismiss_multisite', 'nonce');

    if (current_user_can('manage_options')) {
        delete_option('netwarden_multisite_warning');
        wp_send_json_success();
    } else {
        wp_send_json_error();
    }
}
add_action('wp_ajax_netwarden_dismiss_multisite_notice', 'netwarden_handle_dismiss_multisite_notice');

/**
 * Display admin notice for disabled WP-Cron
 */
function netwarden_admin_cron_notice() {
    // Check if WP-Cron is disabled
    if (!defined('DISABLE_WP_CRON') || !DISABLE_WP_CRON) {
        return;
    }

    // Only show to admins
    if (!current_user_can('manage_options') || !is_admin()) {
        return;
    }

    // Check if user dismissed this notice
    $dismissed = get_user_meta(get_current_user_id(), 'netwarden_cron_dismissed', true);
    if ($dismissed) {
        return;
    }

    ?>
    <div class="notice notice-warning is-dismissible" data-netwarden-notice="cron">
        <p>
            <strong>Netwarden:</strong> WordPress Cron (WP-Cron) is disabled on this site.
        </p>
        <p>
            The Netwarden plugin requires WP-Cron to collect metrics every minute. Since WP-Cron is disabled,
            you need to set up a system cron job to trigger WordPress cron events.
        </p>
        <p>
            Add this to your system crontab to run every minute:<br>
            <code>* * * * * wget -q -O - <?php echo esc_url(site_url('wp-cron.php')); ?> &>/dev/null</code>
        </p>
        <p>
            Or using curl:<br>
            <code>* * * * * curl -s <?php echo esc_url(site_url('wp-cron.php')); ?> &>/dev/null</code>
        </p>
    </div>
    <?php
}
add_action('admin_notices', 'netwarden_admin_cron_notice');

/**
 * Handle cron notice dismissal
 */
function netwarden_handle_dismiss_cron_notice() {
    check_ajax_referer('netwarden_dismiss_cron', 'nonce');

    if (current_user_can('manage_options')) {
        update_user_meta(get_current_user_id(), 'netwarden_cron_dismissed', time());
        wp_send_json_success();
    } else {
        wp_send_json_error();
    }
}
add_action('wp_ajax_netwarden_dismiss_cron_notice', 'netwarden_handle_dismiss_cron_notice');

/**
 * AJAX endpoint: Cron status (for backend health checks)
 *
 * This endpoint allows the Netwarden backend to check the status
 * of the WordPress cron scheduling and last metric submission.
 * Secured with backend authentication.
 */
function netwarden_cron_status() {
    // Verify backend authentication
    if (!Netwarden_Security::verify_backend_request()) {
        Netwarden_Security::send_unauthorized_response();
        return;
    }

    // Rate limiting: max 60 requests per minute
    if (Netwarden_Security::is_rate_limited('cron_status', 60, MINUTE_IN_SECONDS)) {
        wp_send_json_error(array('message' => esc_html__('Rate limit exceeded', 'netwarden')), 429);
        return;
    }

    // Get cron status
    $next_scheduled = wp_next_scheduled('netwarden_collect_metrics');
    $last_submission = get_option('netwarden_last_submission', 0);
    $credentials = Netwarden_DB::get_credentials();

    wp_send_json_success(array(
        'cron_enabled' => !defined('DISABLE_WP_CRON') || !DISABLE_WP_CRON,
        'next_scheduled' => $next_scheduled ? $next_scheduled : null,
        'next_scheduled_in' => $next_scheduled ? max(0, $next_scheduled - time()) : null,
        'last_submission' => $last_submission ? $last_submission : null,
        'last_submission_ago' => $last_submission ? time() - $last_submission : null,
        'configured' => !empty($credentials),
        'timestamp' => time()
    ));
}
add_action('wp_ajax_nopriv_netwarden_cron_status', 'netwarden_cron_status');

/**
 * Display admin notice for consecutive errors
 */
function netwarden_admin_error_notice() {
    // Only show to admins on admin pages
    if (!current_user_can('manage_options') || !is_admin()) {
        return;
    }

    $error_count = (int) get_option('netwarden_consecutive_errors', 0);

    // Show notice after 5 consecutive failures
    if ($error_count >= 5) {
        $last_error = get_option('netwarden_last_error', 'Unknown error');
        $dismissed = get_user_meta(get_current_user_id(), 'netwarden_error_dismissed', true);

        // Don't show if user dismissed it recently (within last hour)
        if ($dismissed && (time() - (int)$dismissed) < HOUR_IN_SECONDS) {
            return;
        }

        ?>
        <div class="notice notice-error is-dismissible" data-netwarden-notice="error">
            <p>
                <strong>Netwarden:</strong> Metric submission has failed <?php echo esc_html($error_count); ?> consecutive times.
            </p>
            <p>
                Last error: <?php echo esc_html($last_error); ?>
            </p>
            <p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=netwarden-settings')); ?>">
                    Check Netwarden Settings
                </a>
            </p>
        </div>
        <?php
    }
}
add_action('admin_notices', 'netwarden_admin_error_notice');

/**
 * Handle error notice dismissal
 */
function netwarden_handle_dismiss_error_notice() {
    check_ajax_referer('netwarden_dismiss_error', 'nonce');

    if (current_user_can('manage_options')) {
        update_user_meta(get_current_user_id(), 'netwarden_error_dismissed', time());
        wp_send_json_success();
    } else {
        wp_send_json_error();
    }
}
add_action('wp_ajax_netwarden_dismiss_error_notice', 'netwarden_handle_dismiss_error_notice');

/**
 * Track failed login attempts (security metric)
 */
function netwarden_track_failed_login($username) {
    $count = (int) get_option('netwarden_failed_logins_24h', 0);
    update_option('netwarden_failed_logins_24h', $count + 1);

    // Set transient to expire in 24 hours - this will auto-reset the counter
    // Store the last reset time
    if (!get_option('netwarden_failed_logins_reset_time')) {
        update_option('netwarden_failed_logins_reset_time', time());
    }

    // Reset counter if 24 hours have passed
    $reset_time = get_option('netwarden_failed_logins_reset_time', time());
    if (time() - $reset_time > DAY_IN_SECONDS) {
        update_option('netwarden_failed_logins_24h', 1);
        update_option('netwarden_failed_logins_reset_time', time());
    }
}
add_action('wp_login_failed', 'netwarden_track_failed_login');

/**
 * Track last login timestamp (user activity metric)
 */
function netwarden_track_last_login($user_login, $user) {
    // Store last login timestamp in user meta
    update_user_meta($user->ID, 'netwarden_last_login', time());
}
add_action('wp_login', 'netwarden_track_last_login', 10, 2);
