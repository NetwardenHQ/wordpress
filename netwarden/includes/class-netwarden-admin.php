<?php
/**
 * Netwarden Admin Class
 *
 * Handles WordPress admin interface and settings
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class Netwarden_Admin {

    /**
     * Constructor
     */
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_action('wp_ajax_netwarden_save_credentials', array($this, 'ajax_save_credentials'));
        add_action('wp_ajax_netwarden_test_connection', array($this, 'ajax_test_connection'));
        add_action('wp_ajax_netwarden_delete_credentials', array($this, 'ajax_delete_credentials'));
        add_filter('plugin_action_links_' . NETWARDEN_PLUGIN_BASENAME, array($this, 'add_plugin_action_links'));
    }

    /**
     * Check rate limit for an action
     *
     * @param string $action Action name
     * @param int $max_requests Maximum requests allowed
     * @param int $time_window Time window in seconds
     * @return bool True if rate limit exceeded
     */
    private function is_rate_limited($action, $max_requests = 3, $time_window = MINUTE_IN_SECONDS) {
        $user_id = get_current_user_id();
        $transient_key = 'netwarden_ratelimit_' . $action . '_' . $user_id;
        $rate_data = get_transient($transient_key);

        $now = time();

        if ($rate_data === false) {
            // First request in window - store count and start time
            set_transient($transient_key, array('count' => 1, 'start' => $now), $time_window);
            return false;
        }

        // Check if we're still in the same time window
        if (($now - $rate_data['start']) >= $time_window) {
            // Window expired - start new window
            set_transient($transient_key, array('count' => 1, 'start' => $now), $time_window);
            return false;
        }

        // Still in same window - check if limit exceeded
        if ($rate_data['count'] >= $max_requests) {
            return true;
        }

        // Increment counter (preserve original start time and TTL)
        $rate_data['count']++;
        $remaining_ttl = $time_window - ($now - $rate_data['start']);
        set_transient($transient_key, $rate_data, max(1, $remaining_ttl));
        return false;
    }

    /**
     * Add admin menu items
     */
    public function add_admin_menu() {
        add_menu_page(
            'Netwarden',
            'Netwarden',
            'manage_options',
            'netwarden-settings',
            array($this, 'render_settings_page'),
            NETWARDEN_PLUGIN_URL . 'images/netwarden.png',
            100
        );
    }

    /**
     * Enqueue admin CSS and JavaScript
     */
    public function enqueue_admin_assets($hook) {
        // Only load on our settings page
        if ($hook !== 'toplevel_page_netwarden-settings') {
            return;
        }

        wp_enqueue_style(
            'netwarden-admin-css',
            NETWARDEN_PLUGIN_URL . 'admin/css/admin-styles.css',
            array(),
            NETWARDEN_VERSION
        );

        wp_enqueue_script(
            'netwarden-admin-js',
            NETWARDEN_PLUGIN_URL . 'admin/js/admin-scripts.js',
            array('jquery'),
            NETWARDEN_VERSION,
            true
        );

        // Pass data to JavaScript
        wp_localize_script('netwarden-admin-js', 'netwardenAdmin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('netwarden_admin_nonce'),
        ));
    }

    /**
     * Render settings page
     */
    public function render_settings_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'netwarden'));
        }

        // Get current credentials
        $credentials = Netwarden_DB::get_credentials();
        $is_configured = !empty($credentials);

        // Check if this is the welcome screen (sanitize GET parameter to prevent XSS)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Simple display parameter, no action performed
        $show_welcome = isset($_GET['welcome']) && sanitize_text_field(wp_unslash($_GET['welcome'])) === '1';

        // Get last submission time
        $last_submission = get_option('netwarden_last_submission');

        // Get error tracking for display
        $consecutive_errors = (int) get_option('netwarden_consecutive_errors', 0);
        $last_error = get_option('netwarden_last_error', '');

        include NETWARDEN_PLUGIN_DIR . 'admin/views/settings-page.php';
    }

    /**
     * AJAX handler: Save credentials
     */
    public function ajax_save_credentials() {
        // Verify nonce
        check_ajax_referer('netwarden_admin_nonce', 'nonce');

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => esc_html__('Insufficient permissions', 'netwarden')));
        }

        // Get and sanitize inputs
        $tenant_id = isset($_POST['tenant_id']) ? sanitize_text_field(wp_unslash($_POST['tenant_id'])) : '';
        $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';

        // Validate inputs
        if (empty($tenant_id) || empty($api_key)) {
            wp_send_json_error(array('message' => esc_html__('Tenant ID and API Key are required', 'netwarden')));
        }

        if (!preg_match('/^[a-zA-Z0-9]{10}$/', $tenant_id)) {
            wp_send_json_error(array('message' => esc_html__('Tenant ID must be exactly 10 alphanumeric characters', 'netwarden')));
        }

        if (strlen($api_key) > 200) {
            wp_send_json_error(array('message' => esc_html__('API Key is too long (maximum 200 characters)', 'netwarden')));
        }

        if (strpos($api_key, 'nw_sk_') !== 0) {
            wp_send_json_error(array('message' => esc_html__('API Key must start with nw_sk_', 'netwarden')));
        }

        // Save credentials
        $saved = Netwarden_DB::save_credentials($tenant_id, $api_key);

        if ($saved) {
            wp_send_json_success(array('message' => esc_html__('Credentials saved successfully', 'netwarden')));
        } else {
            wp_send_json_error(array('message' => esc_html__('Failed to save credentials', 'netwarden')));
        }
    }

    /**
     * AJAX handler: Test connection and send metrics
     */
    public function ajax_test_connection() {
        // Verify nonce
        check_ajax_referer('netwarden_admin_nonce', 'nonce');

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => esc_html__('Insufficient permissions', 'netwarden')));
        }

        // Rate limiting: max 5 requests per minute
        if ($this->is_rate_limited('test_connection', 5, MINUTE_IN_SECONDS)) {
            wp_send_json_error(array('message' => esc_html__('Too many requests. Please wait before trying again.', 'netwarden')));
        }

        // Get credentials
        $credentials = Netwarden_DB::get_credentials();

        if (!$credentials) {
            wp_send_json_error(array('message' => esc_html__('No credentials configured', 'netwarden')));
        }

        // Collect and send all metrics (not just test metric)
        $metrics = Netwarden_Metrics::collect_all();

        if (empty($metrics)) {
            wp_send_json_error(array('message' => esc_html__('No metrics collected', 'netwarden')));
        }

        // Send to API
        $api = new Netwarden_API($credentials['tenant_id'], $credentials['api_key']);
        $result = $api->send_metrics($metrics);

        if ($result['success']) {
            // Update last submission timestamp
            update_option('netwarden_last_submission', time());
            delete_option('netwarden_consecutive_errors');
            delete_option('netwarden_last_error');

            wp_send_json_success(array(
                /* translators: %s: API latency in milliseconds */
                'message' => sprintf(esc_html__('Connection successful! Metrics sent. Latency: %sms', 'netwarden'), number_format_i18n($result['latency_ms'])),
                'latency_ms' => $result['latency_ms']
            ));
        } else {
            // Track error
            $error_count = (int) get_option('netwarden_consecutive_errors', 0);
            update_option('netwarden_consecutive_errors', $error_count + 1);
            update_option('netwarden_last_error', $result['message']);

            wp_send_json_error(array(
                /* translators: %s: Error message from API */
                'message' => sprintf(esc_html__('Connection failed: %s', 'netwarden'), esc_html($result['message']))
            ));
        }
    }

    /**
     * AJAX handler: Delete credentials
     */
    public function ajax_delete_credentials() {
        // Verify nonce
        check_ajax_referer('netwarden_admin_nonce', 'nonce');

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => esc_html__('Insufficient permissions', 'netwarden')));
        }

        // Delete credentials
        $deleted = Netwarden_DB::delete_credentials();

        if ($deleted) {
            // Clear all tracking data
            delete_option('netwarden_last_submission');
            delete_option('netwarden_consecutive_errors');
            delete_option('netwarden_last_error');

            // Clear user's dismissed error notice
            delete_user_meta(get_current_user_id(), 'netwarden_error_dismissed');

            wp_send_json_success(array('message' => esc_html__('Credentials deleted successfully', 'netwarden')));
        } else {
            wp_send_json_error(array('message' => esc_html__('Failed to delete credentials', 'netwarden')));
        }
    }

    /**
     * Add Settings link to plugin actions on Plugins page
     *
     * @param array $links Existing plugin action links
     * @return array Modified plugin action links
     */
    public function add_plugin_action_links($links) {
        $settings_link = sprintf(
            '<a href="%s">%s</a>',
            esc_url(admin_url('admin.php?page=netwarden-settings')),
            esc_html__('Settings', 'netwarden')
        );
        array_unshift($links, $settings_link);
        return $links;
    }
}
