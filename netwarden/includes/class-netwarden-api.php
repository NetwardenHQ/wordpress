<?php
/**
 * Netwarden API Class
 *
 * Handles communication with Netwarden API endpoint
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class Netwarden_API {

    /**
     * API endpoint URL
     */
    const API_ENDPOINT = 'https://api.netwarden.com/agent/data';

    /**
     * Tenant ID
     */
    private $tenant_id;

    /**
     * API Key
     */
    private $api_key;

    /**
     * Constructor
     *
     * @param string $tenant_id
     * @param string $api_key
     */
    public function __construct($tenant_id, $api_key) {
        $this->tenant_id = $tenant_id;
        $this->api_key = $api_key;
    }

    /**
     * Send metrics to Netwarden API
     *
     * @param array $metrics Raw metrics array
     * @return array Result array with 'success' and 'message' keys
     */
    public function send_metrics($metrics) {
        // Format metrics according to API specification
        $formatted_metrics = array();
        foreach ($metrics as $metric) {
            $formatted_metrics[] = Netwarden_Metrics::format_metric($metric);
        }

        // Build payload matching Go agent format
        $payload = $this->build_payload($formatted_metrics);

        // Encode payload to JSON with error handling
        $json_body = json_encode($payload);
        if ($json_body === false) {
            $error_msg = 'Failed to encode metrics payload: ' . json_last_error_msg();
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden API: ' . $error_msg);
            return array(
                'success' => false,
                'message' => $error_msg,
                'latency_ms' => 0
            );
        }

        // Measure API latency
        $start = microtime(true);

        // Send request
        $response = wp_remote_post(self::API_ENDPOINT, array(
            'headers' => array(
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $this->api_key,
            ),
            'body' => $json_body,
            'timeout' => 15,
            'sslverify' => true,
        ));

        // Calculate latency
        $latency_ms = round((microtime(true) - $start) * 1000, 2);

        // Store latency for next metric collection using persistent option
        // Use update_option instead of transient to avoid expiration timing issues with WordPress cron
        update_option('netwarden_last_latency_ms', $latency_ms, false);

        // Check for errors
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden API: HTTP error - ' . $error_message);
            return array(
                'success' => false,
                'message' => $error_message,
                'latency_ms' => $latency_ms
            );
        }

        // Get response code
        $response_code = wp_remote_retrieve_response_code($response);

        if ($response_code !== 200 && $response_code !== 201) {
            $body = wp_remote_retrieve_body($response);
            $error_message = sprintf('API returned status %d: %s', $response_code, $body);
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden API: ' . $error_message);
            return array(
                'success' => false,
                'message' => $error_message,
                'latency_ms' => $latency_ms
            );
        }

        // Success
        return array(
            'success' => true,
            'message' => 'Metrics sent successfully',
            'latency_ms' => $latency_ms
        );
    }

    /**
     * Build API payload matching Go agent format
     *
     * @param array $formatted_metrics
     * @return array
     */
    private function build_payload($formatted_metrics) {
        // Get OS information
        $os_info = $this->get_os_info();

        // Get hostname with unique fallback
        $site_url = get_site_url();
        $parsed = wp_parse_url($site_url);
        if (isset($parsed['host']) && !empty($parsed['host'])) {
            $hostname = $parsed['host'];
        } else {
            // Create unique fallback using database name and site URL hash
            $unique_id = substr(md5(DB_NAME . $site_url), 0, 12);
            $hostname = 'wp-' . $unique_id;
        }

        // Get last latency from persistent option (not transient - more reliable)
        // Use option instead of transient to avoid expiration issues with cron timing
        $agent_latency = get_option('netwarden_last_latency_ms', 0);

        // Validate it's a number (in case option was corrupted)
        if (!is_numeric($agent_latency) || $agent_latency < 0) {
            $agent_latency = 0;
        }

        $payload = array(
            'version' => NETWARDEN_VERSION,
            'os' => $os_info['os'],
            'arch' => $os_info['arch'],
            'hostname' => $hostname,
            'tenant_id' => $this->tenant_id,
            'metrics' => $formatted_metrics,
        );

        // Add os_info matching Go agent format
        $payload['os_info'] = array(
            'os' => $os_info['os'],  // 'WordPress'
            'platform' => $os_info['distro'],  // Underlying platform (linux/windows/darwin)
            'family' => $os_info['platform_family'],
            'version' => $os_info['platform_version'],
            'arch' => $os_info['arch'],
            'kernel_version' => $os_info['kernel_version'],
            'distro' => 'WordPress',  // Distro name
            'distro_version' => $os_info['distro_version'],  // WordPress version
        );

        // Include agent_latency if available
        if ($agent_latency >= 0) {
            $payload['agent_latency'] = (float) $agent_latency;
        }

        return $payload;
    }

    /**
     * Get OS information
     *
     * @return array
     */
    private function get_os_info() {
        $host_os = PHP_OS;
        $arch = php_uname('m');

        // Determine underlying platform for metadata
        if (stripos($host_os, 'linux') !== false) {
            $underlying_platform = 'linux';
            $platform_family = 'debian'; // Most WordPress sites run on Debian/Ubuntu
        } elseif (stripos($host_os, 'darwin') !== false) {
            $underlying_platform = 'darwin';
            $platform_family = 'darwin';
        } elseif (stripos($host_os, 'win') !== false) {
            $underlying_platform = 'windows';
            $platform_family = 'windows';
        } else {
            $underlying_platform = strtolower($host_os);
            $platform_family = 'unknown';
        }

        // Normalize architecture
        if (stripos($arch, 'x86_64') !== false || stripos($arch, 'amd64') !== false) {
            $arch = 'amd64';
        } elseif (stripos($arch, 'aarch64') !== false || stripos($arch, 'arm64') !== false) {
            $arch = 'arm64';
        } elseif (stripos($arch, 'i386') !== false || stripos($arch, 'i686') !== false) {
            $arch = '386';
        }

        return array(
            'os' => 'WordPress',  // Primary OS identifier for WordPress plugin
            'arch' => $arch,
            'platform_family' => $platform_family,
            'platform_version' => php_uname('r'),
            'kernel_version' => php_uname('r'),
            'distro' => $underlying_platform,  // Underlying platform (linux/windows/darwin)
            'distro_version' => get_bloginfo('version'),  // WordPress version
        );
    }

    /**
     * Test API connection
     *
     * @return array Result with 'success' and 'message' keys
     */
    public function test_connection() {
        // Collect a minimal set of metrics for testing
        $test_metrics = array(
            array(
                'metric_name' => 'agent_status',
                'value' => 1,
                'labels' => array('type' => 'wordpress', 'test' => 'true')
            )
        );

        return $this->send_metrics($test_metrics);
    }
}
