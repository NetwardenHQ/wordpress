<?php
/**
 * Netwarden Security Class
 *
 * Handles authentication and security verification for backend requests
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class Netwarden_Security {

    /**
     * Verify backend request authentication
     *
     * Checks if the request is coming from the Netwarden backend
     * by verifying the Authorization header against a shared secret
     *
     * @return bool True if authenticated, false otherwise
     */
    public static function verify_backend_request() {
        // Get Authorization header
        $auth_header = '';

        // Try different methods to get the Authorization header
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']));
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth_header = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['Authorization'])) {
                $auth_header = $headers['Authorization'];
            }
        }

        // No authorization header found
        if (empty($auth_header)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden Security: No authorization header found');
            return false;
        }

        // Extract bearer token
        if (strpos($auth_header, 'Bearer ') !== 0) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden Security: Invalid authorization header format');
            return false;
        }

        $provided_token = substr($auth_header, 7); // Remove 'Bearer ' prefix

        // Get expected secret
        $expected_secret = self::get_backend_secret();

        if (empty($expected_secret)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden Security: Backend secret not configured');
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        if (!hash_equals($expected_secret, $provided_token)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden Security: Invalid backend token');
            return false;
        }

        return true;
    }

    /**
     * Get backend secret
     *
     * Returns the shared secret used to authenticate backend requests
     *
     * Priority order:
     * 1. Environment variable NETWARDEN_BACKEND_SECRET
     * 2. wp-config.php constant NETWARDEN_BACKEND_SECRET
     * 3. Generated from API key (if credentials exist)
     *
     * @return string Backend secret
     */
    private static function get_backend_secret() {
        // Try environment variable first
        $secret = getenv('NETWARDEN_BACKEND_SECRET');
        if (!empty($secret)) {
            return $secret;
        }

        // Try wp-config.php constant
        if (defined('NETWARDEN_BACKEND_SECRET')) {
            return NETWARDEN_BACKEND_SECRET;
        }

        // Fallback: Derive from API key (if credentials exist)
        $credentials = Netwarden_DB::get_credentials();
        if (!empty($credentials) && !empty($credentials['api_key'])) {
            // Use HMAC of API key as backend secret
            // This allows backend to derive the same secret knowing the tenant's API key
            return hash_hmac('sha256', $credentials['api_key'], 'netwarden-backend-auth');
        }

        return '';
    }

    /**
     * Send unauthorized response
     *
     * Sends a 401 Unauthorized JSON response and exits
     */
    public static function send_unauthorized_response() {
        wp_send_json_error(array('message' => 'Unauthorized'), 401);
    }

    /**
     * Rate limit backend requests
     *
     * Prevents abuse by limiting requests from backend
     *
     * @param string $action Action name for rate limiting
     * @param int $max_requests Maximum requests allowed
     * @param int $time_window Time window in seconds
     * @return bool True if rate limit exceeded
     */
    public static function is_rate_limited($action, $max_requests = 60, $time_window = MINUTE_IN_SECONDS) {
        $transient_key = 'netwarden_backend_ratelimit_' . $action;
        $rate_data = get_transient($transient_key);

        $now = time();

        if ($rate_data === false) {
            // First request in window
            set_transient($transient_key, array('count' => 1, 'start' => $now), $time_window);
            return false;
        }

        // Check if window expired
        if (($now - $rate_data['start']) >= $time_window) {
            // Window expired - start new window
            set_transient($transient_key, array('count' => 1, 'start' => $now), $time_window);
            return false;
        }

        // Check if limit exceeded
        if ($rate_data['count'] >= $max_requests) {
            return true;
        }

        // Increment counter
        $rate_data['count']++;
        $remaining_ttl = $time_window - ($now - $rate_data['start']);
        set_transient($transient_key, $rate_data, max(1, $remaining_ttl));
        return false;
    }
}
