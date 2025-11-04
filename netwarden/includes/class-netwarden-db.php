<?php
/**
 * Netwarden Database Class
 *
 * Handles all database operations for storing credentials
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class Netwarden_DB {

    /**
     * Get table name with WordPress prefix
     */
    private static function get_table_name() {
        global $wpdb;
        return $wpdb->prefix . 'netwarden_config';
    }

    /**
     * Create database table on plugin activation
     *
     * @return bool True if table exists after creation attempt, false otherwise
     */
    public static function create_table() {
        global $wpdb;
        $table_name = self::get_table_name();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            tenant_id varchar(10) NOT NULL,
            api_key text NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) $charset_collate;";

        // Load WordPress upgrade functions for dbDelta()
        // Using approved WordPress exception pattern: check function, load file, use immediately
        if (!function_exists('dbDelta')) {
            $upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
            if (file_exists($upgrade_file)) {
                require_once $upgrade_file;
            }
        }

        // Only attempt table creation if dbDelta is available
        if (function_exists('dbDelta')) {
            dbDelta($sql);
        }

        // Verify table was created
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Checking if custom table exists
        $table_exists = ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) === $table_name);

        if (!$table_exists) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Failed to create database table ' . $table_name);
        }

        return $table_exists;
    }

    /**
     * Drop database table on plugin uninstall
     */
    public static function drop_table() {
        global $wpdb;
        $table_name = self::get_table_name();
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table names cannot be parameterized, dropping custom table on uninstall
        $wpdb->query("DROP TABLE IF EXISTS $table_name");
    }

    /**
     * Save credentials (tenant_id and api_key)
     *
     * @param string $tenant_id Tenant ID (10 characters)
     * @param string $api_key API key (starts with nw_sk_)
     * @return bool True on success, false on failure
     */
    public static function save_credentials($tenant_id, $api_key) {
        global $wpdb;
        $table_name = self::get_table_name();

        // Sanitize inputs
        $tenant_id = sanitize_text_field($tenant_id);
        $api_key = sanitize_text_field($api_key);

        // Validate inputs
        if (!self::validate_tenant_id($tenant_id)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Invalid tenant_id format - must be exactly 10 alphanumeric characters');
            return false;
        }

        if (!self::validate_api_key($api_key)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Invalid api_key format - must start with nw_sk_ and be <= 200 characters');
            return false;
        }

        // Encrypt API key using WordPress salts
        $encrypted_api_key = self::encrypt_api_key($api_key);

        // Check if encryption failed
        if ($encrypted_api_key === null) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Failed to encrypt API key - cannot save credentials');
            return false;
        }

        // Check if credentials already exist
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table names cannot be parameterized, custom table query
        $existing = $wpdb->get_var("SELECT id FROM $table_name LIMIT 1");

        if ($existing) {
            // Update existing record
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Updating custom table credentials
            $result = $wpdb->update(
                $table_name,
                array(
                    'tenant_id' => $tenant_id,
                    'api_key' => $encrypted_api_key,
                    'updated_at' => current_time('mysql')
                ),
                array('id' => $existing),
                array('%s', '%s', '%s'),
                array('%d')
            );

            if ($result === false && $wpdb->last_error) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
                error_log('Netwarden: Database update failed - ' . $wpdb->last_error);
            }
        } else {
            // Insert new record
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Inserting into custom table
            $result = $wpdb->insert(
                $table_name,
                array(
                    'tenant_id' => $tenant_id,
                    'api_key' => $encrypted_api_key
                ),
                array('%s', '%s')
            );

            if ($result === false && $wpdb->last_error) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
                error_log('Netwarden: Database insert failed - ' . $wpdb->last_error);
            }
        }

        return $result !== false;
    }

    /**
     * Get stored credentials
     *
     * @return array|null Array with tenant_id and api_key, or null if not found or corrupted
     */
    public static function get_credentials() {
        global $wpdb;
        $table_name = self::get_table_name();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table names cannot be parameterized, querying custom table
        $row = $wpdb->get_row("SELECT tenant_id, api_key FROM $table_name LIMIT 1", ARRAY_A);

        if (!$row) {
            return null;
        }

        // Decrypt API key
        $decrypted_key = self::decrypt_api_key($row['api_key']);

        // If decryption failed, return null (credentials are corrupted)
        if ($decrypted_key === null) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Credentials corrupted, returning null. User needs to re-enter credentials.');
            return null;
        }

        $row['api_key'] = $decrypted_key;

        return $row;
    }

    /**
     * Delete stored credentials
     *
     * @return bool True on success, false on failure
     */
    public static function delete_credentials() {
        global $wpdb;
        $table_name = self::get_table_name();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table names cannot be parameterized, truncating custom table
        $result = $wpdb->query("TRUNCATE TABLE $table_name");
        return $result !== false;
    }

    /**
     * Validate tenant ID format (10 alphanumeric characters)
     *
     * @param string $tenant_id
     * @return bool
     */
    private static function validate_tenant_id($tenant_id) {
        return preg_match('/^[a-zA-Z0-9]{10}$/', $tenant_id) === 1;
    }

    /**
     * Validate API key format (starts with nw_sk_ and reasonable length)
     *
     * @param string $api_key
     * @return bool
     */
    private static function validate_api_key($api_key) {
        // Check format and reasonable length (prevent memory issues)
        return strpos($api_key, 'nw_sk_') === 0 && strlen($api_key) <= 200;
    }

    /**
     * Encrypt API key using WordPress authentication salts
     *
     * @param string $api_key
     * @return string|null Base64 encoded encrypted string, or null on failure
     */
    private static function encrypt_api_key($api_key) {
        // Derive proper 32-byte key from WordPress salt using SHA-256
        $key = hash('sha256', wp_salt('auth'), true);
        $iv_length = openssl_cipher_iv_length('aes-256-cbc');
        $iv = openssl_random_pseudo_bytes($iv_length);

        // Check if IV generation failed (e.g., insufficient entropy source)
        if ($iv === false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Failed to generate IV for encryption - openssl_random_pseudo_bytes returned false');
            return null;
        }

        $encrypted = openssl_encrypt($api_key, 'aes-256-cbc', $key, 0, $iv);

        if ($encrypted === false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: OpenSSL encryption failed');
            return null;
        }

        // Combine IV and encrypted data
        return base64_encode($iv . '::' . $encrypted);
    }

    /**
     * Decrypt API key
     *
     * @param string $encrypted_api_key Base64 encoded encrypted string
     * @return string|null Decrypted API key, or null on failure
     */
    private static function decrypt_api_key($encrypted_api_key) {
        // Derive proper 32-byte key from WordPress salt using SHA-256
        $key = hash('sha256', wp_salt('auth'), true);
        $data = base64_decode($encrypted_api_key);

        if ($data === false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Failed to decode encrypted API key (base64 decode failed)');
            return null;
        }

        $parts = explode('::', $data, 2);
        if (count($parts) !== 2) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Corrupted encrypted API key (invalid format)');
            return null;
        }

        list($iv, $encrypted) = $parts;

        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);

        if ($decrypted === false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
            error_log('Netwarden: Failed to decrypt API key (decryption failed - possibly corrupted data)');
            return null;
        }

        return $decrypted;
    }
}
