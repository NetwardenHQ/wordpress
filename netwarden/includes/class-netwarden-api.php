<?php
/**
 * Netwarden API Class
 *
 * Handles communication with Netwarden API endpoint
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Netwarden_API {

	/**
	 * Default API server URL (SaaS)
	 */
	const DEFAULT_SERVER_URL = 'https://api.netwarden.com';

	/**
	 * Tenant ID
	 */
	private $tenant_id;

	/**
	 * API Key
	 */
	private $api_key;

	/**
	 * Server URL
	 */
	private $server_url;

	/**
	 * Constructor
	 *
	 * @param string $tenant_id
	 * @param string $api_key
	 * @param string $server_url Optional server URL for self-hosted deployments
	 */
	public function __construct( $tenant_id, $api_key, $server_url = '' ) {
		$this->tenant_id  = $tenant_id;
		$this->api_key    = $api_key;
		$this->server_url = ! empty( $server_url ) ? rtrim( $server_url, '/' ) : self::DEFAULT_SERVER_URL;
	}

	/**
	 * Send metrics to Netwarden API
	 *
	 * @param array $metrics Raw metrics array
	 * @return array Result array with 'success' and 'message' keys
	 */
	public function send_metrics( $metrics ) {
		// Format metrics according to API specification
		$formatted_metrics = array();
		foreach ( $metrics as $metric ) {
			$formatted_metrics[] = Netwarden_Metrics::format_metric( $metric );
		}

		// Build payload matching Go agent format
		$payload = $this->build_payload( $formatted_metrics );

		// Encode payload to JSON with error handling
		$json_body = wp_json_encode( $payload );
		if ( false === $json_body ) {
			$error_msg = 'Failed to encode metrics payload: ' . json_last_error_msg();
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden API: ' . $error_msg );
			return array(
				'success'    => false,
				'message'    => $error_msg,
				'latency_ms' => 0,
			);
		}

		// Measure API latency
		$start = microtime( true );

		$api_endpoint = $this->server_url . '/agent/data';
		$response     = wp_remote_post(
			$api_endpoint,
			array(
				'headers'    => array(
					'Content-Type'  => 'application/json',
					'Authorization' => 'Bearer ' . $this->api_key,
				),
				'user-agent' => 'Netwarden-WordPress/' . NETWARDEN_VERSION,
				'body'       => $json_body,
				'timeout'    => 15,
				'sslverify'  => true,
			)
		);

		$latency_ms = round( ( microtime( true ) - $start ) * 1000, 2 );

		if ( is_wp_error( $response ) ) {
			$error_message = $response->get_error_message();
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden API: HTTP error - ' . $error_message );
			return array(
				'success'    => false,
				'message'    => $error_message,
				'latency_ms' => $latency_ms,
			);
		}

		// Get response code
		$response_code = wp_remote_retrieve_response_code( $response );

		if ( 200 !== $response_code && 201 !== $response_code ) {
			// The body is an error document, not a page; keep the log line
			// readable if a proxy answers with HTML.
			$body          = substr( wp_strip_all_tags( wp_remote_retrieve_body( $response ) ), 0, 300 );
			$error_message = sprintf( 'API returned status %d: %s', $response_code, trim( $body ) );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging for monitoring plugin
			error_log( 'Netwarden API: ' . $error_message );
			return array(
				'success'    => false,
				'message'    => $error_message,
				'latency_ms' => $latency_ms,
			);
		}

		// Only a round trip that the server answered is a latency reading;
		// it is reported in the NEXT payload, as the Go agent does.
		update_option( 'netwarden_last_latency_ms', $latency_ms, false );

		return array(
			'success'    => true,
			'message'    => 'Metrics sent successfully',
			'latency_ms' => $latency_ms,
		);
	}

	/**
	 * Build API payload matching Go agent format
	 *
	 * @param array $formatted_metrics
	 * @return array
	 */
	private function build_payload( $formatted_metrics ) {
		$os_info = $this->get_os_info();

		$payload = array(
			'version'   => NETWARDEN_VERSION,
			'os'        => $os_info['os'],
			'arch'      => $os_info['arch'],
			'hostname'  => Netwarden_Metrics::get_hostname(),
			'tenant_id' => $this->tenant_id,
			'metrics'   => $formatted_metrics,
			// Same shape as the Go agent's os_info. The platform recognises a
			// WordPress host by distro === 'WordPress'.
			'os_info'   => array(
				'os'             => $os_info['os'],
				'platform'       => $os_info['platform'],
				'family'         => $os_info['platform'],
				'version'        => $os_info['kernel_version'],
				'arch'           => $os_info['arch'],
				'kernel_version' => $os_info['kernel_version'],
				'distro'         => 'WordPress',
				'distro_version' => $os_info['wordpress_version'],
			),
		);

		// The previous round trip's latency, if there has been one. Before
		// the first successful submission there is no measurement, and the
		// field is left out rather than sent as 0 ms.
		$agent_latency = get_option( 'netwarden_last_latency_ms', false );
		if ( false !== $agent_latency && is_numeric( $agent_latency ) && $agent_latency >= 0 ) {
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
		// What PHP can see of the host: the kernel name and release, and the
		// machine architecture in the Go agent's spelling. The distribution
		// is not knowable from inside PHP and is not guessed.
		$host_os = PHP_OS;
		if ( stripos( $host_os, 'linux' ) !== false ) {
			$platform = 'linux';
		} elseif ( stripos( $host_os, 'darwin' ) !== false ) {
			$platform = 'darwin';
		} elseif ( stripos( $host_os, 'win' ) !== false ) {
			$platform = 'windows';
		} else {
			$platform = strtolower( $host_os );
		}

		$arch = php_uname( 'm' );
		if ( stripos( $arch, 'x86_64' ) !== false || stripos( $arch, 'amd64' ) !== false ) {
			$arch = 'amd64';
		} elseif ( stripos( $arch, 'aarch64' ) !== false || stripos( $arch, 'arm64' ) !== false ) {
			$arch = 'arm64';
		} elseif ( stripos( $arch, 'i386' ) !== false || stripos( $arch, 'i686' ) !== false ) {
			$arch = '386';
		}

		return array(
			'os'                => 'WordPress',
			'arch'              => $arch,
			'platform'          => $platform,
			'kernel_version'    => php_uname( 'r' ),
			'wordpress_version' => get_bloginfo( 'version' ),
		);
	}
}
