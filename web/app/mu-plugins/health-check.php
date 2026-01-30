<?php
/**
 * Plugin Name: Upsun Health Check
 * Description: Lightweight endpoint for health monitoring
 * Version: 1.0.0
 * Author: ProtecPEO
 */

// Only run if accessed via exact /health path or direct script access
$request_path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$is_health_endpoint = ($request_path === '/health' || $request_path === '/health/');
$is_direct_script = (basename($_SERVER['SCRIPT_NAME'] ?? '') === 'health-check.php');

if (!$is_health_endpoint && !$is_direct_script) {
    return;
}

// Bypass full WP loading if possible, or minimally load
define('WP_USE_THEMES', false);
define('WP_INSTALLING', true); // Prevent some plugins from loading

// Basic headers
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

try {
    // 1. Check PHP basic execution
    $response = [
        'status' => 'ok',
        'timestamp' => time(),
        'service' => 'php'
        // Note: hostname intentionally omitted to avoid infrastructure disclosure
    ];

    // 2. Check Database Connection (Lightweight)
    // We try to connect using credentials from env if available
    require_once dirname(__DIR__, 2) . '/wp-config.php';

    global $wpdb;
    if (empty($wpdb)) {
        require_once ABSPATH . WPINC . '/wp-db.php';
        if (file_exists(ABSPATH . 'wp-content/db.php')) {
            require_once ABSPATH . 'wp-content/db.php';
        }
        if (empty($wpdb)) {
            $wpdb = new wpdb(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
        }
    }

    $wpdb->query("SELECT 1");
    if (!empty($wpdb->last_error)) {
        throw new Exception("Database error: " . $wpdb->last_error);
    }

    $response['database'] = 'connected';

    // 3. Check Redis (if enabled)
    if (defined('WP_REDIS_HOST')) {
        try {
            $redis = new Redis();
            $redis->connect(WP_REDIS_HOST, WP_REDIS_PORT);
            $response['redis'] = 'connected';
        } catch (Exception $e) {
            $response['redis'] = 'error'; // Soft fail
        }
    }

    echo json_encode($response);
    exit;

} catch (Exception $e) {
    // Log the actual error for debugging (server-side only)
    error_log('[HEALTH-CHECK] Error: ' . $e->getMessage());

    // Return generic error to client (no sensitive info disclosure)
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Service temporarily unavailable']);
    exit;
}
