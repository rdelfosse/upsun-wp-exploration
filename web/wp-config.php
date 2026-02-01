<?php
/**
 * WordPress Bedrock Configuration for Upsun
 *
 * This file contains the configuration for WordPress running on Upsun/Platform.sh.
 * It reads database credentials and other settings from Upsun environment variables.
 */

// Load Composer autoloader
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Load environment variables from .env file (local development only)
if (file_exists(dirname(__DIR__) . '/.env') && !getenv('PLATFORM_APPLICATION_NAME')) {
    $dotenv = Dotenv\Dotenv::createUnsafeImmutable(dirname(__DIR__));
    $dotenv->load();
}

/**
 * Upsun/Platform.sh Configuration
 * Reads database and Redis credentials from PLATFORM_RELATIONSHIPS
 */
if (getenv('PLATFORM_RELATIONSHIPS')) {
    $relationships = json_decode(base64_decode(getenv('PLATFORM_RELATIONSHIPS')), true);

    // Database configuration
    if (isset($relationships['database'][0])) {
        $db = $relationships['database'][0];
        define('DB_NAME', $db['path']);
        define('DB_USER', $db['username']);
        define('DB_PASSWORD', $db['password']);
        define('DB_HOST', $db['host'] . ':' . $db['port']);
        define('DB_CHARSET', 'utf8mb4');
        define('DB_COLLATE', '');
    }

    // Redis configuration
    if (isset($relationships['redis'][0])) {
        $redis = $relationships['redis'][0];
        define('WP_REDIS_HOST', $redis['host']);
        define('WP_REDIS_PORT', $redis['port']);
        define('WP_REDIS_DATABASE', 0);
        define('WP_REDIS_TIMEOUT', 1);
        define('WP_REDIS_READ_TIMEOUT', 1);
    }
} else {
    // Local development fallback
    define('DB_NAME', getenv('DB_NAME') ?: 'wordpress');
    define('DB_USER', getenv('DB_USER') ?: 'root');
    define('DB_PASSWORD', getenv('DB_PASSWORD') ?: '');
    define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
    define('DB_CHARSET', 'utf8mb4');
    define('DB_COLLATE', '');
}

// Table prefix
$table_prefix = getenv('TABLE_PREFIX') ?: 'wp_';

/**
 * URLs Configuration
 */
if (getenv('PLATFORM_ROUTES')) {
    $routes = json_decode(base64_decode(getenv('PLATFORM_ROUTES')), true);
    foreach ($routes as $url => $route) {
        if (isset($route['primary']) && $route['primary']) {
            $primaryUrl = rtrim($url, '/');
            break;
        }
    }
    if (isset($primaryUrl)) {
        define('WP_HOME', $primaryUrl);
        define('WP_SITEURL', $primaryUrl . '/wp');
    }
} else {
    define('WP_HOME', getenv('WP_HOME') ?: 'http://localhost');
    define('WP_SITEURL', getenv('WP_SITEURL') ?: 'http://localhost/wp');
}

/**
 * Custom Content Directory
 */
define('CONTENT_DIR', '/app');
define('WP_CONTENT_DIR', __DIR__ . CONTENT_DIR);
define('WP_CONTENT_URL', WP_HOME . CONTENT_DIR);

/**
 * Authentication Unique Keys and Salts
 * Generate at: https://api.wordpress.org/secret-key/1.1/salt/
 */
if (getenv('PLATFORM_PROJECT_ENTROPY')) {
    // Use Upsun entropy for consistent salts across deployments
    $entropy = getenv('PLATFORM_PROJECT_ENTROPY');
    define('AUTH_KEY', hash('sha256', $entropy . 'AUTH_KEY'));
    define('SECURE_AUTH_KEY', hash('sha256', $entropy . 'SECURE_AUTH_KEY'));
    define('LOGGED_IN_KEY', hash('sha256', $entropy . 'LOGGED_IN_KEY'));
    define('NONCE_KEY', hash('sha256', $entropy . 'NONCE_KEY'));
    define('AUTH_SALT', hash('sha256', $entropy . 'AUTH_SALT'));
    define('SECURE_AUTH_SALT', hash('sha256', $entropy . 'SECURE_AUTH_SALT'));
    define('LOGGED_IN_SALT', hash('sha256', $entropy . 'LOGGED_IN_SALT'));
    define('NONCE_SALT', hash('sha256', $entropy . 'NONCE_SALT'));
} else {
    // Local development - use .env or defaults
    define('AUTH_KEY', getenv('AUTH_KEY') ?: 'local-dev-key-change-in-production');
    define('SECURE_AUTH_KEY', getenv('SECURE_AUTH_KEY') ?: 'local-dev-key-change-in-production');
    define('LOGGED_IN_KEY', getenv('LOGGED_IN_KEY') ?: 'local-dev-key-change-in-production');
    define('NONCE_KEY', getenv('NONCE_KEY') ?: 'local-dev-key-change-in-production');
    define('AUTH_SALT', getenv('AUTH_SALT') ?: 'local-dev-salt-change-in-production');
    define('SECURE_AUTH_SALT', getenv('SECURE_AUTH_SALT') ?: 'local-dev-salt-change-in-production');
    define('LOGGED_IN_SALT', getenv('LOGGED_IN_SALT') ?: 'local-dev-salt-change-in-production');
    define('NONCE_SALT', getenv('NONCE_SALT') ?: 'local-dev-salt-change-in-production');
}

/**
 * Environment Type
 */
$wpEnv = getenv('WP_ENV') ?: 'development';
define('WP_ENVIRONMENT_TYPE', $wpEnv);

/**
 * Debug Configuration
 */
$isProduction = ($wpEnv === 'production');
define('WP_DEBUG', !$isProduction);
define('WP_DEBUG_LOG', !$isProduction);
define('WP_DEBUG_DISPLAY', false);
define('SCRIPT_DEBUG', !$isProduction);

// Disable file editing in admin (security best practice)
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', $isProduction);

/**
 * Multisite - Disabled by default
 */
define('WP_ALLOW_MULTISITE', false);

/**
 * Cron Configuration
 * Disable WP-Cron in favor of system cron (configured in .upsun/config.yaml)
 */
if (getenv('PLATFORM_APPLICATION_NAME')) {
    define('DISABLE_WP_CRON', true);
}

/**
 * Memory Limits
 */
define('WP_MEMORY_LIMIT', '128M');
define('WP_MAX_MEMORY_LIMIT', '256M');

/**
 * Reverse Proxy / Load Balancer Configuration
 * Required for Upsun to correctly detect HTTPS
 */
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

// Trust Upsun proxy headers
if (getenv('PLATFORM_APPLICATION_NAME')) {
    define('FORCE_SSL_ADMIN', true);
}

/**
 * Absolute path to the WordPress directory
 */
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/wp/');
}

/**
 * Sets up WordPress vars and included files
 */
require_once ABSPATH . 'wp-settings.php';
