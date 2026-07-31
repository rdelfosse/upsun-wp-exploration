<?php
/**
 * Plugin Name: Upsun Security & Configuration
 * Description: Complete security + performance configuration for Upsun/Bedrock
 * Version: 2.0
 */

// Only run on Upsun platform
if (!getenv('PLATFORM_APPLICATION')) {
    return;
}

/**
 * =============================================================================
 * 0. NANO-WAF: Early Security Filtering
 * =============================================================================
 */

/**
 * 0.1 HTTP Method Filtering
 * Block dangerous/unused HTTP methods that can be exploited
 */
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$blocked_methods = ['TRACE', 'TRACK', 'DEBUG', 'CONNECT'];

if (in_array(strtoupper($method), $blocked_methods)) {
    error_log(sprintf('[NANO-WAF] Blocked HTTP method: %s from %s',
        $method,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ));
    status_header(405);
    header('Allow: GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS');
    exit;
}

/**
 * 0.2 User-Agent Filtering
 * Blocks known malicious scanners while allowing legitimate services.
 * Fail-open design: unknown user-agents are allowed through.
 */

if (isset($_SERVER['HTTP_USER_AGENT'])) {
    $ua = strtolower($_SERVER['HTTP_USER_AGENT']);
    $path = $_SERVER['REQUEST_URI'] ?? '';

    // 1. BYPASS: Health endpoint (monitoring tools need access)
    if (strpos($path, '/health') === 0) {
        // Allow all user-agents on health endpoint
    }
    // 2. BYPASS: Secret header present (admin/dev access)
    // Usage: curl -H "X-Dev-Pass: your_secret" https://...
    elseif (
        getenv('WP_ADMIN_SECRET_PATH') &&
        isset($_SERVER['HTTP_X_DEV_PASS']) &&
        $_SERVER['HTTP_X_DEV_PASS'] === getenv('WP_ADMIN_SECRET_PATH')
    ) {
        // Allow with valid dev pass
    }
    // 3. ALLOWLIST: Legitimate services (webhooks, APIs, WordPress, AI crawlers, etc.)
    // Organized by category for maintainability
    elseif (preg_match('/' . implode('|', [
        // CMS & Platforms
        'wordpress', 'jetpack', 'woocommerce',
        // Payments
        'stripe', 'paypal', 'braintree', 'shopify', 'square', 'klarna', 'mollie',
        // Communication
        'slack', 'discord', 'twilio', 'telegram', 'whatsapp',
        // Email
        'sendgrid', 'mailgun', 'mailchimp', 'hubspot',
        // Automation & Dev
        'zapier', 'github', 'gitlab', 'bitbucket', 'postman', 'insomnia',
        // Monitoring & APM
        'pingdom', 'uptimerobot', 'statuscake', 'datadog', 'newrelic', 'sentry', 'gtmetrix',
        // Cloud & CDN
        'cloudflare', 'fastly', 'aws', 'azure', 'google-cloud',
        // Search Engines
        'googlebot', 'bingbot', 'applebot', 'duckduckbot', 'yandexbot', 'baiduspider',
        'sogou', 'qwant', 'ecosia', 'seznam',
        // Social Media
        'facebookexternalhit', 'twitterbot', 'linkedinbot', 'pinterestbot', 'snapchat',
        // AI Crawlers
        'claudebot', 'anthropic', 'gptbot', 'chatgpt-user', 'perplexitybot',
        'google-extended', 'cohere-ai', 'meta-externalagent', 'bytespider',
        // SEO Tools
        'semrush', 'ahrefs', 'moz', 'screaming frog',
        // Feeds & Archives
        'feedly', 'flipboard', 'feedbin', 'archive\.org', 'ia_archiver', 'ccbot',
    ]) . '/i', $ua)) {
        // Allow known good services
    }
    // 4. BLOCKLIST: Known malicious scanners and tools
    elseif (preg_match('/sqlmap|nikto|nessus|openvas|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|wfuzz|burpsuite|hydra|medusa|metasploit|havij|acunetix|netsparker|qualys|w3af|skipfish|arachni|vega|grabber|wpscan|joomscan|droopescan/i', $ua)) {
        // Log and block scanner
        error_log(sprintf('[NANO-WAF] Blocked scanner: %s from %s on %s',
            substr($_SERVER['HTTP_USER_AGENT'], 0, 100),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $path
        ));

        // Return 404 (stealth mode - don't reveal we detected them)
        status_header(404);
        nocache_headers();
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
        exit;
    }
    // 5. DEFAULT: Allow through (fail-open)
}

/**
 * 0.3 Path Filtering (Stealth 404)
 * Block sensitive WordPress paths before WordPress handles them.
 * Returns 404 to avoid fingerprinting.
 */
$request_path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);

// Paths to block with 404 (stealth mode)
$blocked_paths = [
    // Root-level fake paths (don't exist in Bedrock but scanners try them)
    '#^/wp-admin(/|$)#',           // /wp-admin at root
    '#^/wp-login\.php#',           // /wp-login.php at root
    '#^/xmlrpc\.php#',             // /xmlrpc.php at root (real one is /wp/xmlrpc.php)

    // Install/upgrade scripts (never needed after deployment)
    '#^/wp/wp-admin/install\.php#',
    '#^/wp/wp-admin/upgrade\.php#',

    // Version disclosure files
    '#^(/wp)?/readme\.html#i',
    '#^(/wp)?/license\.txt#i',
    '#^(/wp)?/wp-config-sample\.php#i',
];

// Check each blocked path pattern
foreach ($blocked_paths as $pattern) {
    if (preg_match($pattern, $request_path)) {
        http_response_code(404);
        header('X-Robots-Tag: noindex, nofollow', true);
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
        exit;
    }
}

/**
 * =============================================================================
 * 1. INFRASTRUCTURE CONFIGURATION
 * =============================================================================
 */

/**
 * Redis Object Cache
 */
if (getenv('PLATFORM_RELATIONSHIPS')) {
    $relationships = json_decode(base64_decode(getenv('PLATFORM_RELATIONSHIPS')), true);

    if (isset($relationships['cache'][0])) {
        $redis = $relationships['cache'][0];

        if (!defined('WP_REDIS_HOST'))
            define('WP_REDIS_HOST', $redis['host']);
        if (!defined('WP_REDIS_PORT'))
            define('WP_REDIS_PORT', $redis['port']);
        if (!defined('WP_REDIS_DATABASE'))
            define('WP_REDIS_DATABASE', 0);
        if (!defined('WP_REDIS_PREFIX'))
            define('WP_REDIS_PREFIX', getenv('PLATFORM_BRANCH') . '_');
        if (!defined('WP_REDIS_TIMEOUT'))
            define('WP_REDIS_TIMEOUT', 1);
        if (!defined('WP_REDIS_READ_TIMEOUT'))
            define('WP_REDIS_READ_TIMEOUT', 1);
    }
}

/**
 * Dynamic URLs based on environment
 */
add_action('muplugins_loaded', function () {
    $routes = getenv('PLATFORM_ROUTES');

    if ($routes) {
        $routes = json_decode(base64_decode($routes), true);

        foreach ($routes as $url => $route) {
            if ($route['primary'] ?? false) {
                $primary_url = rtrim($url, '/');

                if (!defined('WP_HOME'))
                    define('WP_HOME', $primary_url);
                if (!defined('WP_SITEURL'))
                    define('WP_SITEURL', $primary_url . '/wp');
                break;
            }
        }
    }
}, 1);

/**
 * HTTPS detection behind proxy
 */
add_action('muplugins_loaded', function () {
    if (
        (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
        (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on')
    ) {
        $_SERVER['HTTPS'] = 'on';
    }
}, 0);

/**
 * =============================================================================
 * 2. SECURITY HEADERS
 * =============================================================================
 */

/**
 * CSP Configuration
 *
 * UPSUN_CSP_MODE:
 * - 'off'         : No CSP (not recommended)
 * - 'permissive'  : CSP with unsafe-inline (WordPress compatibility)
 * - 'report-only' : Strict CSP in observation mode (recommended to start)
 * - 'strict'      : Strict blocking CSP (final goal)
 *
 * Define in wp-config.php or via environment variable:
 * define('UPSUN_CSP_MODE', 'report-only');
 */
if (!defined('UPSUN_CSP_MODE')) {
    define('UPSUN_CSP_MODE', 'permissive');
}

/**
 * Generate a unique CSP nonce per request
 */
function upsun_csp_nonce()
{
    static $nonce;
    if (!$nonce) {
        $nonce = base64_encode(random_bytes(16));
    }
    return $nonce;
}

/**
 * Add nonce to WordPress inline scripts
 */
add_filter('script_loader_tag', function ($tag, $_handle, $_src) {
    if (UPSUN_CSP_MODE === 'strict' || UPSUN_CSP_MODE === 'report-only') {
        $nonce = upsun_csp_nonce();
        $tag = str_replace('<script ', '<script nonce="' . esc_attr($nonce) . '" ', $tag);
    }
    return $tag;
}, 10, 3);

/**
 * Add nonce to WordPress inline styles
 */
add_filter('style_loader_tag', function ($tag, $_handle, $_src, $_media) {
    if (UPSUN_CSP_MODE === 'strict' || UPSUN_CSP_MODE === 'report-only') {
        $nonce = upsun_csp_nonce();
        $tag = str_replace('<link ', '<link nonce="' . esc_attr($nonce) . '" ', $tag);
    }
    return $tag;
}, 10, 4);

add_action('send_headers', function () {
    // Skip admin to avoid conflicts
    if (is_admin()) {
        return;
    }

    // Prevent MIME sniffing
    header('X-Content-Type-Options: nosniff');

    // Clickjacking protection
    header('X-Frame-Options: SAMEORIGIN');

    // Cross-Origin Opener Policy (Spectre/Meltdown protection)
    // Isolates browsing context - prevents window.opener attacks
    header('Cross-Origin-Opener-Policy: same-origin');

    // Note: X-XSS-Protection header intentionally omitted
    // It's deprecated, removed from modern browsers, and could introduce vulnerabilities
    // See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection

    // Referrer policy
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // Permissions Policy (formerly Feature-Policy)
    header("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()");

    // HSTS (force HTTPS for 1 year)
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

    // Content Security Policy
    if (UPSUN_CSP_MODE === 'off') {
        return;
    }

    $report_uri = rest_url('upsun/v1/csp-report');
    $nonce = upsun_csp_nonce();

    // Permissive CSP (WordPress compatibility by default)
    $csp_permissive = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google-analytics.com https://www.googletagmanager.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "img-src 'self' data: https: blob:",
        "font-src 'self' https://fonts.gstatic.com data:",
        "connect-src 'self' https://www.google-analytics.com https://stats.g.doubleclick.net",
        "frame-src 'self' https://www.youtube.com https://www.google.com",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "upgrade-insecure-requests",
    ];

    // Strict CSP (security goal)
    $csp_strict = [
        "default-src 'self'",
        "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic' https://www.google-analytics.com https://www.googletagmanager.com",
        "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com",
        "img-src 'self' data: https: blob:",
        "font-src 'self' https://fonts.gstatic.com data:",
        "connect-src 'self' https://www.google-analytics.com https://stats.g.doubleclick.net",
        "frame-src 'self' https://www.youtube.com https://www.google.com",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "upgrade-insecure-requests",
        "report-uri {$report_uri}",
    ];

    // Allow plugins/themes to add rules
    $csp_permissive = apply_filters('upsun_csp_rules', $csp_permissive);
    $csp_strict = apply_filters('upsun_csp_strict_rules', $csp_strict);

    switch (UPSUN_CSP_MODE) {
        case 'strict':
            // Strict blocking mode
            header("Content-Security-Policy: " . implode('; ', $csp_strict));
            break;

        case 'report-only':
            // Observation mode: permissive CSP active + strict CSP in report-only
            header("Content-Security-Policy: " . implode('; ', $csp_permissive));
            header("Content-Security-Policy-Report-Only: " . implode('; ', $csp_strict));
            break;

        case 'permissive':
        default:
            // WordPress compatibility mode
            header("Content-Security-Policy: " . implode('; ', $csp_permissive));
            break;
    }
});

/**
 * REST endpoint to receive CSP reports
 * Rate limited to prevent log spam attacks
 */
add_action('rest_api_init', function () {
    register_rest_route('upsun/v1', '/csp-report', [
        'methods' => 'POST',
        'callback' => function ($request) {
            // Rate limiting: max 10 reports per IP per minute
            $ip = upsun_get_real_ip();
            $key = 'csp_report_' . hash('sha256', $ip);
            $count = upsun_rate_limit_get($key);

            if ($count >= 10) {
                return new WP_REST_Response(['error' => 'rate_limited'], 429);
            }

            upsun_rate_limit_set($key, $count + 1, MINUTE_IN_SECONDS);

            $body = $request->get_body();
            $report = json_decode($body, true);

            if (isset($report['csp-report'])) {
                $violation = $report['csp-report'];
                error_log(sprintf(
                    '[CSP-VIOLATION] %s blocked by %s | Source: %s | Script: %s',
                    $violation['blocked-uri'] ?? 'unknown',
                    $violation['violated-directive'] ?? 'unknown',
                    $violation['source-file'] ?? 'unknown',
                    isset($violation['line-number']) ? "line {$violation['line-number']}" : 'n/a'
                ));
            }

            return new WP_REST_Response(null, 204);
        },
        'permission_callback' => '__return_true',
    ]);
});

/**
 * =============================================================================
 * 3. BLOCKING & DISABLING
 * =============================================================================
 */

/**
 * Completely disable XML-RPC
 */
add_filter('xmlrpc_enabled', '__return_false');
add_filter('xmlrpc_methods', '__return_empty_array');

// Stealth block: Return 404 to make scanners think XML-RPC doesn't exist
add_action('init', function () {
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        status_header(404);
        nocache_headers();
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
        exit;
    }
}, 1);

/**
 * Disable pingbacks
 */
add_filter('pings_open', '__return_false', PHP_INT_MAX);
add_filter('pre_ping', '__return_empty_array');

/**
 * Disable file editor
 */
if (!defined('DISALLOW_FILE_EDIT'))
    define('DISALLOW_FILE_EDIT', true);
if (!defined('DISALLOW_FILE_MODS'))
    define('DISALLOW_FILE_MODS', false); // true to block plugin updates

/**
 * Hide WordPress version
 */
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');

// Hide in feeds
add_filter('get_the_generator_rss2', '__return_empty_string');
add_filter('get_the_generator_atom', '__return_empty_string');

// Hide in scripts/styles
add_filter('style_loader_src', 'upsun_remove_version_query', 10, 2);
add_filter('script_loader_src', 'upsun_remove_version_query', 10, 2);

function upsun_remove_version_query($src, $handle)
{
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}

/**
 * Remove WordPress info from HTTP headers
 */
add_filter('wp_headers', function ($headers) {
    unset($headers['X-Powered-By']);
    unset($headers['X-Pingback']);
    return $headers;
});

// Remove pingback link from head
remove_action('wp_head', 'rsd_link');
remove_action('wp_head', 'wlwmanifest_link');
remove_action('wp_head', 'wp_shortlink_wp_head');

/**
 * Disable WordPress embeds
 */
add_action('init', function () {
    remove_action('wp_head', 'wp_oembed_add_discovery_links');
    remove_action('wp_head', 'wp_oembed_add_host_js');
});

/**
 * =============================================================================
 * 4. REST API PROTECTION — closed by default
 * =============================================================================
 *
 * WordPress ships /wp-json open to anonymous visitors. That default was already
 * questionable — /wp/v2/users enumerates accounts, and knowing a valid login is
 * half a brute-force attack — and wp2shell settled it.
 *
 * wp2shell (disclosed 17-18 July 2026) chains CVE-2026-60137, a SQL injection,
 * with CVE-2026-63030, a route-confusion flaw in the REST batch processor at
 * /wp-json/batch/v1. Separately they are limited; chained they give
 * unauthenticated remote code execution. Both entered the CISA Known Exploited
 * Vulnerabilities catalogue on 21 July 2026. Fixed in WordPress 7.0.2, 6.9.5
 * and 6.8.6.
 *
 * So the default is inverted here: everything is closed to anonymous visitors
 * unless explicitly opened. Blocking a known-bad list only ever protects against
 * the endpoints someone thought of; an allowlist fails closed when a new one
 * appears, whether it ships in core or comes with a plugin.
 *
 * Opening an endpoint:
 *
 *   WP_REST_PUBLIC_NAMESPACES=myplugin/v1,otherplugin/v2   (env, comma separated)
 *
 *   add_filter('upsun_rest_public_namespaces', function ($ns) {
 *       $ns[] = 'myplugin/v1';
 *       return $ns;
 *   });
 *
 * Authenticated requests are untouched: this only decides what an anonymous
 * caller may reach.
 */

/**
 * Namespaces reachable without authentication.
 *
 * `oembed/1.0` is open by default: it is what lets other sites embed yours, it
 * is read-only, and closing it silently breaks embeds in a way that is hard to
 * trace back here. Everything else has to be opted in.
 */
function upsun_rest_public_namespaces()
{
    $namespaces = ['oembed/1.0'];

    $from_env = getenv('WP_REST_PUBLIC_NAMESPACES');
    if ($from_env) {
        foreach (explode(',', $from_env) as $ns) {
            $ns = trim($ns, " 	/");
            if ($ns !== '') {
                $namespaces[] = $ns;
            }
        }
    }

    return apply_filters('upsun_rest_public_namespaces', array_unique($namespaces));
}

/**
 * The route currently being served, normalised without leading slash.
 */
function upsun_current_rest_route()
{
    if (!empty($GLOBALS['wp']->query_vars['rest_route'])) {
        return ltrim((string) $GLOBALS['wp']->query_vars['rest_route'], '/');
    }

    // Pretty permalinks: /wp-json/<route>
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '';
    $prefix = '/' . rest_get_url_prefix() . '/';
    $at = strpos($path, $prefix);

    return false === $at ? '' : ltrim(substr($path, $at + strlen($prefix)), '/');
}

add_filter('rest_authentication_errors', function ($result) {
    // Never overwrite an authentication error raised upstream.
    if (is_wp_error($result) || true === $result) {
        return $result;
    }

    if (is_user_logged_in()) {
        return $result;
    }

    $route = upsun_current_rest_route();

    foreach (upsun_rest_public_namespaces() as $namespace) {
        if (strpos($route, trim($namespace, '/')) === 0) {
            return $result;
        }
    }

    return new WP_Error(
        'rest_closed',
        'REST API is not available to unauthenticated clients.',
        ['status' => 401]
    );
}, 20);

/**
 * Remove the batch processor entirely.
 *
 * This is the CVE-2026-63030 vector: the batch endpoint validated and executed
 * sub-requests in two separate loops, and a sub-request whose URL failed to
 * parse pushed an error into the validation array but not into the matches
 * array. The arrays desynchronised, and every following sub-request ran under
 * the wrong handler.
 *
 * Core is patched. This site does not use batch requests, so keeping the
 * endpoint would be accepting risk with no upside — including from whatever
 * turns up in it next.
 */
add_filter('rest_endpoints', function ($endpoints) {
    foreach (array_keys($endpoints) as $route) {
        if (strpos($route, '/batch/') === 0) {
            unset($endpoints[$route]);
        }
    }
    return $endpoints;
}, PHP_INT_MAX);

/**
 * Belt and braces on user enumeration.
 *
 * The allowlist above already blocks these for anonymous callers. They are
 * dropped from the route table as well so that they disappear from the
 * discovery index rather than merely returning 401 — a 401 confirms the route
 * exists, which is itself worth knowing to an attacker.
 */
add_filter('rest_endpoints', function ($endpoints) {
    if (is_user_logged_in()) {
        return $endpoints;
    }

    foreach (['/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)', '/wp/v2/settings'] as $route) {
        unset($endpoints[$route]);
    }

    return $endpoints;
});

/**
 * Drop the REST discovery link from the head and headers. It is only useful to
 * a client that already knows it wants the API.
 */
remove_action('wp_head', 'rest_output_link_wp_head');
remove_action('template_redirect', 'rest_output_link_header', 11);

/**
 * =============================================================================
 * 5. LOGIN & BRUTE FORCE PROTECTION
 * =============================================================================
 */

/**
 * Rate limiting on login attempts
 * Uses Redis if available (better performance), otherwise fallback to transients
 */

/**
 * Helpers for rate limiting (Redis or transients)
 */
function upsun_rate_limit_get($key)
{
    // Try Redis first if wp-redis is active
    if (function_exists('wp_cache_get') && defined('WP_REDIS_HOST')) {
        $value = wp_cache_get($key, 'upsun_rate_limit');
        if ($value !== false) {
            return $value;
        }
    }
    // Fallback to transient
    return get_transient($key) ?: 0;
}

function upsun_rate_limit_set($key, $value, $expiration)
{
    // Try Redis first
    if (function_exists('wp_cache_set') && defined('WP_REDIS_HOST')) {
        wp_cache_set($key, $value, 'upsun_rate_limit', $expiration);
    }
    // Always set transient as backup
    set_transient($key, $value, $expiration);
}

function upsun_rate_limit_delete($key)
{
    if (function_exists('wp_cache_delete') && defined('WP_REDIS_HOST')) {
        wp_cache_delete($key, 'upsun_rate_limit');
    }
    delete_transient($key);
}

add_filter('authenticate', function ($user, $username, $password) {
    if (empty($username)) {
        return $user;
    }

    $ip = upsun_get_real_ip();
    $key = 'login_attempts_' . hash('sha256', $ip);
    $attempts = upsun_rate_limit_get($key);
    $max_attempts = 5;

    // Block after X attempts
    if ($attempts >= $max_attempts) {
        // Calculate approximate remaining time
        $timeout = get_option('_transient_timeout_' . $key);
        $remaining = $timeout ? ceil(($timeout - time()) / 60) : 30;

        return new WP_Error(
            'too_many_attempts',
            sprintf(
                'Too many login attempts. Please try again in %d minutes.',
                max(1, $remaining)
            )
        );
    }

    return $user;
}, 30, 3);

add_action('wp_login_failed', function ($username) {
    $ip = upsun_get_real_ip();
    $key = 'login_attempts_' . hash('sha256', $ip);
    $attempts = upsun_rate_limit_get($key);
    $lockout_duration = 30 * MINUTE_IN_SECONDS;

    // Increment counter
    upsun_rate_limit_set($key, $attempts + 1, $lockout_duration);

    // Log failure
    error_log(sprintf(
        '[SECURITY] Failed login for "%s" from %s (attempt %d)',
        sanitize_user($username),
        $ip,
        $attempts + 1
    ));
});

// Reset after successful login
add_action('wp_login', function ($user_login, $user) {
    $ip = upsun_get_real_ip();
    $key = 'login_attempts_' . hash('sha256', $ip);
    upsun_rate_limit_delete($key);

    // Log success
    error_log(sprintf(
        '[SECURITY] Successful login: %s (ID: %d) from %s',
        $user_login,
        $user->ID,
        $ip
    ));
}, 10, 2);

/**
 * Block login by email to force username usage
 * Uncomment to enable
 */
// remove_filter('authenticate', 'wp_authenticate_email_password', 20);

/**
 * Hide login errors (don't reveal if user exists)
 */
add_filter('login_errors', function ($error) {
    return 'Invalid credentials.';
});

/**
 * Block user enumeration via ?author=1
 */
add_action('init', function () {
    if (!is_admin() && isset($_GET['author']) && is_numeric($_GET['author'])) {
        wp_redirect(home_url(), 301);
        exit;
    }
});

/**
 * =============================================================================
 * 6. HOTLINKING PROTECTION
 * =============================================================================
 */

add_action('init', function () {
    if (!isset($_SERVER['HTTP_REFERER'])) {
        return;
    }

    // Extensions to protect
    $protected_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp4', 'webm'];
    $request_uri = $_SERVER['REQUEST_URI'];
    $extension = strtolower(pathinfo(parse_url($request_uri, PHP_URL_PATH), PATHINFO_EXTENSION));

    if (!in_array($extension, $protected_extensions)) {
        return;
    }

    $referer_host = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
    $site_host = parse_url(home_url(), PHP_URL_HOST);

    // Allowed domains (add yours)
    $allowed_hosts = [
        $site_host,
        'www.' . $site_host,
        // 'other-domain.com',
    ];

    // Allow filter to extend allowed hosts
    $allowed_hosts = apply_filters('upsun_hotlink_allowed', $allowed_hosts);

    // Trusted domain suffixes (search engines, social media)
    // Format: domain must END with these values (prevents evilgoogle.com bypass)
    $trusted_suffixes = [
        '.google.com',
        '.google.fr',
        '.googleapis.com',
        '.bing.com',
        '.facebook.com',
        '.twitter.com',
        '.x.com',
        '.t.co',
        '.linkedin.com',
        '.pinterest.com',
    ];

    $is_allowed = in_array($referer_host, $allowed_hosts);

    if (!$is_allowed) {
        foreach ($trusted_suffixes as $suffix) {
            // Check exact match or proper subdomain match
            if ($referer_host === ltrim($suffix, '.') || substr($referer_host, -strlen($suffix)) === $suffix) {
                $is_allowed = true;
                break;
            }
        }
    }

    if (!$is_allowed) {
        http_response_code(403);
        exit;
    }
});

/**
 * =============================================================================
 * 7. UPLOAD PROTECTION
 * =============================================================================
 */

/**
 * Allowed MIME types (strict)
 */
add_filter('upload_mimes', function ($mimes) {
    // Remove dangerous types
    unset($mimes['exe']);
    unset($mimes['phtml']);
    unset($mimes['php']);
    unset($mimes['js']);

    // Add what you need
    // NOTE: SVG disabled by default as potential XSS vector
    // To enable SVG safely, install the package:
    // composer require enshrined/svg-sanitize
    // Then uncomment 'svg' below and the SVG sanitization filter above
    // 'svg' => 'image/svg+xml',
    return array_merge($mimes, [
        'webp' => 'image/webp',
        'webm' => 'video/webm',
    ]);
});

/**
 * SVG sanitization (requires enshrined/svg-sanitize)
 * Uncomment after installing the package
 */
// add_filter('wp_handle_upload_prefilter', function($file) {
//     if ($file['type'] === 'image/svg+xml') {
//         if (!class_exists('enshrined\svgSanitize\Sanitizer')) {
//             $file['error'] = 'SVG uploads require the svg-sanitize library.';
//             return $file;
//         }
//
//         $sanitizer = new \enshrined\svgSanitize\Sanitizer();
//         $content = file_get_contents($file['tmp_name']);
//         $clean = $sanitizer->sanitize($content);
//
//         if ($clean === false) {
//             $file['error'] = 'SVG file contains potentially malicious content.';
//             return $file;
//         }
//
//         file_put_contents($file['tmp_name'], $clean);
//     }
//     return $file;
// });

/**
 * Sanitize uploaded file names
 */
add_filter('sanitize_file_name', function ($filename) {
    // Remove special characters
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);

    // Remove double extensions (.php.jpg)
    $parts = explode('.', $filename);
    if (count($parts) > 2) {
        $extension = array_pop($parts);
        $filename = implode('_', $parts) . '.' . $extension;
    }

    return $filename;
});

/**
 * Real file MIME type verification
 */
add_filter('wp_check_filetype_and_ext', function ($data, $file, $filename, $mimes) {
    if (!empty($data['ext']) && !empty($data['type'])) {
        return $data;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $real_mime = finfo_file($finfo, $file);
    finfo_close($finfo);

    // Note: SVG intentionally excluded (XSS vector) - enable via upload_mimes filter if needed
    $allowed_mimes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'video/mp4',
        'video/webm',
    ];

    if (!in_array($real_mime, $allowed_mimes)) {
        return ['ext' => false, 'type' => false, 'proper_filename' => false];
    }

    return $data;
}, 10, 4);

/**
 * =============================================================================
 * 8. COMMENT SPAM PROTECTION
 * =============================================================================
 */

/**
 * Honeypot on comment forms
 */
add_action('comment_form_after_fields', function () {
    echo '<p class="comment-form-website" style="position:absolute;left:-9999px;">';
    echo '<label for="website_hp">Website</label>';
    echo '<input type="text" name="website_hp" id="website_hp" value="" tabindex="-1" autocomplete="off" />';
    echo '</p>';
});

add_filter('preprocess_comment', function ($commentdata) {
    if (!empty($_POST['website_hp'])) {
        wp_die('Spam detected.');
    }
    return $commentdata;
});

/**
 * Block comments with too many links
 */
add_filter('preprocess_comment', function ($commentdata) {
    $max_links = 2;
    $content = $commentdata['comment_content'];

    // Count HTML links
    $html_links = preg_match_all('/<a\s[^>]*href\s*=/i', $content, $matches);

    // Count raw URLs that are NOT inside href attributes (to avoid double counting)
    // First, remove all href="..." content, then count remaining URLs
    $content_without_hrefs = preg_replace('/href\s*=\s*["\'][^"\']*["\']/i', '', $content);
    $raw_urls = preg_match_all('/https?:\/\/[^\s<>"\']+/i', $content_without_hrefs, $matches);

    $link_count = $html_links + $raw_urls;

    if ($link_count > $max_links) {
        wp_die('Too many links in comment.');
    }

    return $commentdata;
});

/**
 * =============================================================================
 * 9. PERFORMANCE
 * =============================================================================
 */

/**
 * Disable WordPress emojis (performance gain)
 */
add_action('init', function () {
    remove_action('wp_head', 'print_emoji_detection_script', 7);
    remove_action('admin_print_scripts', 'print_emoji_detection_script');
    remove_action('wp_print_styles', 'print_emoji_styles');
    remove_action('admin_print_styles', 'print_emoji_styles');
    remove_filter('the_content_feed', 'wp_staticize_emoji');
    remove_filter('comment_text_rss', 'wp_staticize_emoji');
    remove_filter('wp_mail', 'wp_staticize_emoji_for_email');

    add_filter('tiny_mce_plugins', function ($plugins) {
        return is_array($plugins) ? array_diff($plugins, ['wpemoji']) : [];
    });

    add_filter('wp_resource_hints', function ($urls, $relation_type) {
        if ($relation_type === 'dns-prefetch') {
            $urls = array_filter($urls, function ($url) {
                return strpos($url, 'https://s.w.org/images/core/emoji/') === false;
            });
        }
        return $urls;
    }, 10, 2);
});

/**
 * Limit revisions
 */
if (!defined('WP_POST_REVISIONS')) {
    define('WP_POST_REVISIONS', 5);
}

/**
 * Increase autosave interval
 */
if (!defined('AUTOSAVE_INTERVAL')) {
    define('AUTOSAVE_INTERVAL', 120); // 2 minutes
}

/**
 * Disable heartbeat on front-end
 */
add_action('init', function () {
    if (!is_admin()) {
        wp_deregister_script('heartbeat');
    }
});

/**
 * =============================================================================
 * 10. LOGGING & MONITORING
 * =============================================================================
 */

/**
 * Log sensitive option changes
 */
add_action('updated_option', function ($option, $old_value, $new_value) {
    $sensitive_options = [
        'siteurl',
        'home',
        'admin_email',
        'users_can_register',
        'default_role',
    ];

    if (in_array($option, $sensitive_options)) {
        error_log(sprintf(
            '[SECURITY] Option "%s" changed from "%s" to "%s" by user %d',
            $option,
            maybe_serialize($old_value),
            maybe_serialize($new_value),
            get_current_user_id()
        ));
    }
}, 10, 3);

/**
 * Log user role changes
 */
add_action('set_user_role', function ($user_id, $role, $old_roles) {
    error_log(sprintf(
        '[SECURITY] User %d role changed from [%s] to [%s] by user %d',
        $user_id,
        implode(', ', $old_roles),
        $role,
        get_current_user_id()
    ));
}, 10, 3);

/**
 * Log plugin deletions
 */
add_action('delete_plugin', function ($plugin_file) {
    error_log(sprintf(
        '[SECURITY] Plugin "%s" deleted by user %d',
        $plugin_file,
        get_current_user_id()
    ));
});

/**
 * Log post/page creation and updates
 */
add_action('save_post', function ($post_id, $post, $update) {
    // Skip autosaves and revisions
    if (wp_is_post_autosave($post_id) || wp_is_post_revision($post_id)) {
        return;
    }

    $action = $update ? 'updated' : 'created';
    error_log(sprintf(
        '[CONTENT] %s %s "%s" (ID: %d) by user %d',
        ucfirst($post->post_type),
        $action,
        $post->post_title,
        $post_id,
        get_current_user_id()
    ));
}, 10, 3);

/**
 * Log post/page deletions
 */
add_action('delete_post', function ($post_id) {
    $post = get_post($post_id);
    if (!$post || $post->post_type === 'revision') {
        return;
    }

    error_log(sprintf(
        '[CONTENT] %s deleted "%s" (ID: %d) by user %d',
        ucfirst($post->post_type),
        $post->post_title,
        $post_id,
        get_current_user_id()
    ));
});

/**
 * Log media uploads
 */
add_action('add_attachment', function ($attachment_id) {
    $attachment = get_post($attachment_id);
    error_log(sprintf(
        '[CONTENT] Media uploaded "%s" (ID: %d) by user %d',
        $attachment->post_title ?: basename(get_attached_file($attachment_id)),
        $attachment_id,
        get_current_user_id()
    ));
});

/**
 * Log media deletions
 */
add_action('delete_attachment', function ($attachment_id) {
    $attachment = get_post($attachment_id);
    error_log(sprintf(
        '[CONTENT] Media deleted "%s" (ID: %d) by user %d',
        $attachment->post_title ?: 'unknown',
        $attachment_id,
        get_current_user_id()
    ));
});

/**
 * Log comment status changes (moderation)
 */
add_action('transition_comment_status', function ($new_status, $old_status, $comment) {
    if ($new_status === $old_status) {
        return;
    }

    error_log(sprintf(
        '[CONTENT] Comment %d status changed from "%s" to "%s" by user %d (on post %d)',
        $comment->comment_ID,
        $old_status,
        $new_status,
        get_current_user_id(),
        $comment->comment_post_ID
    ));
}, 10, 3);

/**
 * =============================================================================
 * 11. HELPERS
 * =============================================================================
 */

/**
 * Helper: Check if IP is in range (Single IP or CIDR)
 * Supports both IPv4 and IPv6
 *
 * @param string $ip The IP to verify
 * @param string $range The allowed IP or CIDR block
 * @return bool
 */
function upsun_ip_in_range($ip, $range)
{
    // Validate input IP
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    // Single IP comparison (no CIDR)
    if (strpos($range, '/') === false) {
        return $ip === $range;
    }

    list($subnet, $bits) = explode('/', $range);

    // Validate subnet
    if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
        return false;
    }

    // Detect IP version
    $ip_is_v6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    $subnet_is_v6 = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

    // IP versions must match
    if ($ip_is_v6 !== $subnet_is_v6) {
        return false;
    }

    // Validate bits range
    $max_bits = $ip_is_v6 ? 128 : 32;
    $bits = (int) $bits;
    if ($bits < 0 || $bits > $max_bits) {
        return false;
    }

    // Convert to binary representation
    $ip_bin = inet_pton($ip);
    $subnet_bin = inet_pton($subnet);

    if ($ip_bin === false || $subnet_bin === false) {
        return false;
    }

    // Build netmask
    $mask = str_repeat('f', (int)($bits / 4));
    $remainder = $bits % 4;
    if ($remainder > 0) {
        $mask .= dechex(0xf << (4 - $remainder) & 0xf);
    }
    $mask = str_pad($mask, $ip_is_v6 ? 32 : 8, '0');
    $mask_bin = pack('H*', $mask);

    // Compare masked values
    return ($ip_bin & $mask_bin) === ($subnet_bin & $mask_bin);
}

/**
 * Get real IP (behind Upsun proxy)
 *
 * SECURITY: This function trusts X-Forwarded-For headers, etc.
 * This is safe on Upsun because:
 * - The Upsun/Platform.sh proxy is trusted and overwrites these headers
 * - Requests must go through their infrastructure
 *
 * If using a CDN (Cloudflare, etc.), ensure it's configured to overwrite
 * headers forged by malicious clients.
 *
 * For environments without a trusted proxy, use only REMOTE_ADDR.
 *
 * @return string The client IP address
 */
function upsun_get_real_ip()
{
    // On Upsun, we can trust proxy headers
    // Order matters: from most specific to most generic
    $trusted_headers = [
        'HTTP_CF_CONNECTING_IP',     // Cloudflare (if used)
        'HTTP_X_FORWARDED_FOR',      // Upsun/Platform.sh proxy
        'HTTP_X_REAL_IP',            // Nginx proxy
    ];

    // Only if on Upsun (trusted proxy)
    if (getenv('PLATFORM_APPLICATION')) {
        foreach ($trusted_headers as $header) {
            if (!empty($_SERVER[$header])) {
                // X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
                // The first one is the original client IP
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
    }

    // Fallback: Direct IP (or non-Upsun environment)
    $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '';

    // Validate the IP - return empty string if invalid (safer than 0.0.0.0)
    // This prevents bypass scenarios where 0.0.0.0 might match unexpected rules
    if (empty($remote_addr) || !filter_var($remote_addr, FILTER_VALIDATE_IP)) {
        // Log this unusual situation for debugging
        error_log('[SECURITY] Warning: Could not determine client IP address');
        return '';
    }

    return $remote_addr;
}

/**
 * Check if on production environment
 */
function upsun_is_production()
{
    return getenv('PLATFORM_BRANCH') === 'main' || getenv('WP_ENV') === 'production';
}

/**
 * =============================================================================
 * 12. ADMIN HARDENING
 * =============================================================================
 */

/**
 * Force SSL on admin
 */
if (!defined('FORCE_SSL_ADMIN')) {
    define('FORCE_SSL_ADMIN', true);
}

/**
 * Disable PHP error display in production
 */
if (upsun_is_production()) {
    @ini_set('display_errors', 0);
    @ini_set('log_errors', 1);
}

/**
 * Add security headers on admin
 */
add_action('admin_init', function () {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
});

/**
 * Session timeout - logout after inactivity
 */
add_filter('auth_cookie_expiration', function ($expiration, $user_id, $remember) {
    if ($remember) {
        return 14 * DAY_IN_SECONDS; // 14 days if "remember me"
    }
    return 2 * HOUR_IN_SECONDS; // 2 hours otherwise
}, 10, 3);

/**
 * Force logout on browser close (without "remember me")
 */
add_action('set_logged_in_cookie', function ($logged_in_cookie, $expire, $expiration, $user_id, $scheme, $token) {
    if ($expire === 0) {
        // Session cookie, no change
        return;
    }
}, 10, 6);

/**
 * =============================================================================
 * 13. BEDROCK-SPECIFIC PROTECTION
 * =============================================================================
 */

/**
 * Block direct access to composer files
 */
add_action('init', function () {
    $blocked_files = [
        '/composer.json',
        '/composer.lock',
        '/auth.json',
        '/.env',
        '/.env.example',
    ];

    $request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

    foreach ($blocked_files as $file) {
        if ($request_uri === $file) {
            http_response_code(403);
            exit('Access denied');
        }
    }
});

/**
 * =============================================================================
 * 14. CUSTOM HOOKS FOR EXTENSIONS
 * =============================================================================
 */

/**
 * Filter to add custom CSP rules
 * Usage: add_filter('upsun_csp_rules', function($rules) { $rules[] = "..."; return $rules; });
 */
add_filter('upsun_csp_rules', function ($rules) {
    return $rules;
}, 10, 1);

/**
 * Filter to add allowed hotlinking domains
 * Usage: add_filter('upsun_hotlink_allowed', function($hosts) { $hosts[] = "..."; return $hosts; });
 */
add_filter('upsun_hotlink_allowed', function ($hosts) {
    return $hosts;
}, 10, 1);

/**
 * =============================================================================
 * SECRET ADMIN PATH (Rewrite Implementation)
 * =============================================================================
 */

// 1. Add Query Var
add_filter('query_vars', function ($vars) {
    $vars[] = 'upsun_secret_login';
    return $vars;
});

// 2. Add Rewrite Rule (on Init)
add_action('init', function () {
    $secret_slug = getenv('WP_ADMIN_SECRET_PATH');
    if (!$secret_slug)
        return;

    // Map /<secret> to index.php?upsun_secret_login=1
    add_rewrite_rule(
        '^' . preg_quote($secret_slug, '/') . '/?$',
        'index.php?upsun_secret_login=1',
        'top'
    );
});

// 3. Handle the Login Load
add_action('parse_request', function ($wp) {
    if (isset($wp->query_vars['upsun_secret_login']) && $wp->query_vars['upsun_secret_login'] == 1) {

        // --- IP WHITELIST CHECK (with CIDR) ---
        $allowed_ips_env = getenv('WP_ADMIN_ALLOWED_IPS');
        if ($allowed_ips_env) {
            $allowed_ranges = array_map('trim', explode(',', $allowed_ips_env));
            $client_ip = upsun_get_real_ip();
            $allowed = false;

            foreach ($allowed_ranges as $range) {
                if (upsun_ip_in_range($client_ip, $range)) {
                    $allowed = true;
                    break;
                }
            }

            if (!$allowed) {
                error_log("[SECURITY] Blocked IP $client_ip (Allowed: $allowed_ips_env)");
                wp_die('Unauthorized IP address.', 'Forbidden', ['response' => 403]);
            }
        }

        // Mark this as a legitimate secret path access (cannot be forged via GET/POST)
        define('UPSUN_SECRET_LOGIN_ACTIVE', true);

        // Load wp-login.php explicitly
        require_once ABSPATH . 'wp-login.php';
        exit;
    }
});

// 4. Block Direct Access to wp-login.php and wp-admin for unauthenticated users
add_action('init', function () {
    $secret_slug = getenv('WP_ADMIN_SECRET_PATH');
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';

    // Block /wp/wp-admin/* for unauthenticated visitors (stealth 404 for scanners)
    // Check if accessing wp-admin and no WordPress auth cookie present
    if (preg_match('#^/wp/wp-admin(?:/|$)#', $request_uri)) {
        // Check for WordPress login cookie (basic presence check)
        $has_auth_cookie = false;
        foreach ($_COOKIE as $name => $value) {
            if (strpos($name, 'wordpress_logged_in_') === 0) {
                $has_auth_cookie = true;
                break;
            }
        }

        // No auth cookie = scanner or unauthenticated visitor → 404
        if (!$has_auth_cookie) {
            status_header(404);
            nocache_headers();
            echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
            exit;
        }
    }

    // Block direct wp-login.php access if secret path is configured
    if (!$secret_slug) {
        // Fail-secure: Log warning in production if protection is disabled
        if (upsun_is_production()) {
            error_log('[SECURITY] WARNING: WP_ADMIN_SECRET_PATH is not set. Login page is publicly accessible.');
        }
        return;
    }

    global $pagenow;

    // If accessing wp-login.php directly AND not via legitimate secret path rewrite
    // SECURITY: Check constant (unforgeable) instead of GET/POST params (forgeable)
    if ($pagenow === 'wp-login.php' && !defined('UPSUN_SECRET_LOGIN_ACTIVE')) {
        // Return 404 Not Found to obscure existence
        status_header(404);
        nocache_headers();
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
        exit;
    }
}, 1);