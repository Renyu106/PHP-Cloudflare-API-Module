<?php

// Cache
// cf_set_developer_mode(true or false) - Set Developer Mode
// cf_get_developer_mode() - Get Developer Mode
// cf_set_always_online(true or false) - Set Always Online
// cf_get_always_online() - Get Always Online
// cf_set_browser_cache_ttl(0~31536000) - Set Browser Cache TTL
// cf_get_browser_cache_ttl() - Get Browser Cache TTL
// cf_set_cache_level (aggressive, basic, simplified) - Set Cache Level
// cf_get_cache_level() - Get Cache Level
// cf_purge_all_cache(true) - Purge All Cache

// SSL
// cf_set_ssl(flexible, full, strict, off) - Set SSL
// cf_get_ssl() - Get SSL Setting
// cf_get_ssl_verification_info() - Get SSL Verification Info
// cf_get_certificate_pack() - Get Certificate Pack
// cf_set_always_use_https(true or false) - Set Always Use HTTPS
// cf_get_always_use_https() - Get Always Use HTTPS
// cf_get_security_header() - Get Security Header
// cf_set_min_tls_version(1.0, 1.1, 1.2) - Set Min TLS Version
// cf_get_min_tls_version() - Get Min TLS Version
// cf_set_opportunistic_encryption(true or false) - Set Opportunistic Encryption
// cf_get_opportunistic_encryption() - Get Opportunistic Encryption
// cf_get_tls_1_3() - Get TLS 1.3 Using Area
// cf_set_auto_rewrite_https(true or false) - Set Auto Rewrite HTTPS
// cf_get_auto_rewrite_https() - Get Auto Rewrite HTTPS
// cf_set_tls_client_auth(true or false) - Set TLS Client Auth
// cf_get_tls_client_auth() - Get TLS Client Auth

// Security
// cf_get_ua_rules() - Get User-Agent Rules
// cf_set_security_level(off(essentially_off), low, medium, high, under_attack) - Set Security Level
// cf_get_security_level() - Get Security Level
// cf_set_challenge_ttl(300~31536000) - Set Challenge TTL
// cf_get_challenge_ttl() - Get Challenge TTL
// cf_set_browser_check(true or false) - Set Browser Check
// cf_get_browser_check() - Get Browser Check

// Speed
// cf_set_minify(css, html, javascript, true of false) - Set Minify
// cf_get_minify() - Get Minify
// cf_set_brotli(true or false) - Set Brotli
// cf_get_brotli() - Get Brotli
// cf_set_early_hints(true or false) - Set Early Hints
// cf_get_early_hints() - Get Early Hints
// cf_set_rocket_loader(true or false) - Set Rocket Loader
// cf_get_rocket_loader() - Get Rocket Loader

// Network
// cf_set_ipv6(true or false) - Set IPv6
// cf_get_ipv6() - Get IPv6
// cf_set_websockets(true or false) - Set WebSockets
// cf_get_websockets() - Get WebSockets
// cf_set_opportunistic_onion(true or false) - Set Opportunistic Onion
// cf_get_opportunistic_onion() - Get Opportunistic Onion
// cf_set_pseudo_ipv4(true or false) - Set Pseudo IPv4
// cf_get_pseudo_ipv4() - Get Pseudo IPv4
// cf_set_ip_geolocation (true or false) - Set IP Geolocation
// cf_get_ip_geolocation() - Get IP Geolocation
// cf_set_network_error_logging(true or false) - Set Network Error Logging
// cf_get_network_error_logging() - Get Network Error Logging

// Developer Mode
function cf_set_developer_mode($type)
{
    require_once('cf_config.php');
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/development_mode";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_developer_mode()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/development_mode";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Always Online
function cf_set_always_online($type)
{
    require_once('cf_config.php');
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/always_online";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_always_online()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/always_online";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Browser Cache TTL
function cf_set_browser_cache_ttl($ttl)
{
    require_once('cf_config.php');
    if (!is_numeric($ttl)) return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/browser_cache_ttl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":' . $ttl . '}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_browser_cache_ttl()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/browser_cache_ttl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Cache Level
function cf_set_cache_level($level)
{
    require_once('cf_config.php');
    if ($level !== "aggressive" && $level !== "basic" && $level !== "simplified") return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/cache_level";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $level . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_cache_level()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/cache_level";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Remove Cache
function cf_purge_all_cache($agree)
{
    require_once('cf_config.php');
    if ($agree !== true) return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/purge_cache";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'DELETE';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"purge_everything":true}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// SSL
function cf_set_ssl($type)
{
    require_once('cf_config.php');
    if ($type !== "flexible" && $type !== "full" && $type !== "off" && $type !== "strict") return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ssl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_ssl()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ssl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_ssl_verification_info()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/ssl/verification";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Certificate Pack
function cf_get_certificate_pack()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/ssl/certificate_packs";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Always HTTPS use
function cf_set_always_use_https($type)
{
    require_once('cf_config.php');
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/always_use_https";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_always_use_https()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/always_use_https";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Security Header
function cf_get_security_header()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/security_header";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Min TLS Version
function cf_set_min_tls_version($version)
{
    require_once 'cf_config.php';
    if (!is_numeric($version)) return false;
    if ($version !== 1.0 && $version !== 1.1 && $version !== 1.2 && $version !== 1.3) return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/min_tls_version";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $version . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_min_tls_version()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/min_tls_version";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Opportunistic Encryption
function cf_set_opportunistic_encryption($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/opportunistic_encryption";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_opportunistic_encryption()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/opportunistic_encryption";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Get TLS 1.3 Using Area
function cf_get_tls_1_3()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/tls_1_3";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Auto Rewrite HTTPS
function cf_set_auto_rewrite_https($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/automatic_https_rewrites";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_auto_rewrite_https()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/automatic_https_rewrites";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Tls Client Auth
function cf_set_tls_client_auth($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/tls_client_auth";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_tls_client_auth()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/tls_client_auth";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// User Agent Blocking
function cf_get_ua_rules()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/firewall/access_rules/rules";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Security Level
function cf_set_security_level($type)
{
    require_once 'cf_config.php';
    if ($type !== "off" && $type !== "essentially_off" && $type !== "low" && $type !== "medium" && $type !== "high" && $type !== "under_attack") return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/security_level";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_security_level()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/security_level";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Challenge TTL
function cf_set_challenge_ttl($ttl)
{
    require_once 'cf_config.php';
    if ($ttl < 300 || $ttl > 31536000) return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/challenge_ttl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":' . $ttl . '}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_challenge_ttl()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/challenge_ttl";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Browser Check
function cf_set_browser_check($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/browser_check";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_browser_check()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/browser_check";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Minify
function cf_set_minify($name, $type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    if ($name !== "css" && $name !== "html" && $name !== "js") return false;
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/minify";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":{"' . $name . '":"' . $type . '"}}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_minify()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/minify";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Brotli
function cf_set_brotli($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/brotli";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_brotli()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/brotli";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Early Hints
function cf_set_early_hints($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/early_hints";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_early_hints()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/early_hints";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Rocket Loader
function cf_set_rocket_loader($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/rocket_loader";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_rocker_loader()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/rocket_loader";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// IPv6
function cf_set_ipv6($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ipv6";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_ipv6()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ipv6";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Web Sockets
function cf_set_web_sockets($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/websockets";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_web_sockets()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/websockets";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Opportunistic Onions
function cf_set_opportunistic_onion($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/opportunistic_onion";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_opportunistic_onion()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/opportunistic_onion";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Pseudo IPv4
function cf_set_pseudo_ipv4($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/pseudo_ipv4";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_pseudo_ipv4()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/pseudo_ipv4";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// IP Geolocation
function cf_set_ip_geolocation($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ip_geolocation";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_ip_geolocation()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/ip_geolocation";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

// Network Error Logging
function cf_set_network_error_logging($type)
{
    require_once 'cf_config.php';
    if ($type !== true && $type !== false) return false;
    if ($type == true) $type = "on";
    else $type = "off";
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/nel";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'PATCH';
    $cf_curl_opt[CURLOPT_POSTFIELDS] = '{"value":"' . $type . '"}';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

function cf_get_network_error_logging()
{
    require_once 'cf_config.php';
    $cf_curl_opt[CURLOPT_URL] = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/settings/nel";
    $cf_curl_opt[CURLOPT_CUSTOMREQUEST] = 'GET';

    $cf_curl = curl_init(); // Initiate cURL
    curl_setopt_array($cf_curl, $cf_curl_opt); // Set cURL options
    $response = curl_exec($cf_curl); // Execute cURL
    curl_close($cf_curl); // Close cURL
    return $response;
}

//

echo cf_get_network_error_logging(true);