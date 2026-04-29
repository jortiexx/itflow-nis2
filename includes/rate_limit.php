<?php
/*
 * Lightweight per-IP rate limiter.
 *
 * Uses the existing `logs` table (mysql) as the backing store. Each call
 * to rateLimitCheck() consults the count of matching log entries within
 * the supplied window. If exceeded, the function emits a 429 and exits.
 * It does NOT itself write a log entry — callers are expected to have
 * logAction() in their normal failure path; this just reads what's
 * already there.
 *
 * For endpoints that should be limited but do not naturally produce log
 * entries on every request (e.g. OAuth callbacks where the legitimate
 * response is success), a short-lived in-memory bucket is appropriate.
 * For now we only need rate limiting on credential-style endpoints
 * (vault unlock attempts) and SSO callback failure cycles, both of
 * which already log via logAction.
 */

/**
 * Built-in defaults for each rate-limit scope. Used when the settings
 * row is missing the column (fresh install before the migration runs)
 * or when the config value is non-positive (treat as disabled scope).
 */
if (!defined('RATELIMIT_DEFAULTS')) {
    define('RATELIMIT_DEFAULTS', [
        'login'   => ['max' => 10, 'window' => 600,  'log_type' => 'Login',     'log_action' => 'Failed'],
        'vault'   => ['max' => 20, 'window' => 600,  'log_type' => 'Vault',     'log_action' => 'Unlock failed'],
        'sso'     => ['max' => 20, 'window' => 600,  'log_type' => 'SSO Login', 'log_action' => 'Failed'],
        'api'     => ['max' => 30, 'window' => 600,  'log_type' => 'API',       'log_action' => 'Failed'],
        'pwreset' => ['max' => 5,  'window' => 3600, 'log_type' => 'Contact',   'log_action' => 'Modify'],
    ]);
}

if (!function_exists('rateLimitConfig')) {
    /**
     * Read rate-limit thresholds from the settings row. Returns a static
     * cache so subsequent calls are free. Falls back to RATELIMIT_DEFAULTS
     * if the columns don't exist yet (mid-upgrade).
     */
    function rateLimitConfig(mysqli $mysqli): array
    {
        static $cache = null;
        if ($cache !== null) return $cache;

        $cache = [
            'enabled' => true,
            'scopes'  => RATELIMIT_DEFAULTS,
        ];

        $row = @mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT config_ratelimit_enabled,
                    config_ratelimit_login_max, config_ratelimit_login_window,
                    config_ratelimit_vault_max, config_ratelimit_vault_window,
                    config_ratelimit_sso_max, config_ratelimit_sso_window,
                    config_ratelimit_api_max, config_ratelimit_api_window,
                    config_ratelimit_pwreset_max, config_ratelimit_pwreset_window
             FROM settings WHERE company_id = 1 LIMIT 1"));
        if (!$row) {
            return $cache;
        }
        $cache['enabled'] = !isset($row['config_ratelimit_enabled']) || intval($row['config_ratelimit_enabled']) === 1;

        $map = [
            'login'   => ['max' => 'config_ratelimit_login_max',   'window' => 'config_ratelimit_login_window'],
            'vault'   => ['max' => 'config_ratelimit_vault_max',   'window' => 'config_ratelimit_vault_window'],
            'sso'     => ['max' => 'config_ratelimit_sso_max',     'window' => 'config_ratelimit_sso_window'],
            'api'     => ['max' => 'config_ratelimit_api_max',     'window' => 'config_ratelimit_api_window'],
            'pwreset' => ['max' => 'config_ratelimit_pwreset_max', 'window' => 'config_ratelimit_pwreset_window'],
        ];
        foreach ($map as $scope => $cols) {
            if (isset($row[$cols['max']]) && intval($row[$cols['max']]) > 0) {
                $cache['scopes'][$scope]['max'] = intval($row[$cols['max']]);
            }
            if (isset($row[$cols['window']]) && intval($row[$cols['window']]) > 0) {
                $cache['scopes'][$scope]['window'] = intval($row[$cols['window']]);
            }
        }
        return $cache;
    }
}

if (!function_exists('rateLimitCheckScope')) {
    /**
     * Look up the configured threshold for the named scope and apply it.
     *
     * Scopes: login | vault | sso | api | pwreset
     *
     * No-op if rate limiting is globally disabled in settings, or if the
     * scope name is unknown.
     */
    function rateLimitCheckScope(string $scope, mysqli $mysqli): void
    {
        $cfg = rateLimitConfig($mysqli);
        if (!$cfg['enabled']) return;
        if (!isset($cfg['scopes'][$scope])) return;
        $s = $cfg['scopes'][$scope];
        rateLimitCheck($s['log_type'], $s['log_action'], $s['max'], $s['window']);
    }
}

if (!function_exists('rateLimitCheck')) {

    /**
     * Block the request if there are >= $max_attempts log entries with
     * log_type=$log_type AND log_action=$log_action AND log_ip=current
     * within the past $window_seconds.
     *
     * @param string $log_type     Value of logs.log_type to count
     * @param string $log_action   Value of logs.log_action to count (e.g. 'Failed')
     * @param int    $max_attempts Threshold (>= triggers block)
     * @param int    $window_seconds Window in seconds
     */
    function rateLimitCheck(string $log_type, string $log_action, int $max_attempts, int $window_seconds): void
    {
        global $mysqli, $session_ip;

        if (!isset($mysqli) || !$mysqli) {
            return;
        }
        $ip = isset($session_ip) ? $session_ip : (isset($_SERVER['REMOTE_ADDR']) ? mysqli_real_escape_string($mysqli, $_SERVER['REMOTE_ADDR']) : '');
        if ($ip === '') {
            return;
        }
        $log_type_e   = mysqli_real_escape_string($mysqli, $log_type);
        $log_action_e = mysqli_real_escape_string($mysqli, $log_action);
        $window       = intval($window_seconds);

        $row = mysqli_fetch_assoc(mysqli_query(
            $mysqli,
            "SELECT COUNT(log_id) AS n
             FROM logs
             WHERE log_type   = '$log_type_e'
               AND log_action = '$log_action_e'
               AND log_ip     = '$ip'
               AND log_created_at > (NOW() - INTERVAL $window SECOND)"
        ));
        $n = $row ? intval($row['n']) : 0;

        if ($n >= $max_attempts) {
            header('HTTP/1.1 429 Too Many Requests');
            header('Retry-After: ' . $window);
            // Best-effort log; if logging itself is rate-limited we don't loop.
            if (function_exists('logAction')) {
                @logAction($log_type, 'Blocked', "$ip blocked due to $n recent $log_action attempts in {$window}s window");
            }
            exit("Too many requests. Please wait and try again.");
        }
    }
}
