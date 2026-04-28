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
