<?php
/*
 * Standard security response headers.
 *
 * Applied to:
 *  - Authenticated pages: included via check_login.php (which session_init
 *    pulls in indirectly).
 *  - Public entry points (login.php, SSO endpoints, vault unlock): included
 *    explicitly.
 *
 * Headers set here:
 *  - Strict-Transport-Security: when HTTPS is enforced.
 *  - X-Frame-Options DENY: prevents clickjacking. ITFlow has no legitimate
 *    iframe embedding use case.
 *  - X-Content-Type-Options nosniff: stop MIME-sniffing of static assets.
 *  - Referrer-Policy strict-origin-when-cross-origin: do not leak full URLs.
 *  - Permissions-Policy: deny browser features ITFlow does not use.
 *  - Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy: isolate
 *    browsing context from third-party windows.
 *
 * NOT set here:
 *  - Content-Security-Policy. ITFlow uses inline scripts and event handlers
 *    extensively; a strict CSP would break the app. The login page sets a
 *    minimal CSP locally; broader CSP rollout requires a refactor that is
 *    out of scope for this phase.
 */

if (!function_exists('sendSecurityHeaders')) {
    function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        // HSTS — only when HTTPS is in effect. 1-year max-age + preload.
        global $config_https_only;
        $is_https = (
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        );
        if (!empty($config_https_only) && $is_https) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');

        // Browser features ITFlow does not use. Locking these down reduces
        // the attack surface for compromised JavaScript.
        header('Permissions-Policy: '
            . 'accelerometer=(), '
            . 'autoplay=(), '
            . 'camera=(), '
            . 'cross-origin-isolated=(), '
            . 'display-capture=(), '
            . 'encrypted-media=(), '
            . 'fullscreen=(self), '
            . 'geolocation=(), '
            . 'gyroscope=(), '
            . 'magnetometer=(), '
            . 'microphone=(), '
            . 'midi=(), '
            . 'payment=(), '
            . 'picture-in-picture=(), '
            . 'publickey-credentials-get=(self), '
            . 'screen-wake-lock=(), '
            . 'sync-xhr=(self), '
            . 'usb=(), '
            . 'web-share=(), '
            . 'xr-spatial-tracking=()'
        );
    }
}

sendSecurityHeaders();
