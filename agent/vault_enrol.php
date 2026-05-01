<?php
/*
 * Vault enrolment redemption page.
 *
 * Reachable via a magic link the admin emailed:
 *   /agent/vault_enrol.php?t=<token>
 *
 * Required state to proceed:
 *   - User is signed in via SSO (login.logged=true). If not, redirect to the
 *     SSO login flow with a return URL so they come back here.
 *   - The token is valid, unconsumed, and not expired for the current user.
 *
 * On successful redemption the master key is recovered and pushed into the
 * session via generateUserSessionKey. The page then renders the standard
 * PIN/PRF enrolment forms (reuses the same UI components as user_security.php).
 */

ob_start();

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_headers.php';
require_once __DIR__ . '/../includes/vault_unlock.php';
require_once __DIR__ . '/../includes/vault_enrolment.php';
require_once __DIR__ . '/../includes/security_audit.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

ob_end_clean();

// Require authenticated session. If not signed in, bounce to login with
// the current URL as last_visited so we return here after sign-in.
if (empty($_SESSION['user_id']) || empty($_SESSION['logged'])) {
    $_SESSION['login_message'] = 'Sign in via SSO to redeem your vault enrolment link.';
    header('Location: /login.php?last_visited=' . base64_encode($_SERVER['REQUEST_URI']));
    exit;
}

require_once __DIR__ . '/../includes/load_global_settings.php';
require_once __DIR__ . '/../includes/inc_set_timezone.php';

$user_id = intval($_SESSION['user_id']);
$row = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT user_name FROM users WHERE user_id = $user_id LIMIT 1"));
$user_name = $row ? $row['user_name'] : '';

$token = (string)($_GET['t'] ?? '');
$error = null;

if ($token === '') {
    $error = 'Missing enrolment token.';
} else {
    $master = vaultRedeemEnrolmentToken($user_id, $token, $mysqli);
    if ($master === null) {
        $error = 'This enrolment link is invalid, expired, or has already been used.';
        logAction('Vault', 'Enrolment failed', "Invalid magic-link enrolment attempt for user_id=$user_id", 0, $user_id);
        securityAudit('vault.enrolment.failed', [
            'user_id' => $user_id,
            'metadata' => ['reason' => 'invalid_or_consumed'],
        ]);
    } else {
        // Push master key into session so the standard enrolment forms work.
        session_regenerate_id(true);
        generateUserSessionKey($master);
        $_SESSION['vault_unlocked']    = true;
        $_SESSION['vault_unlocked_at'] = time();
        $_SESSION['vault_step_up_at']  = time();
        $_SESSION['csrf_token']        = randomString(32);

        logAction('Vault', 'Enrolment redeemed', "$user_name redeemed magic-link vault enrolment", 0, $user_id);
        securityAudit('vault.enrolment.redeemed', [
            'user_id' => $user_id,
        ]);

        // Send them straight to the security page where they enrol PIN / PRF.
        header('Location: /agent/user/user_security.php?enrolment=ok');
        exit;
    }
}

// Render an error page on failure path.
$brand_row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT companies.company_name, companies.company_logo
    FROM settings
    LEFT JOIN companies ON settings.company_id = companies.company_id
    WHERE settings.company_id = 1 LIMIT 1
"));
$company_name = $brand_row['company_name'] ?? 'ITFlow';
$company_logo = $brand_row['company_logo'] ?? '';

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title><?= nullable_htmlentities($company_name) ?> | Vault enrolment</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">
    <link rel="stylesheet" href="/plugins/fontawesome-free/css/all.min.css">
    <link rel="stylesheet" href="/plugins/adminlte/css/adminlte.min.css">
</head>
<body class="hold-transition login-page">
<div class="login-box">
    <div class="login-logo">
        <?php if (!empty($company_logo) && file_exists($_SERVER['DOCUMENT_ROOT'] . "/uploads/settings/$company_logo")) { ?>
            <img alt="<?= nullable_htmlentities($company_name) ?> logo" height="110" width="380" class="img-fluid" src="/uploads/settings/<?= htmlentities($company_logo) ?>">
        <?php } else { ?>
            <span class="text-primary text-bold"><i class="fas fa-paper-plane mr-2"></i>IT</span>Flow
        <?php } ?>
    </div>
    <div class="card">
        <div class="card-body login-card-body">
            <p class="login-box-msg px-0"><i class="fa fa-envelope-open-text mr-2"></i>Vault enrolment link</p>

            <?php if ($error): ?>
                <div class="alert alert-danger small"><?= htmlentities($error) ?></div>
            <?php endif; ?>

            <p class="small text-muted">
                Ask your administrator to issue a fresh enrolment link.
            </p>
            <p class="small mb-0">
                <a href="/post.php?logout">Log out</a>
            </p>
        </div>
    </div>
</div>
</body>
</html>
