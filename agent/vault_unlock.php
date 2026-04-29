<?php
/*
 * Vault unlock — PIN entry for SSO-authenticated agents (or anyone whose
 * session has the user logged in but the vault not yet unlocked).
 *
 * Reachable when:
 *   - $_SESSION['user_id'] is set (logged in)
 *   - vault is not unlocked yet (no master key in session)
 *   - the user has a PIN method enrolled
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_headers.php';
require_once __DIR__ . '/../includes/vault_unlock.php';
require_once __DIR__ . '/../includes/rate_limit.php';
require_once __DIR__ . '/../includes/security_audit.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

if (empty($_SESSION['user_id']) || empty($_SESSION['logged'])) {
    header('Location: /login.php');
    exit;
}

$user_id   = intval($_SESSION['user_id']);
$row       = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT user_name FROM users WHERE user_id = $user_id LIMIT 1"));
$user_name = $row ? $row['user_name'] : '';

// Company branding for the login-page chrome
$brand_row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT companies.company_name, companies.company_logo
    FROM settings
    LEFT JOIN companies ON settings.company_id = companies.company_id
    WHERE settings.company_id = 1
    LIMIT 1
"));
$company_name = $brand_row['company_name'] ?? 'ITFlow';
$company_logo = $brand_row['company_logo'] ?? '';

require_once __DIR__ . '/../includes/load_global_settings.php';
require_once __DIR__ . '/../includes/inc_set_timezone.php';

$has_pin = vaultUserHasMethod($user_id, 'pin', $mysqli);
$has_prf = vaultUserHasMethod($user_id, 'webauthn_prf', $mysqli);

if (!$has_pin && !$has_prf) {
    // Nothing to unlock with — let them in but keep vault locked.
    $_SESSION['vault_unlocked'] = false;
    $start = $config_start_page ?? 'clients.php';
    header("Location: /agent/$start");
    exit;
}

// Already unlocked? Skip.
if (vaultMasterKeyFromSession() !== null) {
    $_SESSION['vault_unlocked'] = true;
    $start = $config_start_page ?? 'clients.php';
    header("Location: /agent/$start");
    exit;
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Per-IP rate limit. Configurable via Admin → Security settings.
    $session_ip = mysqli_real_escape_string($mysqli, sanitizeInput(getIP()));
    rateLimitCheckScope('vault', $mysqli);

    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $error = 'Session expired — please try again.';
    } else {
        $pin = (string)($_POST['pin'] ?? '');
        $unlock = vaultUnlockWithPin($user_id, $pin, $mysqli);
        if ($unlock !== null) {
            // Privilege escalation point — rotate the session id.
            session_regenerate_id(true);
            generateUserSessionKey($unlock['master']);
            // Phase 11: when the PIN method also wraps the privkey, push
            // it to the session so the user retains compartmentalised
            // (per-grant) decrypt access after SSO+PIN unlock.
            if (!empty($unlock['privkey'])) {
                pushUserPrivkeyToSession($unlock['privkey']);
            }
            $_SESSION['vault_unlocked'] = true;
            $_SESSION['csrf_token'] = randomString(32);
            logAction('Vault', 'Unlock', "$user_name unlocked vault via PIN", 0, $user_id);
            securityAudit('vault.unlock.success', [
                'user_id' => $user_id,
                'metadata' => ['method' => 'pin', 'privkey_restored' => !empty($unlock['privkey'])],
            ]);
            $start = $config_start_page ?? 'clients.php';
            header("Location: /agent/$start");
            exit;
        }
        // Generic message — don't reveal which factor failed
        $error = 'Incorrect PIN, or the vault is temporarily locked due to repeated failed attempts.';
        logAction('Vault', 'Unlock failed', "$user_name failed vault PIN unlock", 0, $user_id);
        securityAudit('vault.unlock.failed', [
            'user_id' => $user_id,
            'metadata' => ['method' => 'pin'],
        ]);
    }
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?= nullable_htmlentities($company_name) ?> | Unlock vault</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">

    <link rel="stylesheet" href="/plugins/fontawesome-free/css/all.min.css">

    <?php if (file_exists($_SERVER['DOCUMENT_ROOT'] . '/uploads/favicon.ico')) { ?>
        <link rel="icon" type="image/x-icon" href="/uploads/favicon.ico">
    <?php } ?>

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

            <p class="login-box-msg px-0">
                <i class="fa fa-lock mr-2"></i>Unlock your vault
            </p>

            <?php if ($error): ?>
                <div class="alert alert-danger small"><?= htmlentities($error) ?></div>
            <?php endif; ?>

            <p class="small text-muted text-center mb-3">
                Signed in as <strong><?= htmlentities($user_name) ?></strong>.
            </p>

            <?php if ($has_prf): ?>
                <button type="button" id="vault_prf_unlock_btn"
                        class="btn btn-primary btn-block mb-2" data-autostart="1">
                    <i class="fas fa-fingerprint mr-2"></i>Unlock with security key
                </button>
                <div id="vault_prf_unlock_status" class="small text-center mb-3"></div>
                <script src="/plugins/webauthn/vault-prf-unlock.js"></script>
            <?php endif; ?>

            <?php if ($has_prf && $has_pin): ?>
                <hr class="my-2">
                <p class="small text-muted text-center mb-2">Or use your PIN:</p>
            <?php endif; ?>

            <?php if ($has_pin): ?>
                <form method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= htmlentities($_SESSION['csrf_token']) ?>">

                    <div class="input-group mb-3">
                        <input type="password" class="form-control" name="pin"
                               placeholder="Vault PIN" required <?= $has_prf ? '' : 'autofocus' ?>
                               inputmode="text" minlength="<?= VAULT_PIN_MIN_LENGTH ?>">
                        <div class="input-group-append">
                            <div class="input-group-text"><i class="fas fa-key"></i></div>
                        </div>
                    </div>

                    <button type="submit" class="btn <?= $has_prf ? 'btn-outline-secondary' : 'btn-primary' ?> btn-block mb-3">
                        <i class="fa fa-unlock mr-2"></i>Unlock with PIN
                    </button>
                </form>

                <p class="small text-muted mb-0">
                    After <?= VAULT_LOCKOUT_THRESHOLD ?> failed PIN attempts the method is locked for <?= VAULT_LOCKOUT_MINUTES ?> minutes.
                </p>
            <?php endif; ?>

            <hr class="my-3">

            <p class="small mb-0">
                <?php if (!$has_pin): ?>
                    No PIN fallback configured. Add one via My Account → Security after signing in with password.<br>
                <?php endif; ?>
                <a href="/post.php?logout">Log out</a>
            </p>
        </div>
    </div>
</div>

</body>
</html>
