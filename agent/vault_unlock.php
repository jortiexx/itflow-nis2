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

require_once __DIR__ . '/../includes/load_global_settings.php';
require_once __DIR__ . '/../includes/inc_set_timezone.php';

$has_pin = vaultUserHasMethod($user_id, 'pin', $mysqli);

if (!$has_pin) {
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

    // Per-IP rate limit: 20 failed PIN attempts in 10 minutes blocks further tries.
    $session_ip = mysqli_real_escape_string($mysqli, sanitizeInput(getIP()));
    rateLimitCheck('Vault', 'Unlock failed', 20, 600);

    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $error = 'Session expired — please try again.';
    } else {
        $pin = (string)($_POST['pin'] ?? '');
        $master = vaultTryUnlockWithPin($user_id, $pin, $mysqli);
        if ($master !== null) {
            // Privilege escalation point — rotate the session id.
            session_regenerate_id(true);
            generateUserSessionKey($master);
            $_SESSION['vault_unlocked'] = true;
            $_SESSION['csrf_token'] = randomString(32);
            logAction('Vault', 'Unlock', "$user_name unlocked vault via PIN", 0, $user_id);
            securityAudit('vault.unlock.success', [
                'user_id' => $user_id,
                'metadata' => ['method' => 'pin'],
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
    <meta charset="UTF-8">
    <title>Unlock vault</title>
    <link rel="stylesheet" href="/plugins/AdminLTE/dist/css/adminlte.min.css">
    <link rel="stylesheet" href="/plugins/fontawesome-free/css/all.min.css">
</head>
<body class="hold-transition login-page" style="background: #1f2d3d;">
<div class="login-box">
    <div class="card card-outline card-primary">
        <div class="card-header text-center">
            <h3 class="mb-0"><i class="fa fa-lock mr-2"></i>Unlock vault</h3>
        </div>
        <div class="card-body">

            <?php if ($error): ?>
                <div class="alert alert-danger small"><?= htmlentities($error) ?></div>
            <?php endif; ?>

            <p class="small text-muted">
                Signed in as <strong><?= htmlentities($user_name) ?></strong>. Enter your vault PIN to access stored credentials. After <?= VAULT_LOCKOUT_THRESHOLD ?> failed attempts the PIN is locked for <?= VAULT_LOCKOUT_MINUTES ?> minutes.
            </p>

            <form method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlentities($_SESSION['csrf_token']) ?>">

                <div class="input-group mb-3">
                    <input type="password" class="form-control" name="pin"
                           placeholder="Vault PIN" required autofocus
                           inputmode="text" minlength="<?= VAULT_PIN_MIN_LENGTH ?>">
                    <div class="input-group-append">
                        <div class="input-group-text"><i class="fas fa-key"></i></div>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block mb-3">
                    <i class="fa fa-unlock mr-2"></i>Unlock
                </button>
            </form>

            <hr>
            <p class="small mb-0">
                Don't have a PIN? Sign in with your password first to set one up. <br>
                <a href="/post.php?logout">Log out</a>
            </p>
        </div>
    </div>
</div>
</body>
</html>
