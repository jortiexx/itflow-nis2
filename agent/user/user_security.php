<?php
require_once "includes/inc_all_user.php";
require_once "../../includes/vault_unlock.php";

// User remember me tokens
$sql_remember_tokens = mysqli_query($mysqli, "SELECT * FROM remember_tokens WHERE remember_token_user_id = $session_user_id");
$remember_token_count = mysqli_num_rows($sql_remember_tokens);

$vault_methods = vaultListMethods($session_user_id, $mysqli);
$vault_master_key_present = (vaultMasterKeyFromSession() !== null);

$webauthn_creds = [];
try {
    $rs = mysqli_query($mysqli, "
        SELECT cred_id, label, cose_alg, created_at, last_used_at
        FROM user_webauthn_credentials
        WHERE user_id = $session_user_id
        ORDER BY created_at ASC
    ");
    if ($rs) while ($r = mysqli_fetch_assoc($rs)) $webauthn_creds[] = $r;
} catch (Throwable $e) {
    // Table does not exist yet (pre-migration). Silently treat as empty list.
}

?>

<div class="card card-dark">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-shield-alt mr-2"></i>Your Password</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" enctype="multipart/form-data" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <label>Your New Password <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-lock"></i></span>
                    </div>
                    <input type="password" class="form-control" data-toggle="password" name="new_password" placeholder="Leave blank for no change" autocomplete="new-password" minlength="8" required>
                    <div class="input-group-append">
                        <span class="input-group-text"><i class="fa fa-fw fa-eye"></i></span>
                    </div>
                </div>
            </div>

            <button type="submit" name="edit_your_user_password" class="btn btn-primary"><i class="fas fa-check mr-2"></i>Change</button>

        </form>

         <div class="float-right">
            <?php if (empty($session_token)) { ?>
                <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#enableMFAModal">
                    <i class="fas fa-lock mr-2"></i>Enable MFA
                </button>

                <?php require_once "modals/user_mfa_modal.php"; ?>

            <?php } else { ?>
                <a href="post.php?disable_mfa&csrf_token=<?php echo $_SESSION['csrf_token'] ?>" class="btn btn-danger"><i class="fas fa-unlock mr-2"></i>Disable MFA</a>
            <?php } ?>
        </div>

    </div>
</div>

<div class="card card-dark">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-fw fa-fingerprint mr-2"></i>Security keys (WebAuthn)</h3>
    </div>
    <div class="card-body">
        <p class="small text-muted">
            Register a hardware security key (YubiKey, Windows Hello, Touch ID, platform passkey) as a phishing-resistant second factor.
            Once enrolled, you'll see a "Use security key" button at sign-in instead of needing a TOTP code.
        </p>

        <?php if (empty($webauthn_creds)): ?>
            <p class="text-muted small">No security keys registered.</p>
        <?php else: ?>
            <table class="table table-sm">
                <thead><tr><th>Label</th><th>Algorithm</th><th>Registered</th><th>Last used</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($webauthn_creds as $c): ?>
                    <tr>
                        <td><?= nullable_htmlentities($c['label']) ?></td>
                        <td><?= intval($c['cose_alg']) === -7 ? 'ES256' : (intval($c['cose_alg']) === -257 ? 'RS256' : '?') ?></td>
                        <td><?= nullable_htmlentities($c['created_at']) ?></td>
                        <td><?= nullable_htmlentities($c['last_used_at'] ?? '-') ?></td>
                        <td>
                            <form action="post.php" method="post" class="d-inline" onsubmit="return confirm('Remove this security key?');">
                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                <input type="hidden" name="cred_id" value="<?= intval($c['cred_id']) ?>">
                                <button type="submit" name="delete_webauthn_credential" class="btn btn-sm btn-outline-danger">
                                    <i class="fa fa-trash"></i>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <hr>
        <h5>Register a new security key</h5>
        <div class="form-group">
            <label>Label</label>
            <input type="text" id="webauthn_label" class="form-control" maxlength="100" placeholder="e.g. YubiKey blue, Touch ID Macbook">
        </div>
        <button type="button" id="webauthn_register_btn" class="btn btn-primary">
            <i class="fa fa-plus mr-2"></i>Register security key
        </button>
        <div id="webauthn_register_status" class="mt-2 small"></div>
    </div>
</div>

<script>
(function () {
    function b64uToBytes(b64u) {
        const pad = '='.repeat((4 - b64u.length % 4) % 4);
        const b64 = (b64u + pad).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(b64);
        const out = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }
    function bytesToB64u(buf) {
        const b = new Uint8Array(buf);
        let s = '';
        for (const c of b) s += String.fromCharCode(c);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    document.getElementById('webauthn_register_btn').addEventListener('click', async function () {
        const status = document.getElementById('webauthn_register_status');
        status.textContent = 'Requesting registration challenge…';
        try {
            const r = await fetch('webauthn_register_options.php', { credentials: 'same-origin' });
            if (!r.ok) throw new Error('options request failed: ' + r.status);
            const opts = await r.json();
            opts.challenge = b64uToBytes(opts.challenge);
            opts.user.id = b64uToBytes(opts.user.id);
            (opts.excludeCredentials || []).forEach(c => c.id = b64uToBytes(c.id));

            status.textContent = 'Waiting for your security key…';
            const cred = await navigator.credentials.create({ publicKey: opts });

            const payload = {
                id: cred.id,
                rawId: bytesToB64u(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON:    bytesToB64u(cred.response.clientDataJSON),
                    attestationObject: bytesToB64u(cred.response.attestationObject),
                },
            };

            const fd = new FormData();
            fd.append('csrf_token', '<?= $_SESSION['csrf_token'] ?>');
            fd.append('credential', JSON.stringify(payload));
            fd.append('label', document.getElementById('webauthn_label').value || '');
            const verify = await fetch('webauthn_register_verify.php', { method: 'POST', body: fd, credentials: 'same-origin' });
            const result = await verify.json();
            if (!verify.ok || result.error) {
                status.innerHTML = '<span class="text-danger">Failed: ' + (result.error || 'unknown error') + '</span>';
                return;
            }
            status.innerHTML = '<span class="text-success">Security key registered. Reload to see it in the list.</span>';
            setTimeout(() => location.reload(), 1500);
        } catch (e) {
            status.innerHTML = '<span class="text-danger">' + (e.message || e) + '</span>';
        }
    });
})();
</script>

<div class="card card-dark">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-fw fa-key mr-2"></i>Vault unlock methods</h3>
    </div>
    <div class="card-body">
        <p class="small text-muted">
            Vault unlock methods let you decrypt stored credentials when you sign in via SSO instead of with a password.
            Use a vault PIN distinct from any account password.
        </p>

        <?php if (empty($vault_methods)): ?>
            <p class="text-muted small">No unlock methods configured.</p>
        <?php else: ?>
            <table class="table table-sm">
                <thead><tr><th>Type</th><th>Label</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($vault_methods as $m): ?>
                    <tr>
                        <td><?= htmlentities($m['method_type']) ?></td>
                        <td><?= nullable_htmlentities($m['label']) ?></td>
                        <td><?= nullable_htmlentities($m['created_at']) ?></td>
                        <td><?= nullable_htmlentities($m['last_used_at'] ?? '-') ?></td>
                        <td>
                            <?php if (!empty($m['locked_until']) && strtotime($m['locked_until']) > time()): ?>
                                <span class="badge badge-warning">Locked until <?= htmlentities($m['locked_until']) ?></span>
                            <?php elseif (intval($m['failed_attempts']) > 0): ?>
                                <span class="badge badge-secondary"><?= intval($m['failed_attempts']) ?> failed</span>
                            <?php else: ?>
                                <span class="badge badge-success">OK</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <form action="post.php" method="post" class="d-inline" onsubmit="return confirm('Remove this unlock method?');">
                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                <input type="hidden" name="vault_method_id" value="<?= intval($m['method_id']) ?>">
                                <button type="submit" name="delete_vault_method" class="btn btn-sm btn-outline-danger">
                                    <i class="fa fa-trash"></i>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <hr>
        <h5>Set or update vault PIN</h5>

        <?php if (!$vault_master_key_present): ?>
            <div class="alert alert-warning small">
                Your vault is currently locked. Sign in with your account password (not SSO) to set or update a vault PIN.
            </div>
        <?php else: ?>
            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

                <div class="form-group">
                    <label>New PIN <small class="text-muted">(minimum <?= VAULT_PIN_MIN_LENGTH ?> characters)</small></label>
                    <input type="password" class="form-control" name="vault_pin" autocomplete="new-password"
                           minlength="<?= VAULT_PIN_MIN_LENGTH ?>" required>
                </div>

                <div class="form-group">
                    <label>Confirm new PIN</label>
                    <input type="password" class="form-control" name="vault_pin_confirm" autocomplete="new-password"
                           minlength="<?= VAULT_PIN_MIN_LENGTH ?>" required>
                </div>

                <div class="form-group">
                    <label>Label <small class="text-muted">(optional, for your reference)</small></label>
                    <input type="text" class="form-control" name="vault_pin_label" maxlength="100"
                           placeholder="e.g. work laptop">
                </div>

                <button type="submit" name="set_vault_pin" class="btn btn-primary">
                    <i class="fa fa-check mr-2"></i>Save PIN
                </button>
            </form>
        <?php endif; ?>

    </div>
</div>

<?php if ($remember_token_count > 0) { ?>
    <div class="card card-dark">
        <div class="card-header py-3">
            <h3 class="card-title"><i class="fas fa-fw fa-clock mr-2"></i>2FA Remember-Me Tokens</h3>
        </div>
        <div class="card-body">

            <ul>
                <?php while ($row = mysqli_fetch_assoc($sql_remember_tokens)) {
                    $token_id = intval($row['remember_token_id']);
                    $token_created = nullable_htmlentities($row['remember_token_created_at']);

                    echo "<li>ID: $token_id | Created: $token_created</li>";
                } ?>
            </ul>

            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

                <button type="submit" name="revoke_your_2fa_remember_tokens" class="btn btn-danger btn-block mt-3"><i class="fas fa-exclamation-triangle mr-2"></i>Revoke Remember-Me Tokens</button>

            </form>

        </div>
    </div>
<?php } ?>

<?php

// Show the error alert if it exists:
if (!empty($_SESSION['alert_type']) && $_SESSION['alert_type'] == 'error') {
    echo "<div class='alert alert-danger'>{$_SESSION['alert_message']}</div>";
    // Clear it so it doesn't persist on refresh
    unset($_SESSION['alert_type']);
    unset($_SESSION['alert_message']);
}

// If the user just failed a TOTP verification, auto-open the modal:
if (!empty($_SESSION['show_mfa_modal'])) {
    echo "
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // jQuery or vanilla JS to open the modal
            $('#enableMFAModal').modal('show');
        });
    </script>";
    unset($_SESSION['show_mfa_modal']);
}

require_once "../../includes/footer.php";
