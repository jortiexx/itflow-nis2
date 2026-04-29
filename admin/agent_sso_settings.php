<?php
require_once "includes/inc_all_admin.php";

$row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT config_agent_sso_enabled,
            config_agent_sso_tenant_id,
            config_agent_sso_client_id,
            config_agent_sso_client_secret,
            config_agent_sso_redirect_uri,
            config_agent_sso_jit_provisioning,
            config_agent_sso_default_role_id
     FROM settings
     WHERE company_id = 1
     LIMIT 1"
));

$enabled          = !empty($row['config_agent_sso_enabled']);
$tenant_id        = $row['config_agent_sso_tenant_id'] ?? '';
$sso_client_id    = $row['config_agent_sso_client_id'] ?? '';
$sso_client_secret = $row['config_agent_sso_client_secret'] ?? '';
$redirect_uri     = $row['config_agent_sso_redirect_uri'] ?? '';
$jit              = !empty($row['config_agent_sso_jit_provisioning']);
$default_role_id  = intval($row['config_agent_sso_default_role_id'] ?? 0);

$base = ($config_https_only ? 'https://' : 'http://') . $config_base_url;
$auto_redirect_uri = "$base/agent/login_entra_callback.php";

$roles = mysqli_query($mysqli, "SELECT role_id, role_name FROM user_roles WHERE role_archived_at IS NULL ORDER BY role_name ASC");

?>
<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-id-badge mr-2"></i>Agent SSO (Microsoft Entra ID)</h3>
    </div>
    <div class="card-body">

        <div class="alert alert-info small">
            <strong>Setup:</strong> register a new application in your Entra ID tenant
            (App registrations → New registration). Set the redirect URI (Web platform) to:
            <code><?= htmlentities($auto_redirect_uri) ?></code>.
            Add a client secret under <em>Certificates &amp; secrets</em>. No API permissions are required
            beyond the default <code>User.Read</code>; sign-in uses the OIDC <code>id_token</code> directly.
            For tenant-side access control, use Enterprise Applications → Users and groups
            and require user assignment.
        </div>

        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <label>Status</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-toggle-on"></i></span>
                    </div>
                    <select class="form-control" name="agent_sso_enabled">
                        <option value="0" <?= $enabled ? '' : 'selected' ?>>Disabled</option>
                        <option value="1" <?= $enabled ? 'selected' : '' ?>>Enabled</option>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Entra Directory (Tenant) ID</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-building"></i></span>
                    </div>
                    <input type="text" class="form-control" name="agent_sso_tenant_id"
                           placeholder="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                           value="<?= nullable_htmlentities($tenant_id) ?>">
                </div>
                <small class="form-text text-muted">
                    The GUID of your Entra tenant (App registrations → Directory (tenant) ID).
                </small>
            </div>

            <div class="form-group">
                <label>Application (Client) ID</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                    </div>
                    <input type="text" class="form-control" name="agent_sso_client_id"
                           placeholder="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                           value="<?= nullable_htmlentities($sso_client_id) ?>">
                </div>
            </div>

            <div class="form-group">
                <label>Client Secret</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="agent_sso_client_secret"
                           placeholder="<?= $sso_client_secret ? '(unchanged)' : 'Auto-generated from App Registration' ?>"
                           autocomplete="new-password">
                </div>
                <small class="form-text text-muted">
                    Leave blank to keep the existing secret. The secret is stored in the database;
                    treat it with the same care as your database credentials.
                </small>
            </div>

            <div class="form-group">
                <label>Redirect URI</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-link"></i></span>
                    </div>
                    <input type="text" class="form-control" name="agent_sso_redirect_uri"
                           value="<?= nullable_htmlentities($redirect_uri ?: $auto_redirect_uri) ?>">
                </div>
                <small class="form-text text-muted">
                    Must match the redirect URI configured in the Entra app registration exactly.
                    Default: <code><?= htmlentities($auto_redirect_uri) ?></code>
                </small>
            </div>

            <hr>
            <h5>Just-in-time (JIT) provisioning</h5>

            <div class="form-group">
                <label>JIT provisioning</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-magic"></i></span>
                    </div>
                    <select class="form-control" name="agent_sso_jit_provisioning">
                        <option value="0" <?= $jit ? '' : 'selected' ?>>Disabled (only pre-existing accounts can sign in)</option>
                        <option value="1" <?= $jit ? 'selected' : '' ?>>Enabled (auto-create agents on first sign-in)</option>
                    </select>
                </div>
                <small class="form-text text-muted">
                    When enabled, agents who sign in via Entra without a pre-existing account are created
                    automatically with the default role below. Only enable if you trust your tenant-side
                    user assignment.
                </small>
            </div>

            <div class="form-group">
                <label>Default role for JIT-provisioned agents</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-user-tag"></i></span>
                    </div>
                    <select class="form-control" name="agent_sso_default_role_id">
                        <option value="0">- Select role -</option>
                        <?php while ($r = mysqli_fetch_assoc($roles)) { ?>
                            <option value="<?= intval($r['role_id']) ?>" <?= ($default_role_id === intval($r['role_id'])) ? 'selected' : '' ?>>
                                <?= nullable_htmlentities($r['role_name']) ?>
                            </option>
                        <?php } ?>
                    </select>
                </div>
            </div>

            <hr>

            <button type="submit" name="edit_agent_sso_settings" class="btn btn-primary text-bold">
                <i class="fa fa-check mr-2"></i>Save
            </button>

        </form>

        <hr>
        <h5>Agent sign-in URL</h5>
        <p>Direct sign-in: <code><?= htmlentities($base) ?>/agent/login_entra.php</code></p>
        <p>The <em>Sign in with Microsoft</em> button on the main login page will appear automatically once SSO is enabled.</p>
    </div>
</div>

<?php require_once "../includes/footer.php";
