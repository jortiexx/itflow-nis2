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

        <div class="alert alert-info">
            <div class="d-flex justify-content-between align-items-start">
                <div class="small">
                    <strong>Setup:</strong> register a new application in your Entra ID tenant.
                    The Setup helper has a copy-paste PowerShell snippet that does this for you, or
                    walk through the portal manually. Redirect URI for this install:
                    <code id="ssoRedirectUri"><?= htmlentities($auto_redirect_uri) ?></code>
                    <button type="button" class="btn btn-sm btn-outline-secondary py-0 ml-2"
                            onclick="navigator.clipboard.writeText(document.getElementById('ssoRedirectUri').textContent); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy',1500)">Copy</button>
                </div>
                <button type="button" class="btn btn-info btn-sm ml-3 flex-shrink-0"
                        data-toggle="modal" data-target="#ssoSetupHelper">
                    <i class="fa fa-fw fa-magic mr-1"></i>Setup helper
                </button>
            </div>
        </div>

<?php
// PowerShell snippet, redirect URI baked in for this install.
$_ps_redirect = $redirect_uri ?: $auto_redirect_uri;
$_ps_snippet = <<<PS
# 1) Sign in as an Entra admin (device-code flow opens a browser tab)
az login --use-device-code --allow-no-subscriptions

# 2) Capture tenant id from the active session
\$tenant_id = (az account show --query tenantId -o tsv)

# 3) Create the app + a 24-month client secret. Redirect URI is hard-coded
#    for this ITFlow install.
\$redirect = "{$_ps_redirect}"
\$app = az ad app create `
    --display-name "ITFlow Agent SSO" `
    --sign-in-audience AzureADMyOrg `
    --web-redirect-uris \$redirect `
    --enable-id-token-issuance true `
    --output json --only-show-errors | ConvertFrom-Json
\$client_id     = \$app.appId
\$app_object_id = \$app.id

\$end_date = (Get-Date).AddMonths(24).ToString("yyyy-MM-ddTHH:mm:ssZ")
\$secret = az ad app credential reset `
    --id \$app_object_id `
    --display-name "itflow-sso" `
    --end-date \$end_date `
    --output json --only-show-errors | ConvertFrom-Json

# 4) Print the values to paste back into the form below
Write-Host "Tenant ID:     \$tenant_id"        -ForegroundColor Green
Write-Host "Client ID:     \$client_id"        -ForegroundColor Green
Write-Host "Client Secret: \$(\$secret.password)" -ForegroundColor Yellow
Write-Host ""
Write-Host "(The secret is shown once. Paste these three values into Admin -> Agent SSO settings.)"
PS;
?>

<!-- Setup helper modal -->
<div class="modal fade" id="ssoSetupHelper" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header bg-info">
                <h5 class="modal-title text-white"><i class="fa fa-fw fa-magic mr-2"></i>Entra app registration helper</h5>
                <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
            </div>
            <div class="modal-body">
                <p class="text-secondary">
                    Two paths — pick whichever feels less painful. Both end with three values
                    (Tenant ID, Client ID, Client Secret) that you paste into the form on this page.
                </p>

                <ul class="nav nav-tabs" role="tablist">
                    <li class="nav-item">
                        <a class="nav-link active" data-toggle="tab" href="#ssoHelperPS" role="tab">
                            <i class="fa fa-fw fa-terminal mr-1"></i>PowerShell (recommended)
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-toggle="tab" href="#ssoHelperPortal" role="tab">
                            <i class="fa fa-fw fa-globe mr-1"></i>Azure portal
                        </a>
                    </li>
                </ul>

                <div class="tab-content border border-top-0 p-3">

                    <div class="tab-pane fade show active" id="ssoHelperPS" role="tabpanel">
                        <p class="small text-secondary">
                            Run this on any machine with <a href="https://learn.microsoft.com/cli/azure/install-azure-cli-windows" target="_blank">Azure CLI</a> installed.
                            Sign-in is via device-code flow, so you log in as Entra admin in your normal browser session.
                            The script creates the app, generates a 24-month secret, and prints the three values.
                        </p>
                        <div class="position-relative">
                            <button type="button" class="btn btn-sm btn-outline-secondary position-absolute" style="top:8px; right:8px;"
                                    onclick="const t=document.getElementById('ssoPsSnippet').textContent; navigator.clipboard.writeText(t); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy',1500)">Copy</button>
                            <pre style="background:#1e1e1e; color:#dcdcdc; padding:1rem; border-radius:4px; max-height:380px; overflow:auto;"><code id="ssoPsSnippet"><?= htmlspecialchars($_ps_snippet) ?></code></pre>
                        </div>
                        <p class="small text-secondary mb-0">
                            Don't have Azure CLI? <code>winget install -e --id Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements</code>.
                        </p>
                    </div>

                    <div class="tab-pane fade" id="ssoHelperPortal" role="tabpanel">
                        <p class="small text-secondary">Walk through the Azure portal manually. ~6 clicks.</p>
                        <ol class="small">
                            <li>
                                <a href="https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank">
                                    Open <strong>App registrations</strong> in Entra <i class="fa fa-fw fa-external-link-alt"></i>
                                </a>
                                → click <strong>+ New registration</strong>.
                            </li>
                            <li>Name: <code>ITFlow Agent SSO</code>. Supported account types: <strong>Accounts in this organizational directory only</strong>.</li>
                            <li>
                                Redirect URI — Platform: <strong>Web</strong>; URI:
                                <code><?= htmlentities($_ps_redirect) ?></code>
                                <button type="button" class="btn btn-sm btn-outline-secondary py-0 ml-1"
                                        onclick="navigator.clipboard.writeText('<?= htmlentities($_ps_redirect, ENT_QUOTES) ?>'); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy',1500)">Copy</button>
                            </li>
                            <li>Click <strong>Register</strong>. Copy <em>Directory (tenant) ID</em> + <em>Application (client) ID</em> from the Overview page → paste into the form below.</li>
                            <li>Left nav → <strong>Certificates &amp; secrets</strong> → <strong>+ New client secret</strong>. Description: <code>itflow-sso</code>; expiry: 24 months. Copy the <strong>Value</strong> (the secret, NOT the secret ID) → paste below.</li>
                            <li>Left nav → <strong>Authentication</strong> → under "Implicit grant and hybrid flows" tick <strong>ID tokens (used for implicit and hybrid flows)</strong> → Save.</li>
                            <li>(Recommended) <a href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview" target="_blank">Enterprise applications <i class="fa fa-fw fa-external-link-alt"></i></a> → ITFlow Agent SSO → <strong>Properties</strong> → <em>Assignment required?</em> = Yes; then <strong>Users and groups</strong> → assign the agents who should be able to sign in.</li>
                        </ol>
                    </div>

                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
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
