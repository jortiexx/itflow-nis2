<?php
require_once "includes/inc_all_admin.php";

?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-shield-alt mr-2"></i>Security</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <label>Login Message</label>
                <textarea class="form-control" name="config_login_message" rows="5" placeholder="Enter a message to be displayed on the login screen"><?php echo nullable_htmlentities($config_login_message); ?></textarea>
            </div>

            <div class="form-group">
                <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" name="config_login_key_required" <?php if ($config_login_key_required == 1) { echo "checked"; } ?> value="1" id="customSwitch1">
                    <label class="custom-control-label" for="customSwitch1">Require a login key to access the technician login page?</label>
                </div>
            </div>

            <div class="form-group">
                <label>Login key secret value <small class="text-secondary">(This must be provided in the URL as /login.php?key=<?php echo nullable_htmlentities($config_login_key_secret)?>)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="text" class="form-control" name="config_login_key_secret" pattern="\w{3,99}" placeholder="Something really easy for techs to remember: e.g. MYSECRET" value="<?php echo nullable_htmlentities($config_login_key_secret); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>2FA Remember Me Expire <small class="text-secondary">(The amount of days before a device 2FA remember me token will expire)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-clock"></i></span>
                    </div>
                    <input type="number" class="form-control" name="config_login_remember_me_expire" placeholder="Enter Days to Expire" value="<?php echo intval($config_login_remember_me_expire); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>Log retention <small class="text-secondary">(The amount of days before app/audit/auth logs are deleted during nightly cron)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-clock"></i></span>
                    </div>
                    <input type="number" class="form-control" name="config_log_retention" placeholder="Enter days to retain" value="<?php echo intval($config_log_retention); ?>">
                </div>
            </div>

            <hr>

            <h5 class="mb-2"><i class="fa fa-fw fa-tachometer-alt mr-2 text-info"></i>Rate limiting</h5>
            <p class="text-secondary small">
                Per-IP throttles applied at sensitive entry points. Each scope blocks further attempts (HTTP 429) once the failure count for that source IP exceeds the threshold within the time window. Failures keep counting until they age out; the counter is the same one that drives the existing security audit.
            </p>

            <div class="form-group">
                <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" name="config_ratelimit_enabled" <?php if ($config_ratelimit_enabled == 1) { echo "checked"; } ?> value="1" id="rlEnable">
                    <label class="custom-control-label" for="rlEnable">Enable rate limiting (recommended)</label>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label>Login attempts (max in window)</label>
                        <div class="input-group">
                            <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-sign-in-alt"></i></span></div>
                            <input type="number" min="1" class="form-control" name="config_ratelimit_login_max" value="<?= intval($config_ratelimit_login_max) ?>">
                            <div class="input-group-append"><span class="input-group-text">in</span></div>
                            <input type="number" min="60" class="form-control" name="config_ratelimit_login_window" value="<?= intval($config_ratelimit_login_window) ?>">
                            <div class="input-group-append"><span class="input-group-text">s</span></div>
                        </div>
                        <small class="text-secondary">Default 10 / 600 s. Applies to the password login form (per source IP).</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label>Vault unlock attempts</label>
                        <div class="input-group">
                            <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-lock"></i></span></div>
                            <input type="number" min="1" class="form-control" name="config_ratelimit_vault_max" value="<?= intval($config_ratelimit_vault_max) ?>">
                            <div class="input-group-append"><span class="input-group-text">in</span></div>
                            <input type="number" min="60" class="form-control" name="config_ratelimit_vault_window" value="<?= intval($config_ratelimit_vault_window) ?>">
                            <div class="input-group-append"><span class="input-group-text">s</span></div>
                        </div>
                        <small class="text-secondary">Default 20 / 600 s. PIN + WebAuthn-PRF unlock attempts.</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label>SSO callback failures</label>
                        <div class="input-group">
                            <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-id-badge"></i></span></div>
                            <input type="number" min="1" class="form-control" name="config_ratelimit_sso_max" value="<?= intval($config_ratelimit_sso_max) ?>">
                            <div class="input-group-append"><span class="input-group-text">in</span></div>
                            <input type="number" min="60" class="form-control" name="config_ratelimit_sso_window" value="<?= intval($config_ratelimit_sso_window) ?>">
                            <div class="input-group-append"><span class="input-group-text">s</span></div>
                        </div>
                        <small class="text-secondary">Default 20 / 600 s. Entra ID / OIDC callback failures.</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label>API authentication failures</label>
                        <div class="input-group">
                            <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-key"></i></span></div>
                            <input type="number" min="1" class="form-control" name="config_ratelimit_api_max" value="<?= intval($config_ratelimit_api_max) ?>">
                            <div class="input-group-append"><span class="input-group-text">in</span></div>
                            <input type="number" min="60" class="form-control" name="config_ratelimit_api_window" value="<?= intval($config_ratelimit_api_window) ?>">
                            <div class="input-group-append"><span class="input-group-text">s</span></div>
                        </div>
                        <small class="text-secondary">Default 30 / 600 s. Wrong / expired API key submissions.</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label>Password reset email requests</label>
                        <div class="input-group">
                            <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-envelope"></i></span></div>
                            <input type="number" min="1" class="form-control" name="config_ratelimit_pwreset_max" value="<?= intval($config_ratelimit_pwreset_max) ?>">
                            <div class="input-group-append"><span class="input-group-text">in</span></div>
                            <input type="number" min="60" class="form-control" name="config_ratelimit_pwreset_window" value="<?= intval($config_ratelimit_pwreset_window) ?>">
                            <div class="input-group-append"><span class="input-group-text">s</span></div>
                        </div>
                        <small class="text-secondary">Default 5 / 3600 s. Stops password-reset email bombing.</small>
                    </div>
                </div>
            </div>

            <hr>

            <button type="submit" name="edit_security_settings" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Save</button>

        </form>
    </div>
</div>

<?php
require_once "../includes/footer.php";

