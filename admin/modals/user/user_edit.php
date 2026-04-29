<?php

require_once '../../../includes/modal_header.php';

$user_id = intval($_GET['id']);

$sql = mysqli_query($mysqli, "SELECT * FROM users
    LEFT JOIN user_settings ON users.user_id = user_settings.user_id
    WHERE users.user_id = $user_id LIMIT 1"
);

$row = mysqli_fetch_assoc($sql);
$user_name = nullable_htmlentities($row['user_name']);
$user_email = nullable_htmlentities($row['user_email']);
$user_avatar = nullable_htmlentities($row['user_avatar']);
$user_token = nullable_htmlentities($row['user_token']);
$user_config_force_mfa = intval($row['user_config_force_mfa']);
$user_force_webauthn   = intval($row['user_force_webauthn'] ?? 0);
$user_role_id = intval($row['user_role_id']);
$user_initials = nullable_htmlentities(initials($user_name));

// Get User Client Access Permissions
$user_client_access_sql = mysqli_query($mysqli,"SELECT client_id FROM user_client_permissions WHERE user_id = $user_id");
$client_access_array = [];
while ($row = mysqli_fetch_assoc($user_client_access_sql)) {
    $client_access_array[] = intval($row['client_id']);
}

// Generate the HTML form content using output buffering.
ob_start();
?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fas fa-fw fa-user-edit mr-2"></i>Editing user:
        <strong><?php echo $user_name; ?></strong></h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" enctype="multipart/form-data" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="user_id" value="<?php echo $user_id; ?>">
    <div class="modal-body">

        <ul class="nav nav-pills nav-justified mb-3">
            <li class="nav-item">
                <a class="nav-link active" data-toggle="pill" href="#pills-user-details<?php echo $user_id; ?>">Details</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-toggle="pill" href="#pills-user-access<?php echo $user_id; ?>">Restrict Access</a>
            </li>
        </ul>

        <hr>

        <div class="tab-content">

            <div class="tab-pane fade show active" id="pills-user-details<?php echo $user_id; ?>">

                <center class="mb-3">
                    <?php if (!empty($user_avatar)) { ?>
                        <img class="img-fluid" src="<?php echo "../uploads/users/$user_id/$user_avatar"; ?>">
                    <?php } else { ?>
                        <span class="fa-stack fa-4x">
                            <i class="fa fa-circle fa-stack-2x text-secondary"></i>
                            <span class="fa fa-stack-1x text-white"><?php echo $user_initials; ?></span>
                        </span>
                    <?php } ?>
                </center>

                <div class="form-group">
                    <label>Name <strong class="text-danger">*</strong></label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                        </div>
                        <input type="text" class="form-control" name="name" placeholder="Full Name" maxlength="200"
                               value="<?php echo $user_name; ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label>Email <strong class="text-danger">*</strong></label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-envelope"></i></span>
                        </div>
                        <input type="email" class="form-control" name="email" placeholder="Email Address" maxlength="200"
                               value="<?php echo $user_email; ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label>New Password</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-lock"></i></span>
                        </div>
                        <input type="password" class="form-control" data-toggle="password" name="new_password" id="password"
                               placeholder="Leave Blank For No Password Change" autocomplete="new-password">
                        <div class="input-group-append">
                            <span class="input-group-text"><i class="fa fa-fw fa-eye"></i></span>
                        </div>
                        <div class="input-group-append">
                            <span class="btn btn-default"><i class="fa fa-fw fa-question" onclick="generatePassword()"></i></span>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Role <strong class="text-danger">*</strong></label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-user-shield"></i></span>
                        </div>
                        <select class="form-control select2" name="role" required>
                            <?php
                            $sql_user_roles = mysqli_query($mysqli, "SELECT * FROM user_roles WHERE role_archived_at IS NULL");
                            while ($row = mysqli_fetch_assoc($sql_user_roles)) {
                                $role_id = intval($row['role_id']);
                                $role_name = nullable_htmlentities($row['role_name']);

                                ?>
                                <option <?php if ($role_id == $user_role_id) {echo "selected";} ?> value="<?php echo $role_id; ?>"><?php echo $role_name; ?></option>
                            <?php } ?>

                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label>Avatar</label>
                    <input type="file" class="form-control-file" accept="image/*" name="file">
                </div>

                <div class="form-group">
                    <div class="custom-control custom-checkbox">
                        <input class="custom-control-input" type="checkbox" id="forceMFACheckBox<?php echo $user_id; ?>" name="force_mfa" value="1" <?php if($user_config_force_mfa == 1){ echo "checked"; } ?>>
                        <label for="forceMFACheckBox<?php echo $user_id; ?>" class="custom-control-label">
                            Force MFA
                        </label>
                    </div>
                    <div class="custom-control custom-checkbox mt-2">
                        <input class="custom-control-input" type="checkbox" id="forceWebAuthnCheckBox<?php echo $user_id; ?>" name="force_webauthn" value="1" <?php if($user_force_webauthn == 1){ echo "checked"; } ?>>
                        <label for="forceWebAuthnCheckBox<?php echo $user_id; ?>" class="custom-control-label">
                            Require phishing-resistant MFA (WebAuthn only) <small class="text-muted">— rejects TOTP and remember-me bypass for this user</small>
                        </label>
                    </div>
                </div>

                <?php if (!empty($user_token)) { ?>

                    <div class="form-group">
                        <label>2FA</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-id-card"></i></span>
                            </div>
                            <select class="form-control" name="2fa">
                                <option value="">Keep enabled</option>
                                <option value="disable">Disable</option>
                            </select>
                        </div>
                    </div>

                <?php } ?>

                <hr>
                <div class="form-group">
                    <label>Vault enrolment</label>
                    <p class="small text-muted mb-2">
                        Issue a one-hour magic link for this user to set up their vault PIN or hardware unlock without needing a password. The link is emailed to the user (or shown to you for manual delivery if SMTP is not configured). Useful for SSO-only / JIT-provisioned agents.
                    </p>
                    <a href="post.php?send_vault_enrolment&user_id=<?= $user_id ?>&csrf_token=<?= urlencode($_SESSION['csrf_token']) ?>"
                       class="btn btn-outline-primary btn-sm confirm-link">
                        <i class="fa fa-envelope-open-text mr-2"></i>Send vault enrolment link
                    </a>
                </div>
            </div>

            <div class="tab-pane fade" id="pills-user-access<?php echo $user_id; ?>">

                <div class="alert alert-info small">
                    Check boxes to authorize user client access. No boxes grant full client access. Admin users are unaffected.
                </div>

                <?php
                // Phase 11+: scalable UI for many clients. Pull tags once so we can
                // emit data-tag-ids on each row for tag-filtered bulk actions.
                $tag_rs = mysqli_query($mysqli,
                    "SELECT tag_id, tag_name FROM tags WHERE tag_type = 1 AND tag_archived_at IS NULL ORDER BY tag_name ASC");
                $all_tags = [];
                while ($t = mysqli_fetch_assoc($tag_rs)) $all_tags[] = $t;

                // tag_id sets per client_id
                $client_tag_map = [];
                $ct_rs = mysqli_query($mysqli, "SELECT client_id, tag_id FROM client_tags");
                while ($r = mysqli_fetch_assoc($ct_rs)) {
                    $client_tag_map[intval($r['client_id'])][] = intval($r['tag_id']);
                }
                ?>

                <!-- Search + bulk action toolbar -->
                <div class="form-row align-items-center mb-2">
                    <div class="col-md-6 mb-2">
                        <div class="input-group input-group-sm">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-search"></i></span>
                            </div>
                            <input type="text" class="form-control client-access-search"
                                   placeholder="Filter clients..." autocomplete="off"
                                   data-target="#client-access-list-<?= $user_id ?>">
                        </div>
                    </div>
                    <div class="col-md-6 mb-2 text-right">
                        <small class="text-muted client-access-counter mr-2"
                               data-target="#client-access-list-<?= $user_id ?>">0 of 0 selected</small>
                        <div class="btn-group btn-group-sm" role="group">
                            <button type="button" class="btn btn-outline-secondary client-access-bulk"
                                    data-target="#client-access-list-<?= $user_id ?>"
                                    data-action="check-visible">Check visible</button>
                            <button type="button" class="btn btn-outline-secondary client-access-bulk"
                                    data-target="#client-access-list-<?= $user_id ?>"
                                    data-action="uncheck-visible">Uncheck visible</button>
                        </div>
                    </div>
                </div>

                <?php if (!empty($all_tags)): ?>
                <div class="form-row mb-2 align-items-center">
                    <label class="col-form-label col-form-label-sm mr-2 ml-1">By tag:</label>
                    <div class="col">
                        <?php foreach ($all_tags as $t): ?>
                            <button type="button" class="btn btn-outline-info btn-sm mb-1 client-access-by-tag"
                                    data-tag-id="<?= intval($t['tag_id']) ?>"
                                    data-target="#client-access-list-<?= $user_id ?>">
                                <?= nullable_htmlentities($t['tag_name']) ?>
                            </button>
                        <?php endforeach; ?>
                    </div>
                </div>
                <small class="form-text text-muted mb-2">
                    Click a tag once to select all clients with that tag. Click again to deselect them.
                </small>
                <?php endif; ?>

                <ul class="list-group" id="client-access-list-<?= $user_id ?>"
                    style="max-height: 50vh; overflow-y: auto;">
                    <li class="list-group-item bg-dark sticky-top">
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input client-access-check-all"
                                   data-target="#client-access-list-<?= $user_id ?>">
                            <label class="form-check-label ml-3">
                                <strong>Restrict Access to Clients</strong>
                                <small class="text-muted"> &mdash; check the toggle to select all (or filter first)</small>
                            </label>
                        </div>
                    </li>

                    <?php

                    $sql_client_select = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL ORDER BY client_name ASC");
                    while ($row = mysqli_fetch_assoc($sql_client_select)) {
                        $client_id_select = intval($row['client_id']);
                        $client_name_select = nullable_htmlentities($row['client_name']);
                        $tag_ids_for_client = $client_tag_map[$client_id_select] ?? [];
                        $tag_ids_attr = implode(',', $tag_ids_for_client);

                    ?>

                    <li class="list-group-item client-access-row" data-client-name="<?= htmlentities(strtolower($row['client_name'])) ?>" data-tag-ids="<?= $tag_ids_attr ?>">
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input client-checkbox" name="clients[]" value="<?php echo $client_id_select; ?>" <?php if (in_array($client_id_select, $client_access_array)) { echo "checked"; } ?>>
                            <label class="form-check-label ml-2"><?php echo $client_name_select; ?></label>
                        </div>
                    </li>

                    <?php } ?>

                </ul>

            </div>

        </div>

    </div>
    <div class="modal-footer">
        <button type="submit" name="edit_user" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Save</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fas fa-times mr-2"></i>Cancel</button>
    </div>
</form>

<script>

function generatePassword() {
    // Send a GET request to ajax.php as ajax.php?get_readable_pass=true
    jQuery.get(
        "/agent/ajax.php", {
            get_readable_pass: 'true'
        },
        function(data) {
            //If we get a response from post.php, parse it as JSON
            const password = JSON.parse(data);
            document.getElementById("password").value = password;
        }
    );
}

// Phase 11+: scalable client-access UI. Search filter, bulk toggle on
// visible rows, tag-based bulk select. All client-side; the form data
// structure (clients[] checkboxes) is unchanged so the existing POST
// handler keeps working.
(function () {
    function getList(target) {
        return document.querySelector(target);
    }
    function visibleRows(list) {
        return Array.from(list.querySelectorAll('.client-access-row'))
            .filter(function (row) { return row.style.display !== 'none'; });
    }
    function updateCounter(target) {
        var list = getList(target);
        if (!list) return;
        var all = list.querySelectorAll('.client-checkbox');
        var checked = list.querySelectorAll('.client-checkbox:checked');
        var counter = document.querySelector('.client-access-counter[data-target="' + target + '"]');
        if (counter) counter.textContent = checked.length + ' of ' + all.length + ' selected';
    }

    document.querySelectorAll('.client-access-search').forEach(function (input) {
        input.addEventListener('input', function () {
            var target = input.dataset.target;
            var list = getList(target);
            if (!list) return;
            var q = input.value.toLowerCase().trim();
            list.querySelectorAll('.client-access-row').forEach(function (row) {
                var name = row.dataset.clientName || '';
                row.style.display = (q === '' || name.indexOf(q) !== -1) ? '' : 'none';
            });
        });
    });

    document.querySelectorAll('.client-access-bulk').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var target = btn.dataset.target;
            var list = getList(target);
            if (!list) return;
            var checked = btn.dataset.action === 'check-visible';
            visibleRows(list).forEach(function (row) {
                var cb = row.querySelector('.client-checkbox');
                if (cb) cb.checked = checked;
            });
            updateCounter(target);
        });
    });

    document.querySelectorAll('.client-access-by-tag').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var target = btn.dataset.target;
            var list = getList(target);
            if (!list) return;
            var tag_id = btn.dataset.tagId;

            // Determine if we're checking or unchecking — based on whether
            // ALL matching clients are currently checked.
            var matches = Array.from(list.querySelectorAll('.client-access-row')).filter(function (row) {
                var ids = (row.dataset.tagIds || '').split(',').filter(function (x) { return x; });
                return ids.indexOf(tag_id) !== -1;
            });
            var allChecked = matches.length > 0 && matches.every(function (row) {
                var cb = row.querySelector('.client-checkbox');
                return cb && cb.checked;
            });
            matches.forEach(function (row) {
                var cb = row.querySelector('.client-checkbox');
                if (cb) cb.checked = !allChecked;
            });
            updateCounter(target);
        });
    });

    document.querySelectorAll('.client-access-check-all').forEach(function (master) {
        master.addEventListener('change', function () {
            var target = master.dataset.target;
            var list = getList(target);
            if (!list) return;
            // Apply only to visible rows so search + master-toggle compose.
            visibleRows(list).forEach(function (row) {
                var cb = row.querySelector('.client-checkbox');
                if (cb) cb.checked = master.checked;
            });
            updateCounter(target);
        });
    });

    document.querySelectorAll('.client-checkbox').forEach(function (cb) {
        cb.addEventListener('change', function () {
            var list = cb.closest('ul.list-group');
            if (list && list.id) updateCounter('#' + list.id);
        });
    });

    // Initialise counters on load.
    document.querySelectorAll('.client-access-counter').forEach(function (counter) {
        updateCounter(counter.dataset.target);
    });
})();

</script>

<?php
require_once "../../../includes/modal_footer.php";
