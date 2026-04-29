<?php
/*
 * Phase 15: legacy file encryption — first-login migration UI.
 *
 * Renders a Bootstrap progress bar + status line. The actual encryption
 * work is done one batch at a time via AJAX polls to
 * /agent/migrate_legacy_files_step.php.
 *
 * The redirect into this page is triggered by includes/load_user_session.php
 * whenever the user lands on any agent page AND there are still plaintext
 * files this user can encrypt AND the vault is unlocked.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/check_login.php';
require_once __DIR__ . '/../includes/legacy_file_sweeper.php';

$total_pending = legacyFilesPendingForUser($mysqli, $session_user_id, $session_is_admin);

// Branding for the page chrome (login/vault style).
$brand_row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT companies.company_name, companies.company_logo
    FROM settings
    LEFT JOIN companies ON settings.company_id = companies.company_id
    WHERE settings.company_id = 1
    LIMIT 1
"));
$company_name = $brand_row['company_name'] ?? 'ITFlow';
$company_logo = $brand_row['company_logo'] ?? '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Migrating legacy files — <?= nullable_htmlentities($company_name) ?></title>
    <?php if (file_exists($_SERVER['DOCUMENT_ROOT'] . '/uploads/favicon.ico')) { ?>
        <link rel="icon" type="image/x-icon" href="/uploads/favicon.ico">
    <?php } ?>
    <link rel="stylesheet" href="/plugins/fontawesome-free/css/all.min.css">
    <link rel="stylesheet" href="/plugins/adminlte/css/adminlte.min.css">
    <style>
        body { background: #f4f6f9; }
        .migrate-card { max-width: 640px; margin: 8vh auto; }
    </style>
</head>
<body>
<div class="container">
    <div class="card migrate-card shadow">
        <div class="card-body p-4">
            <?php if (!empty($company_logo) && file_exists($_SERVER['DOCUMENT_ROOT'] . "/uploads/settings/$company_logo")) { ?>
                <div class="text-center mb-3">
                    <img alt="<?= nullable_htmlentities($company_name) ?> logo" height="60" class="img-fluid" src="/uploads/settings/<?= htmlentities($company_logo) ?>">
                </div>
            <?php } ?>

            <h4 class="mb-3"><i class="fa fa-fw fa-shield-alt mr-2 text-info"></i>Encrypting legacy files</h4>

            <?php if ($total_pending === 0) { ?>
                <div class="alert alert-success">
                    <i class="fa fa-check mr-2"></i> Nothing to do. Redirecting…
                </div>
                <script>setTimeout(function(){ location.href = '/'; }, 800);</script>
            <?php } else { ?>
                <p class="text-secondary">
                    A one-time sweep is encrypting <strong id="totalCount"><?= $total_pending ?></strong>
                    file(s) that were uploaded before file at-rest encryption was enabled.
                    This runs once per upgrade. <strong>Please leave this tab open until it completes.</strong>
                </p>
                <p class="text-secondary small">
                    Each file is read, AES-256-GCM encrypted with the per-client master key, and written
                    back to disk. The page polls progress automatically — no action needed.
                </p>

                <div class="progress mb-3" style="height: 28px;">
                    <div id="progress" class="progress-bar progress-bar-striped progress-bar-animated bg-info"
                         role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                </div>

                <div class="d-flex justify-content-between">
                    <span id="status" class="text-secondary">Starting…</span>
                    <span id="batch" class="text-secondary small"></span>
                </div>

                <div id="errorBox" class="alert alert-warning mt-3 d-none">
                    <strong>Heads up:</strong> <span id="errorMsg"></span>
                </div>

                <hr>
                <details class="text-secondary small">
                    <summary>Why does this happen now?</summary>
                    <p class="mt-2">
                        Phase 13 of the security hardening encrypts every <em>new</em> file upload with the
                        per-client master key. Files that existed on disk before that change stayed
                        plaintext. The sweep can only run once a vault is unlocked — which is now —
                        so the upgrade defers it to your first login. After this completes, you'll
                        never see this screen again unless new clients with legacy files are added.
                    </p>
                </details>
            <?php } ?>
        </div>
    </div>
</div>

<?php if ($total_pending > 0) { ?>
<script>
(function() {
    const total = <?= intval($total_pending) ?>;
    const csrf  = "<?= $_SESSION['csrf_token'] ?>";
    const progressBar = document.getElementById('progress');
    const statusEl    = document.getElementById('status');
    const batchEl     = document.getElementById('batch');
    const errorBox    = document.getElementById('errorBox');
    const errorMsg    = document.getElementById('errorMsg');
    let batchNumber = 0;
    let consecutiveNoProgress = 0;

    async function step() {
        batchNumber++;
        try {
            const fd = new FormData();
            fd.append('csrf_token', csrf);
            const r = await fetch('/agent/migrate_legacy_files_step.php', {
                method: 'POST',
                body: fd,
                credentials: 'same-origin',
            });
            if (!r.ok) {
                throw new Error('HTTP ' + r.status);
            }
            const data = await r.json();

            if (data.reason === 'no_master_key') {
                statusEl.textContent = 'Vault is locked. Redirecting to unlock…';
                setTimeout(() => { location.href = '/agent/vault_unlock.php'; }, 1500);
                return;
            }

            const remaining = Math.max(0, parseInt(data.remaining || 0));
            const processed = Math.max(0, total - remaining);
            const pct = total > 0 ? Math.round((processed / total) * 100) : 100;
            progressBar.style.width = pct + '%';
            progressBar.setAttribute('aria-valuenow', pct);
            progressBar.textContent = pct + '%';
            statusEl.textContent = processed + ' / ' + total + ' encrypted';
            batchEl.textContent  = 'batch ' + batchNumber + ' · +' + (data.encrypted_this_batch || 0) +
                                   (data.failed_this_batch ? ' (' + data.failed_this_batch + ' failed)' : '');

            if (data.failed_this_batch && data.failed_this_batch > 0) {
                errorBox.classList.remove('d-none');
                errorMsg.textContent = data.failed_this_batch + ' file(s) could not be encrypted in this batch — see security_audit_log for details. Continuing…';
            }

            if (remaining === 0 || data.reason === 'nothing_to_do') {
                progressBar.classList.remove('progress-bar-animated');
                progressBar.classList.remove('bg-info');
                progressBar.classList.add('bg-success');
                statusEl.textContent = 'Done! Redirecting…';
                batchEl.textContent  = '';
                setTimeout(() => { location.href = '/'; }, 1200);
                return;
            }

            // Stuck-detection: if 5 consecutive batches make no progress
            // and no new failures, stop polling and tell the user.
            if ((data.encrypted_this_batch || 0) === 0 && (data.failed_this_batch || 0) === 0) {
                consecutiveNoProgress++;
                if (consecutiveNoProgress >= 5) {
                    errorBox.classList.remove('d-none');
                    errorMsg.textContent = 'No progress for 5 batches. Try refreshing this page; if it persists, run scripts/encrypt_legacy_files.php from the CLI.';
                    return;
                }
            } else {
                consecutiveNoProgress = 0;
            }

            setTimeout(step, 50);
        } catch (e) {
            errorBox.classList.remove('d-none');
            errorMsg.textContent = 'Error during batch: ' + e.message + '. Retrying in 3s…';
            setTimeout(step, 3000);
        }
    }
    step();
})();
</script>
<?php } ?>
</body>
</html>
