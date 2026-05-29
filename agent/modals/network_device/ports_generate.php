<?php
require_once '../../../includes/modal_header.php';

$client_id = intval($_GET['client_id'] ?? 0);
$preselect_asset_id = intval($_GET['asset_id'] ?? 0);

$existing_count = 0;
if ($preselect_asset_id > 0) {
    $row = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT COUNT(*) AS n FROM asset_ports WHERE port_device_asset_id = $preselect_asset_id AND port_archived_at IS NULL"));
    $existing_count = $row ? intval($row['n']) : 0;
}

ob_start();
?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-plus mr-2"></i>Add / regenerate ports</h5>
    <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

    <div class="modal-body">

        <?php if ($client_id) { ?>
            <input type="hidden" name="client_id" value="<?= $client_id ?>">
        <?php } else { ?>
            <div class="form-group">
                <label>Client <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-user"></i></span></div>
                    <select class="form-control select2" name="client_id" required>
                        <option value="">- Select Client -</option>
                        <?php
                        $sql = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL $access_permission_query ORDER BY client_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            echo "<option value='" . intval($row['client_id']) . "'>" . nullable_htmlentities($row['client_name']) . "</option>";
                        }
                        ?>
                    </select>
                </div>
                <small class="form-text text-muted">Switch the modal to pre-select an asset by reopening from a client's page.</small>
            </div>
        <?php } ?>

        <div class="form-group">
            <label>Asset <strong class="text-danger">*</strong></label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-ethernet"></i></span></div>
                <select class="form-control select2" name="asset_id" required <?= $client_id ? '' : 'disabled' ?>>
                    <option value="">- Select asset -</option>
                    <?php if ($client_id) {
                        $sql = mysqli_query($mysqli, "SELECT asset_id, asset_name, asset_type, asset_make, asset_model FROM assets WHERE asset_client_id = $client_id AND asset_archived_at IS NULL ORDER BY asset_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $aid = intval($row['asset_id']);
                            $alabel = nullable_htmlentities($row['asset_name'] . ' (' . $row['asset_type'] . ($row['asset_make'] ? ' — ' . $row['asset_make'] . ' ' . $row['asset_model'] : '') . ')');
                            $sel = $aid === $preselect_asset_id ? 'selected' : '';
                            echo "<option $sel value='$aid'>$alabel</option>";
                        }
                    } ?>
                </select>
            </div>
            <small class="form-text text-muted">Any asset can have ports added. Typically you'll pick a Switch, Firewall/Router, Access Point, or a Patch Panel asset.</small>
        </div>

        <?php if ($existing_count > 0) { ?>
            <div class="alert alert-warning small">
                <i class="fa fa-fw fa-exclamation-triangle mr-1"></i>
                This asset already has <strong><?= $existing_count ?></strong> port(s). New port rows will be numbered starting at <strong><?= $existing_count + 1 ?></strong>; existing rows are not touched.
            </div>
        <?php } ?>

        <div class="form-group">
            <label>Port count to add <strong class="text-danger">*</strong></label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-hashtag"></i></span></div>
                <input type="number" min="1" max="512" class="form-control" name="port_count" required value="24" autofocus>
            </div>
            <small class="form-text text-muted">Common counts: 8, 16, 24, 48. The generated rows are empty placeholders — click cells in the faceplate to fill them in.</small>
        </div>

        <div class="form-group">
            <label>PoE budget (W, optional)</label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-bolt"></i></span></div>
                <input type="number" min="0" max="10000" class="form-control" name="asset_poe_budget_watts" placeholder="e.g. 740">
            </div>
            <small class="form-text text-muted">Saved on the asset; only relevant for PoE-capable switches. Leaving blank keeps the existing value.</small>
        </div>

    </div>
    <div class="modal-footer">
        <button type="submit" name="generate_asset_ports" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Generate ports</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>
<?php require_once '../../../includes/modal_footer.php'; ?>
