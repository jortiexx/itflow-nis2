<?php
require_once '../../../includes/modal_header.php';

$vlan_id = intval($_GET['id']);

$sql = mysqli_query($mysqli, "SELECT * FROM vlans WHERE vlan_id = $vlan_id LIMIT 1");
$row = mysqli_fetch_assoc($sql);
if (!$row) {
    ob_start();
    echo "<div class='modal-body'><div class='alert alert-danger'>VLAN not found.</div></div>";
    require_once '../../../includes/modal_footer.php';
    exit;
}

$client_id        = intval($row['vlan_client_id']);
$vlan_number      = intval($row['vlan_number']);
$vlan_name        = nullable_htmlentities($row['vlan_name']);
$vlan_description = nullable_htmlentities($row['vlan_description']);
$vlan_color       = nullable_htmlentities($row['vlan_color'] ?: '#6c757d');
$vlan_network_id  = intval($row['vlan_network_id']);

enforceClientAccess();

ob_start();
?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-layer-group mr-2"></i>Edit VLAN <?= $vlan_number ?></h5>
    <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="vlan_id" value="<?= $vlan_id ?>">

    <div class="modal-body">
        <div class="form-row">
            <div class="form-group col-md-4">
                <label>VLAN # <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-hashtag"></i></span></div>
                    <input type="number" min="1" max="4094" class="form-control" name="vlan_number" value="<?= $vlan_number ?>" required>
                </div>
            </div>
            <div class="form-group col-md-6">
                <label>Name <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span></div>
                    <input type="text" class="form-control" name="vlan_name" value="<?= $vlan_name ?>" maxlength="200" required>
                </div>
            </div>
            <div class="form-group col-md-2">
                <label>Color</label>
                <input type="color" class="form-control" name="vlan_color" value="<?= $vlan_color ?>" style="height:38px;">
            </div>
        </div>

        <div class="form-group">
            <label>Description</label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-align-left"></i></span></div>
                <input type="text" class="form-control" name="vlan_description" maxlength="500" value="<?= $vlan_description ?>">
            </div>
        </div>

        <div class="form-group">
            <label>Linked network (subnet)</label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-network-wired"></i></span></div>
                <select class="form-control select2" name="vlan_network_id">
                    <option value="">- None -</option>
                    <?php
                    $sql_net = mysqli_query($mysqli, "SELECT network_id, network_name, network FROM networks WHERE network_client_id = $client_id AND network_archived_at IS NULL ORDER BY network_name ASC");
                    while ($nrow = mysqli_fetch_assoc($sql_net)) {
                        $nid = intval($nrow['network_id']);
                        $nlabel = nullable_htmlentities(($nrow['network_name'] ?: '?') . ' (' . ($nrow['network'] ?: '?') . ')');
                        $sel = ($nid === $vlan_network_id) ? 'selected' : '';
                        echo "<option $sel value='$nid'>$nlabel</option>";
                    }
                    ?>
                </select>
            </div>
        </div>
    </div>
    <div class="modal-footer">
        <button type="submit" name="edit_vlan" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>
<?php require_once '../../../includes/modal_footer.php'; ?>
