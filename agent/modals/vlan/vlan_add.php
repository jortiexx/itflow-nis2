<?php
require_once '../../../includes/modal_header.php';

$client_id = intval($_GET['client_id'] ?? 0);

ob_start();
?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-layer-group mr-2"></i>New VLAN</h5>
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
                            $cid = intval($row['client_id']);
                            $cname = nullable_htmlentities($row['client_name']);
                            echo "<option value='$cid'>$cname</option>";
                        }
                        ?>
                    </select>
                </div>
            </div>
        <?php } ?>

        <div class="form-row">
            <div class="form-group col-md-4">
                <label>VLAN # <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-hashtag"></i></span></div>
                    <input type="number" min="1" max="4094" class="form-control" name="vlan_number" required autofocus>
                </div>
                <small class="form-text text-muted">802.1Q tag (1-4094)</small>
            </div>
            <div class="form-group col-md-6">
                <label>Name <strong class="text-danger">*</strong></label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span></div>
                    <input type="text" class="form-control" name="vlan_name" placeholder="e.g. VOIP, IoT, Guest" required maxlength="200">
                </div>
            </div>
            <div class="form-group col-md-2">
                <label>Color</label>
                <input type="color" class="form-control" name="vlan_color" value="#6c757d" style="height:38px;">
            </div>
        </div>

        <div class="form-group">
            <label>Description</label>
            <div class="input-group">
                <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-align-left"></i></span></div>
                <input type="text" class="form-control" name="vlan_description" maxlength="500" placeholder="Optional notes for this VLAN">
            </div>
        </div>

        <?php if ($client_id) { ?>
            <div class="form-group">
                <label>Linked network (subnet)</label>
                <div class="input-group">
                    <div class="input-group-prepend"><span class="input-group-text"><i class="fa fa-fw fa-network-wired"></i></span></div>
                    <select class="form-control select2" name="vlan_network_id">
                        <option value="">- None -</option>
                        <?php
                        $sql = mysqli_query($mysqli, "SELECT network_id, network_name, network FROM networks WHERE network_client_id = $client_id AND network_archived_at IS NULL ORDER BY network_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $nid = intval($row['network_id']);
                            $nlabel = nullable_htmlentities(($row['network_name'] ?: '?') . ' (' . ($row['network'] ?: '?') . ')');
                            echo "<option value='$nid'>$nlabel</option>";
                        }
                        ?>
                    </select>
                </div>
                <small class="form-text text-muted">Optional — links this VLAN tag to the IPv4/IPv6 subnet that lives on it.</small>
            </div>
        <?php } ?>
    </div>
    <div class="modal-footer">
        <button type="submit" name="add_vlan" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Create</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>
<?php require_once '../../../includes/modal_footer.php'; ?>
