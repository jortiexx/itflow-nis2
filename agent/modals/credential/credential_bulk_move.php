<?php

require_once '../../../includes/modal_header.php';

$credential_ids = array_map('intval', $_GET['credential_ids'] ?? []);

$count = count($credential_ids);

ob_start();

?>

<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-exchange-alt mr-2"></i>Move <strong><?= $count ?></strong> Credentials to another Client</h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <?php foreach ($credential_ids as $credential_id) { ?><input type="hidden" name="credential_ids[]" value="<?= $credential_id ?>"><?php } ?>
    <div class="modal-body">

        <div class="alert alert-warning">
            <i class="fa fa-fw fa-key mr-1"></i>
            Each credential is decrypted with the current client's key, re-encrypted with the key of the
            target client and verified before it is saved. Links to assets, contacts, vendors, software,
            services and folders that do not belong to the target client are removed.
        </div>

        <div class="form-group">
            <label>Target Client <strong class="text-danger">*</strong></label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                </div>
                <select class="form-control select2" name="target_client_id" required>
                    <option value="">- Select Client -</option>
                    <?php

                    $sql_clients_select = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL $access_permission_query ORDER BY client_name ASC");
                    while ($row = mysqli_fetch_assoc($sql_clients_select)) {
                        $client_id_select = intval($row['client_id']);
                        $client_name_select = nullable_htmlentities($row['client_name']);
                        ?>
                        <option value="<?= $client_id_select ?>"><?= $client_name_select ?></option>
                    <?php } ?>

                </select>
            </div>
        </div>

    </div>

    <div class="modal-footer">
        <button type="submit" name="bulk_move_credentials" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Move Credentials</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>

<?php
require_once '../../../includes/modal_footer.php';
