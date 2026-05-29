<?php

$sort = "vlan_number";
$order = "ASC";

if (isset($_GET['client_id'])) {
    require_once "includes/inc_all_client.php";
    $client_query = "AND vlan_client_id = $client_id";
    $client_url = "client_id=$client_id&";
    if (isset($_GET['archived']) && $_GET['archived'] == 1) {
        $archived = 1;
        $archive_query = "vlan_archived_at IS NOT NULL";
    } else {
        $archived = 0;
        $archive_query = "vlan_archived_at IS NULL";
    }
} else {
    require_once "includes/inc_client_overview_all.php";
    $client_query = '';
    $client_url = '';
    if (isset($_GET['archived']) && $_GET['archived'] == 1) {
        $archived = 1;
        $archive_query = "(client_archived_at IS NOT NULL OR vlan_archived_at IS NOT NULL)";
    } else {
        $archived = 0;
        $archive_query = "(client_archived_at IS NULL AND vlan_archived_at IS NULL)";
    }
}

enforceUserPermission('module_support');

if (!$client_url) {
    if (isset($_GET['client']) && !empty($_GET['client'])) {
        $client_query = 'AND vlan_client_id = ' . intval($_GET['client']);
        $client = intval($_GET['client']);
    } else {
        $client_query = '';
        $client = '';
    }
}

$sql = mysqli_query(
    $mysqli,
    "SELECT SQL_CALC_FOUND_ROWS vlans.*, clients.client_id, clients.client_name, networks.network_name
     FROM vlans
     LEFT JOIN clients ON client_id = vlan_client_id
     LEFT JOIN networks ON network_id = vlan_network_id
     WHERE $archive_query
       AND (vlan_name LIKE '%$q%' OR vlan_description LIKE '%$q%' OR vlan_number LIKE '%$q%' OR client_name LIKE '%$q%')
       $access_permission_query
       $client_query
     ORDER BY $sort $order
     LIMIT $record_from, $record_to"
);

$num_rows = mysqli_fetch_row(mysqli_query($mysqli, "SELECT FOUND_ROWS()"));

?>
<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2"><i class="fas fa-fw fa-layer-group mr-2"></i>VLANs</h3>
        <div class="card-tools">
            <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/vlan/vlan_add.php?<?= $client_url ?>">
                <i class="fas fa-plus mr-2"></i>New VLAN
            </button>
        </div>
    </div>
    <div class="card-body">
        <form autocomplete="off">
            <?php if ($client_url) { ?>
                <input type="hidden" name="client_id" value="<?= $client_id ?>">
            <?php } ?>
            <input type="hidden" name="archived" value="<?= $archived ?>">
            <div class="row">
                <div class="col-md-4">
                    <div class="input-group mb-3 mb-md-0">
                        <input type="search" class="form-control" name="q" value="<?= isset($q) ? stripslashes(nullable_htmlentities($q)) : '' ?>" placeholder="Search VLANs">
                        <div class="input-group-append">
                            <button class="btn btn-dark"><i class="fa fa-search"></i></button>
                        </div>
                    </div>
                </div>
                <?php if (!$client_url) { ?>
                    <div class="col-md-2">
                        <select class="form-control select2" name="client" onchange="this.form.submit()">
                            <option value="">- All Clients -</option>
                            <?php
                            $sql_clients_filter = mysqli_query($mysqli, "
                                SELECT DISTINCT client_id, client_name
                                FROM clients
                                JOIN vlans ON vlan_client_id = client_id
                                WHERE $archive_query
                                $access_permission_query
                                ORDER BY client_name ASC
                            ");
                            while ($row_f = mysqli_fetch_assoc($sql_clients_filter)) {
                                $cid = intval($row_f['client_id']);
                                $cname = nullable_htmlentities($row_f['client_name']);
                                $sel = ($client == $cid) ? 'selected' : '';
                                echo "<option $sel value='$cid'>$cname</option>";
                            }
                            ?>
                        </select>
                    </div>
                <?php } ?>
                <div class="col-md-6">
                    <div class="btn-group float-right">
                        <a href="?<?= $client_url ?>archived=<?= $archived == 1 ? 0 : 1 ?>"
                           class="btn btn-<?= $archived == 1 ? 'primary' : 'default' ?>">
                            <i class="fa fa-fw fa-archive mr-2"></i>Archived
                        </a>
                    </div>
                </div>
            </div>
        </form>
        <hr>
        <div class="table-responsive">
            <table class="table table-striped table-borderless table-hover">
                <thead class="text-dark <?= $num_rows[0] == 0 ? 'd-none' : '' ?>">
                <tr>
                    <th><a class="text-secondary" href="?<?= $url_query_strings_sort ?>&sort=vlan_number&order=<?= $disp ?>">VLAN # <?= $sort == 'vlan_number' ? $order_icon : '' ?></a></th>
                    <th><a class="text-secondary" href="?<?= $url_query_strings_sort ?>&sort=vlan_name&order=<?= $disp ?>">Name <?= $sort == 'vlan_name' ? $order_icon : '' ?></a></th>
                    <th>Description</th>
                    <th>Network</th>
                    <?php if (!$client_url) { ?>
                        <th>Client</th>
                    <?php } ?>
                    <th class="text-center">Action</th>
                </tr>
                </thead>
                <tbody>
                <?php while ($row = mysqli_fetch_assoc($sql)) {
                    $vlan_id          = intval($row['vlan_id']);
                    $vlan_number      = intval($row['vlan_number']);
                    $vlan_name        = nullable_htmlentities($row['vlan_name']);
                    $vlan_description = nullable_htmlentities($row['vlan_description']);
                    $vlan_color       = nullable_htmlentities($row['vlan_color'] ?: '#6c757d');
                    $vlan_archived_at = $row['vlan_archived_at'];
                    $row_client_id    = intval($row['client_id']);
                    $row_client_name  = nullable_htmlentities($row['client_name']);
                    $network_name     = nullable_htmlentities($row['network_name']);
                    ?>
                    <tr>
                        <td>
                            <span class="badge" style="background:<?= $vlan_color ?>;color:#fff;font-size:0.95em;">VLAN <?= $vlan_number ?></span>
                        </td>
                        <td>
                            <a class="text-dark ajax-modal" href="#" data-modal-url="modals/vlan/vlan_edit.php?id=<?= $vlan_id ?>">
                                <?= $vlan_name ?>
                            </a>
                        </td>
                        <td><small class="text-secondary"><?= $vlan_description ?: '-' ?></small></td>
                        <td><?= $network_name ?: '-' ?></td>
                        <?php if (!$client_url) { ?>
                            <td><a href="vlans.php?client_id=<?= $row_client_id ?>"><?= $row_client_name ?></a></td>
                        <?php } ?>
                        <td>
                            <div class="dropdown dropleft text-center">
                                <button class="btn btn-secondary btn-sm" type="button" data-toggle="dropdown">
                                    <i class="fas fa-ellipsis-h"></i>
                                </button>
                                <div class="dropdown-menu">
                                    <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/vlan/vlan_edit.php?id=<?= $vlan_id ?>">
                                        <i class="fas fa-fw fa-edit mr-2"></i>Edit
                                    </a>
                                    <?php if ($session_user_role == 3) { ?>
                                        <?php if ($vlan_archived_at) { ?>
                                            <div class="dropdown-divider"></div>
                                            <a class="dropdown-item text-info confirm-link" href="post.php?restore_vlan=<?= $vlan_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                <i class="fas fa-fw fa-redo mr-2"></i>Restore
                                            </a>
                                            <div class="dropdown-divider"></div>
                                            <a class="dropdown-item text-danger text-bold confirm-link" href="post.php?delete_vlan=<?= $vlan_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                <i class="fas fa-fw fa-trash mr-2"></i>Delete
                                            </a>
                                        <?php } else { ?>
                                            <div class="dropdown-divider"></div>
                                            <a class="dropdown-item text-danger confirm-link" href="post.php?archive_vlan=<?= $vlan_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                <i class="fas fa-fw fa-archive mr-2"></i>Archive
                                            </a>
                                        <?php } ?>
                                    <?php } ?>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php } ?>
                </tbody>
            </table>
        </div>
        <?php require_once "../includes/filter_footer.php"; ?>
    </div>
</div>
<?php require_once "../includes/footer.php"; ?>
