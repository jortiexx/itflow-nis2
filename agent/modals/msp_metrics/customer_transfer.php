<?php
require_once '../../../includes/modal_header.php';

$customer_id = intval($_GET['id']);
$cust = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT customer_id, customer_name, transferred_from_customer_id, transferred_at, transfer_notes
     FROM msp_dim_customer WHERE customer_id = $customer_id LIMIT 1"));

ob_start();

if (!$cust) {
    echo "<div class='modal-body'><div class='alert alert-danger'>Klant niet gevonden.</div></div>";
    require_once '../../../includes/modal_footer.php';
    exit;
}

$transferred_from_id = intval($cust['transferred_from_customer_id'] ?? 0);
$transferred_at      = $cust['transferred_at']  ?: date('Y-m-d');
$transfer_notes      = $cust['transfer_notes']  ?? '';

// All OTHER customers for the predecessor select. Active customers come
// first (most-likely matches for a transfer-in), then historical ones
// (kept around exactly so we can point at "former" customers like Zo
// Kinderopvang who no longer have active subs but who a contract came
// from). Marked visually so the user knows the status.
$others = mysqli_query($mysqli,
    "SELECT customer_id, customer_name, has_active_subscription FROM msp_dim_customer
     WHERE customer_id <> $customer_id
     ORDER BY has_active_subscription DESC, customer_name ASC");
?>
<div class="modal-header">
    <h5 class="modal-title"><i class="fa fa-fw fa-exchange-alt mr-2"></i>Klant overgenomen van...</h5>
    <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
</div>
<form action="/agent/post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="customer_id" value="<?= $customer_id ?>">

    <div class="modal-body">
        <div class="form-group">
            <label>Klant</label>
            <input type="text" class="form-control" value="<?= nullable_htmlentities($cust['customer_name']) ?>" disabled>
        </div>

        <div class="form-group">
            <label>Overgenomen van</label>
            <select name="transferred_from_customer_id" class="form-control select2" data-placeholder="Zoek bestaande klant">
                <option value="0">- Geen overdracht (verwijder relatie) -</option>
                <?php while ($o = mysqli_fetch_assoc($others)) {
                    $sel = $transferred_from_id === intval($o['customer_id']) ? 'selected' : '';
                    $label = nullable_htmlentities($o['customer_name']);
                    if (!intval($o['has_active_subscription'])) $label .= ' — (historisch, geen actief abo)';
                    ?>
                    <option value="<?= intval($o['customer_id']) ?>" <?= $sel ?>><?= $label ?></option>
                <?php } ?>
            </select>
            <small class="form-text text-muted">
                De voorganger blijft bestaan in de tabel (toont nu een "→ naar"-marker). Deze klant
                wordt niet meer als "nieuw" geteld in de cohort-chart.
            </small>
        </div>

        <div class="form-group">
            <label>Datum overdracht</label>
            <input type="date" class="form-control" name="transferred_at" value="<?= htmlentities($transferred_at) ?>">
        </div>

        <div class="form-group">
            <label>Toelichting (optioneel)</label>
            <textarea class="form-control" name="transfer_notes" rows="2" placeholder="bv. abonnement verhuisd van holding naar werkmaatschappij"><?= nullable_htmlentities($transfer_notes) ?></textarea>
        </div>
    </div>

    <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Annuleren</button>
        <button type="submit" name="edit_msp_customer_transfer" class="btn btn-primary">Opslaan</button>
    </div>
</form>

<?php require_once '../../../includes/modal_footer.php';
