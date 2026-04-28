<?php
require_once "includes/inc_all_admin.php";
require_once "../includes/security_audit.php";

$page = max(1, intval($_GET['page'] ?? 1));
$per  = 50;
$off  = ($page - 1) * $per;

$type_filter = isset($_GET['type']) ? trim((string)$_GET['type']) : '';
$user_filter = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;

$where = [];
if ($type_filter !== '') {
    $type_e = mysqli_real_escape_string($mysqli, $type_filter);
    $where[] = "event_type LIKE '%$type_e%'";
}
if ($user_filter > 0) {
    $where[] = "user_id = $user_filter";
}
$where_sql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$total_row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT COUNT(*) AS n FROM security_audit_log $where_sql"
));
$total = intval($total_row['n']);

$rs = mysqli_query(
    $mysqli,
    "SELECT log_id, event_time, event_type, user_id, target_type, target_id,
            source_ip, user_agent, metadata, entry_hash
     FROM security_audit_log
     $where_sql
     ORDER BY log_id DESC
     LIMIT $per OFFSET $off"
);

$latest_hash_hex = securityAuditLatestHash($mysqli) ?? '(no entries yet)';

?>
<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-shield-alt mr-2"></i>Security audit log</h3>
    </div>
    <div class="card-body">

        <div class="alert alert-secondary small">
            <strong>Latest entry hash:</strong>
            <code style="word-break: break-all;"><?= htmlentities($latest_hash_hex) ?></code>
            <br>
            Pin this value externally (SIEM, cold storage, paper) at any time. Future runs of
            <code>php scripts/audit_verify.php</code> can then prove no tampering up to the
            point you recorded it.
        </div>

        <form method="get" class="form-inline mb-3">
            <input type="text" class="form-control mr-2" name="type" placeholder="event_type contains..." value="<?= htmlentities($type_filter) ?>">
            <input type="number" class="form-control mr-2" name="user_id" placeholder="user_id" value="<?= $user_filter > 0 ? $user_filter : '' ?>">
            <button type="submit" class="btn btn-primary">Filter</button>
            <a href="?" class="btn btn-link">Clear</a>
        </form>

        <table class="table table-sm">
            <thead>
            <tr>
                <th>ID</th><th>Time</th><th>Event</th><th>User</th>
                <th>Target</th><th>IP</th><th>Metadata</th>
            </tr>
            </thead>
            <tbody>
            <?php while ($row = mysqli_fetch_assoc($rs)): ?>
                <tr>
                    <td><?= intval($row['log_id']) ?></td>
                    <td><small><?= htmlentities($row['event_time']) ?></small></td>
                    <td><code><?= htmlentities($row['event_type']) ?></code></td>
                    <td><?= $row['user_id'] !== null ? intval($row['user_id']) : '-' ?></td>
                    <td>
                        <?php if ($row['target_type']): ?>
                            <small><?= htmlentities($row['target_type']) ?>:<?= intval($row['target_id']) ?></small>
                        <?php else: ?>-<?php endif; ?>
                    </td>
                    <td><small><?= nullable_htmlentities($row['source_ip'] ?? '') ?></small></td>
                    <td><small><?= $row['metadata'] ? htmlentities($row['metadata']) : '' ?></small></td>
                </tr>
            <?php endwhile; ?>
            </tbody>
        </table>

        <?php
        $pages = max(1, (int)ceil($total / $per));
        if ($pages > 1):
        ?>
            <nav>
                <ul class="pagination">
                    <?php for ($p = max(1, $page - 3); $p <= min($pages, $page + 3); $p++): ?>
                        <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                            <a class="page-link" href="?page=<?= $p ?>&type=<?= urlencode($type_filter) ?>&user_id=<?= $user_filter > 0 ? $user_filter : '' ?>"><?= $p ?></a>
                        </li>
                    <?php endfor; ?>
                </ul>
            </nav>
        <?php endif; ?>

        <p class="text-muted small">Total entries: <?= $total ?>. Showing page <?= $page ?> of <?= $pages ?>.</p>

    </div>
</div>

<?php require_once "../includes/footer.php";
