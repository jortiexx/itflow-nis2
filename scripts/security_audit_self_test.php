#!/usr/bin/env php
<?php
/*
 * Security audit log self-test (offline; no DB).
 *
 * Tests the canonical-serialization and hash-chain math used by
 * securityAudit() and audit_verify, without touching the database.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "This script must be run from the CLI.\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../includes/security_audit.php';

$failures = 0;
$tests    = 0;

function check(string $label, bool $ok): void
{
    global $failures, $tests;
    $tests++;
    if ($ok) {
        echo "  [PASS] $label\n";
    } else {
        echo "  [FAIL] $label\n";
        $failures++;
    }
}

echo "=== Security audit log self-test ===\n\n";

// -----------------------------------------------------------------
echo "1. Canonical serialization is order-independent\n";
$entry_a = [
    'event_time'  => '2026-04-28 12:00:00.000000',
    'event_type'  => 'login.password.success',
    'user_id'     => 42,
    'target_type' => null,
    'target_id'   => null,
    'source_ip'   => '10.0.0.1',
    'user_agent'  => 'Mozilla/5.0',
    'metadata'    => '{"mfa":"with MFA"}',
];
$entry_b_shuffled = [
    'metadata'    => '{"mfa":"with MFA"}',
    'event_type'  => 'login.password.success',
    'user_agent'  => 'Mozilla/5.0',
    'event_time'  => '2026-04-28 12:00:00.000000',
    'user_id'     => 42,
    'source_ip'   => '10.0.0.1',
    'target_id'   => null,
    'target_type' => null,
];
check(
    'identical fields in different array order produce identical canonical form',
    securityAuditCanonicalize($entry_a) === securityAuditCanonicalize($entry_b_shuffled)
);

// -----------------------------------------------------------------
echo "\n2. Hash chain — three-entry walk\n";
$prev = SECURITY_AUDIT_NULL_HASH;
check('null hash is 32 zero bytes', strlen(SECURITY_AUDIT_NULL_HASH) === 32 && SECURITY_AUDIT_NULL_HASH === str_repeat("\x00", 32));

$entries = [
    ['event_time' => '2026-04-28 10:00:00.000000', 'event_type' => 'a'],
    ['event_time' => '2026-04-28 10:01:00.000000', 'event_type' => 'b', 'user_id' => 1],
    ['event_time' => '2026-04-28 10:02:00.000000', 'event_type' => 'c', 'metadata' => '{"x":1}'],
];

$hashes = [];
foreach ($entries as $e) {
    $canonical = securityAuditCanonicalize($e);
    $h = hash('sha256', $prev . $canonical, true);
    $hashes[] = ['prev' => $prev, 'entry' => $h, 'canonical' => $canonical];
    $prev = $h;
}
check('three distinct hashes', $hashes[0]['entry'] !== $hashes[1]['entry'] && $hashes[1]['entry'] !== $hashes[2]['entry']);
check('chain links consistent', $hashes[1]['prev'] === $hashes[0]['entry'] && $hashes[2]['prev'] === $hashes[1]['entry']);

// -----------------------------------------------------------------
echo "\n3. Tampering with entry 1 invalidates entry 1 hash\n";
$tampered_e = $entries[1];
$tampered_e['user_id'] = 99;  // changed from 1 to 99
$tampered_canonical = securityAuditCanonicalize($tampered_e);
$tampered_hash = hash('sha256', $hashes[1]['prev'] . $tampered_canonical, true);
check('recomputed hash with tampered field differs from stored', $tampered_hash !== $hashes[1]['entry']);

// -----------------------------------------------------------------
echo "\n4. Removing entry 1 breaks the chain at entry 2\n";
// If we delete entry 1, entry 2's prev_hash (= entry 1's entry_hash) no
// longer matches what verifier computes (entry 0's entry_hash).
$walk_after_delete_prev = $hashes[0]['entry'];  // verifier's running prev after entry 0
$entry_2_stored_prev    = $hashes[2]['prev'];   // entry_1.entry_hash
check(
    'after deleting entry 1, verifier prev != entry 2 stored prev',
    $walk_after_delete_prev !== $entry_2_stored_prev
);

// -----------------------------------------------------------------
echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
