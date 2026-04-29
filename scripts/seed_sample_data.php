#!/usr/bin/env php
<?php
/*
 * Sample data seeder.
 *
 * Populates a freshly-installed ITFlow database with a representative
 * set of clients, contacts, assets, credentials, documents, and files.
 * Used for the upgrade-test playbook (docs/upgrade_test.md): you seed
 * a vanilla install, switch to the fork, run the migrations, and verify
 * nothing breaks.
 *
 * Properties:
 *   - Idempotent. Re-running creates no duplicates (uses unique
 *     client_name as the lookup key).
 *   - Realistic but minimal. 3 clients, 2 contacts each, 2 assets each,
 *     2 credentials each, 1 document each, 2 files each.
 *   - Files are written to disk as PLAINTEXT with file_encrypted = 0,
 *     deliberately mimicking a pre-phase-13 install. The legacy file
 *     sweeper should pick these up on first admin login after upgrade.
 *   - Credentials are stored unencrypted (legacy "v0") — they will be
 *     re-encrypted on next save under the v3 per-client master key.
 *     This mirrors the lazy-migration model used throughout the fork.
 *
 * Usage:
 *   php scripts/seed_sample_data.php
 *   php scripts/seed_sample_data.php --reset      (delete seeded data first)
 *   php scripts/seed_sample_data.php --verbose
 *
 * NOT for production. Sample data uses obvious fake names and predictable
 * passwords. The seeder marks all seeded rows so they can be cleanly
 * removed via --reset.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

if (!$mysqli || mysqli_connect_errno()) {
    fwrite(STDERR, "DB connection failed\n");
    exit(2);
}

$reset   = in_array('--reset', $argv, true);
$verbose = in_array('--verbose', $argv, true);

// Marker put into the *_notes / description fields so we can recognise
// rows we created and clean them up on --reset.
const SEED_MARKER = '[seed:sample-data-v1]';

function log_v(string $msg): void {
    global $verbose;
    if ($verbose) echo "  $msg\n";
}

function pickClientId(mysqli $mysqli, string $client_name): ?int {
    $name_e = mysqli_real_escape_string($mysqli, $client_name);
    $r = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT client_id FROM clients WHERE client_name = '$name_e' LIMIT 1"));
    return $r ? intval($r['client_id']) : null;
}

if ($reset) {
    echo "=== Resetting previously-seeded sample data ===\n";

    // Find all clients we created (marked in client_notes).
    $marker_e = mysqli_real_escape_string($mysqli, SEED_MARKER);
    $client_ids = [];
    $res = mysqli_query($mysqli,
        "SELECT client_id FROM clients WHERE client_notes LIKE '%$marker_e%'");
    while ($res && ($r = mysqli_fetch_assoc($res))) {
        $client_ids[] = intval($r['client_id']);
    }

    foreach ($client_ids as $cid) {
        log_v("removing client $cid + dependents");

        // Files: also remove from disk.
        $f = mysqli_query($mysqli,
            "SELECT file_id, file_reference_name FROM files WHERE file_client_id = $cid");
        while ($f && ($r = mysqli_fetch_assoc($f))) {
            $disk = __DIR__ . "/../uploads/clients/$cid/" . basename($r['file_reference_name']);
            if (is_file($disk)) @unlink($disk);
        }

        mysqli_query($mysqli, "DELETE FROM files       WHERE file_client_id       = $cid");
        mysqli_query($mysqli, "DELETE FROM credentials WHERE credential_client_id = $cid");
        mysqli_query($mysqli, "DELETE FROM documents   WHERE document_client_id   = $cid");
        mysqli_query($mysqli, "DELETE FROM assets      WHERE asset_client_id      = $cid");
        mysqli_query($mysqli, "DELETE FROM contacts    WHERE contact_client_id    = $cid");
        mysqli_query($mysqli, "DELETE FROM client_master_keys WHERE client_id = $cid");
        mysqli_query($mysqli, "DELETE FROM clients     WHERE client_id            = $cid");
    }
    echo "Removed " . count($client_ids) . " seeded client(s) and their dependents.\n";
    exit(0);
}

echo "=== Seeding sample data ===\n";

$clients_to_seed = [
    [
        'name'   => 'Acme Industries',
        'website'=> 'acme.example',
        'type'   => 'Customer',
        'contacts' => [
            ['name' => 'Wile E Coyote',  'email' => 'wile@acme.example',  'title' => 'CTO'],
            ['name' => 'Roadrunner',     'email' => 'rr@acme.example',    'title' => 'Mascot'],
        ],
        'assets' => [
            ['name' => 'srv-acme-01', 'type' => 'Server',   'make' => 'Dell',  'os' => 'Windows Server 2022'],
            ['name' => 'fw-acme-01',  'type' => 'Firewall', 'make' => 'Fortinet', 'os' => 'FortiOS 7.4'],
        ],
        'credentials' => [
            ['name' => 'Acme AD admin',     'username' => 'acme\\administrator', 'password' => 'pl@inText-Adm1n!', 'note' => 'Domain admin password — change after onboarding.'],
            ['name' => 'Acme firewall web', 'username' => 'admin',               'password' => 'F1r3w@ll!Pa$$',    'note' => ''],
        ],
        'document' => [
            'name'    => 'Acme onboarding runbook',
            'content' => "<h2>Acme onboarding runbook</h2><p>Step 1: confirm DNS, step 2: connect VPN, step 3: pat self on back.</p><p>Critical: backup admin pass is stored in the credential vault.</p>",
        ],
        'files' => [
            ['name' => 'acme-network-diagram.txt', 'ext' => 'txt', 'mime' => 'text/plain',
             'content' => "Acme network\n  10.20.30.0/24 LAN\n  10.20.31.0/24 DMZ\n  Default GW 10.20.30.1\n"],
            ['name' => 'acme-vpn.ovpn',            'ext' => 'ovpn', 'mime' => 'application/octet-stream',
             'content' => "client\ndev tun\nproto udp\nremote vpn.acme.example 1194\n# fake config — would normally include certs/keys"],
        ],
    ],
    [
        'name'   => 'Globex Corp',
        'website'=> 'globex.example',
        'type'   => 'Customer',
        'contacts' => [
            ['name' => 'Hank Scorpio', 'email' => 'hank@globex.example', 'title' => 'CEO'],
            ['name' => 'Aristotle Amadopolis', 'email' => 'a.a@globex.example', 'title' => 'Plant manager'],
        ],
        'assets' => [
            ['name' => 'sw-globex-core', 'type' => 'Switch', 'make' => 'Cisco', 'os' => 'IOS 17.9'],
            ['name' => 'nas-globex-01',  'type' => 'NAS',    'make' => 'Synology', 'os' => 'DSM 7.2'],
        ],
        'credentials' => [
            ['name' => 'Globex switch enable',   'username' => 'enable',   'password' => 'Sw1tch3n@ble', 'note' => 'Console port only.'],
            ['name' => 'Globex Synology admin',  'username' => 'admin',    'password' => 'syN0L0gy-pa$$', 'note' => "Backup creds:\n  user: backup\n  pwd: B@ckUp_2024"],
        ],
        'document' => [
            'name'    => 'Globex DR plan',
            'content' => "<h2>Globex DR plan</h2><ol><li>Snapshot NAS hourly</li><li>Replicate to off-site every 6h</li><li>Test restore quarterly</li></ol>",
        ],
        'files' => [
            ['name' => 'globex-rack-layout.txt', 'ext' => 'txt', 'mime' => 'text/plain',
             'content' => "Rack 1: server hosts\nRack 2: switch + patchpanels\nRack 3: storage\n"],
            ['name' => 'globex-licenses.txt',    'ext' => 'txt', 'mime' => 'text/plain',
             'content' => "Synology DSM Pro: ABCD-1234-EFGH-5678 (expires 2027)\nCisco SmartNet: SN-XYZ-99887766\n"],
        ],
    ],
    [
        'name'   => 'Initech',
        'website'=> 'initech.example',
        'type'   => 'Customer',
        'contacts' => [
            ['name' => 'Bill Lumbergh', 'email' => 'bill@initech.example', 'title' => 'VP'],
            ['name' => 'Peter Gibbons', 'email' => 'peter@initech.example','title' => 'Software Engineer'],
        ],
        'assets' => [
            ['name' => 'wks-initech-pgibbons', 'type' => 'Workstation', 'make' => 'HP', 'os' => 'Windows 11 Pro'],
        ],
        'credentials' => [
            ['name' => 'Initech 365 admin', 'username' => 'admin@initech.example', 'password' => 'TPS-r3p0rts!', 'note' => ''],
        ],
        'document' => [
            'name'    => 'Initech password policy',
            'content' => "<h2>Initech password policy</h2><p>Minimum 12 chars; rotate quarterly. <strong>Do not</strong> reuse cover-sheet patterns.</p>",
        ],
        'files' => [
            ['name' => 'initech-asset-list.txt', 'ext' => 'txt', 'mime' => 'text/plain',
             'content' => "wks-initech-pgibbons (HP, Win11)\nprn-initech-floor3 (Brother MFC, no flames)\n"],
        ],
    ],
];

$total_clients     = 0;
$total_contacts    = 0;
$total_assets      = 0;
$total_credentials = 0;
$total_documents   = 0;
$total_files       = 0;

foreach ($clients_to_seed as $c) {
    $existing = pickClientId($mysqli, $c['name']);
    if ($existing) {
        log_v("client '{$c['name']}' already exists (id=$existing); skipping");
        continue;
    }

    $name_e    = mysqli_real_escape_string($mysqli, $c['name']);
    $website_e = mysqli_real_escape_string($mysqli, $c['website']);
    $type_e    = mysqli_real_escape_string($mysqli, $c['type']);
    $notes_e   = mysqli_real_escape_string($mysqli, "Sample customer for upgrade testing. " . SEED_MARKER);

    mysqli_query($mysqli,
        "INSERT INTO clients SET
            client_name = '$name_e',
            client_website = '$website_e',
            client_type = '$type_e',
            client_currency_code = 'USD',
            client_net_terms = 30,
            client_notes = '$notes_e'");
    $client_id = intval(mysqli_insert_id($mysqli));
    if ($client_id <= 0) {
        fwrite(STDERR, "Failed to create client {$c['name']}\n");
        continue;
    }
    log_v("created client {$c['name']} (id=$client_id)");
    $total_clients++;

    foreach ($c['contacts'] as $contact) {
        $cn = mysqli_real_escape_string($mysqli, $contact['name']);
        $ce = mysqli_real_escape_string($mysqli, $contact['email']);
        $ct = mysqli_real_escape_string($mysqli, $contact['title']);
        mysqli_query($mysqli,
            "INSERT INTO contacts SET
                contact_name = '$cn',
                contact_email = '$ce',
                contact_title = '$ct',
                contact_client_id = $client_id");
        $total_contacts++;
    }

    foreach ($c['assets'] as $asset) {
        $an = mysqli_real_escape_string($mysqli, $asset['name']);
        $at = mysqli_real_escape_string($mysqli, $asset['type']);
        $am = mysqli_real_escape_string($mysqli, $asset['make']);
        $ao = mysqli_real_escape_string($mysqli, $asset['os']);
        mysqli_query($mysqli,
            "INSERT INTO assets SET
                asset_name = '$an',
                asset_type = '$at',
                asset_make = '$am',
                asset_os = '$ao',
                asset_client_id = $client_id");
        $total_assets++;
    }

    // Credentials are seeded as PLAINTEXT in the password column. The
    // production code will lazy-encrypt on next save (encrypt-on-write
    // pattern from phase 9 onward). Reading them back without a vault
    // session will return the plaintext bytes; with a vault session
    // decryptCredentialEntry detects the absence of a v2/v3 prefix and
    // returns the value as-is.
    foreach ($c['credentials'] as $cred) {
        $cn  = mysqli_real_escape_string($mysqli, $cred['name']);
        $cu  = mysqli_real_escape_string($mysqli, $cred['username']);
        $cp  = mysqli_real_escape_string($mysqli, $cred['password']);
        $cnt = mysqli_real_escape_string($mysqli, $cred['note']);
        mysqli_query($mysqli,
            "INSERT INTO credentials SET
                credential_name = '$cn',
                credential_username = '$cu',
                credential_password = '$cp',
                credential_note = '$cnt',
                credential_client_id = $client_id");
        $total_credentials++;
    }

    // One document per client. Plaintext content_raw drives the FULLTEXT
    // search index post-revert.
    $dn  = mysqli_real_escape_string($mysqli, $c['document']['name']);
    $dh  = mysqli_real_escape_string($mysqli, $c['document']['content']);
    $dr  = mysqli_real_escape_string($mysqli,
        $c['document']['name'] . ' ' . strip_tags($c['document']['content']));
    mysqli_query($mysqli,
        "INSERT INTO documents SET
            document_name = '$dn',
            document_content = '$dh',
            document_content_raw = '$dr',
            document_client_id = $client_id");
    $total_documents++;

    // Files. Write each one to disk as plaintext with file_encrypted = 0,
    // then INSERT the row. This mirrors a pre-phase-13 upload.
    $client_dir = __DIR__ . "/../uploads/clients/$client_id";
    if (!is_dir($client_dir)) {
        mkdir($client_dir, 0755, true);
    }

    foreach ($c['files'] as $file) {
        $reference = bin2hex(random_bytes(8)) . '.' . $file['ext'];
        $disk_path = $client_dir . '/' . $reference;
        if (file_put_contents($disk_path, $file['content']) === false) {
            fwrite(STDERR, "Failed to write file $disk_path\n");
            continue;
        }
        $fn   = mysqli_real_escape_string($mysqli, $file['name']);
        $fr   = mysqli_real_escape_string($mysqli, $reference);
        $fext = mysqli_real_escape_string($mysqli, $file['ext']);
        $fmt  = mysqli_real_escape_string($mysqli, $file['mime']);
        $fs   = strlen($file['content']);
        mysqli_query($mysqli,
            "INSERT INTO files SET
                file_name = '$fn',
                file_reference_name = '$fr',
                file_ext = '$fext',
                file_mime_type = '$fmt',
                file_size = $fs,
                file_client_id = $client_id");
        $total_files++;
    }
}

echo "\n=== Summary ===\n";
echo "Clients created:     $total_clients\n";
echo "Contacts created:    $total_contacts\n";
echo "Assets created:      $total_assets\n";
echo "Credentials created: $total_credentials\n";
echo "Documents created:   $total_documents\n";
echo "Files created:       $total_files\n";
echo "\nMarker used: " . SEED_MARKER . "\n";
echo "Run with --reset to remove the seeded data.\n";

exit(0);
