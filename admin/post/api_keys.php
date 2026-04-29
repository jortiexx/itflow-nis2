<?php

/*
 * ITFlow - GET/POST request handler for API settings
 */

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once __DIR__ . '/../../includes/vault_unlock.php';

if (isset($_POST['add_api_key'])) {

    validateCSRFToken($_POST['csrf_token']);

    $name = sanitizeInput($_POST['name']);
    $expire = sanitizeInput($_POST['expire']);
    $client_id = intval($_POST['client']);
    $secret = sanitizeInput($_POST['key']); // API Key

    // Credential decryption password — wrap the master key both in v1 (legacy
    // PBKDF2 + AES-128-CBC) and v2 (Argon2id + AES-256-GCM) so existing API
    // consumers keep working while new requests can use the v2 path.
    $apikey_password_plain = trim($_POST['password']);
    $password = password_hash($apikey_password_plain, PASSWORD_DEFAULT);
    $apikey_specific_encryption_ciphertext = encryptUserSpecificKey($apikey_password_plain);

    // v2 wrapping: encryptUserSpecificKey() above already validated that the
    // session has a usable master key (it throws otherwise). Reuse the master
    // key from the active session to wrap a fresh v2 row.
    $apikey_v2 = '';
    $session_master_key = null;
    try {
        $session_master_key = vaultMasterKeyFromSession();
        if ($session_master_key !== null) {
            $apikey_v2 = encryptUserSpecificKeyV2($session_master_key, $apikey_password_plain);
        }
    } catch (Throwable $e) {
        error_log('API key v2 wrap failed: ' . $e->getMessage());
    }
    $apikey_v2_e = mysqli_real_escape_string($mysqli, $apikey_v2);

    // Phase 11: for client-scoped API keys (api_key_client_id > 0), wrap THAT
    // client's master key directly under the API password. API consumers
    // with this row get a per-client compartmentalised path that does not
    // route through the shared session master key — a compromised API key
    // is bounded to its scoped client and cannot decrypt any other client's
    // data. For global API keys (client_id = 0) this column stays NULL and
    // they continue to use the legacy shared-master path.
    $apikey_client_master_wrapped = '';
    if ($client_id > 0) {
        try {
            $client_master = getClientMasterKeyViaGrant($client_id, $mysqli)
                          ?? ensureClientMasterKey($client_id, $mysqli);
            if ($client_master !== null) {
                $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
                $kek  = deriveKekArgon2id($apikey_password_plain, $salt);
                $blob = cryptoEncryptV2($client_master, $kek);
                sodium_memzero($kek);
                sodium_memzero($client_master);
                $apikey_client_master_wrapped = base64_encode($salt . $blob);
            }
        } catch (Throwable $e) {
            error_log('API key per-client wrap failed: ' . $e->getMessage());
        }
    }
    $apikey_cm_e = mysqli_real_escape_string($mysqli, $apikey_client_master_wrapped);

    mysqli_query($mysqli,"INSERT INTO api_keys SET api_key_name = '$name', api_key_secret = '$secret', api_key_decrypt_hash = '$apikey_specific_encryption_ciphertext', api_key_decrypt_hash_v2 = '$apikey_v2_e', api_key_client_master_wrapped = '$apikey_cm_e', api_key_expire = '$expire', api_key_client_id = $client_id");

    $api_key_id = mysqli_insert_id($mysqli);

    logAction("API Key", "Create", "$session_name created API key $name set to expire on $expire", $client_id, $api_key_id);

    flash_alert("API Key <strong>$name</strong> created");

    redirect();

}

if (isset($_GET['revoke_api_key'])) {

    validateCSRFToken($_GET['csrf_token']);

    $api_key_id = intval($_GET['revoke_api_key']);

    // Get API Key Name
    $row = mysqli_fetch_assoc(mysqli_query($mysqli,"SELECT api_key_name, api_key_client_id FROM api_keys WHERE api_key_id = $api_key_id"));
    $api_key_name = sanitizeInput($row['api_key_name']);
    $client_id = intval($row['api_key_client_id']);

    mysqli_query($mysqli,"UPDATE api_keys SET api_key_expire = NOW() WHERE api_key_id = $api_key_id");

    logAction("API Key", "Revoke", "$session_name revoked API key $name", $client_id);

    flash_alert("API Key <strong>$name</strong> revoked", 'error');

    redirect();

}

if (isset($_GET['delete_api_key'])) {

    validateCSRFToken($_GET['csrf_token']);

    $api_key_id = intval($_GET['delete_api_key']);

    // Get API Key Name
    $row = mysqli_fetch_assoc(mysqli_query($mysqli,"SELECT api_key_name, api_key_client_id FROM api_keys WHERE api_key_id = $api_key_id"));
    $api_key_name = sanitizeInput($row['api_key_name']);
    $client_id = intval($row['api_key_client_id']);

    mysqli_query($mysqli,"DELETE FROM api_keys WHERE api_key_id = $api_key_id");

    logAction("API Key", "Delete", "$session_name deleted API key $name", $client_id);

    flash_alert("API Key <strong>$name</strong> deleted", 'error');

    redirect();

}

if (isset($_POST['bulk_delete_api_keys'])) {

    validateCSRFToken($_POST['csrf_token']);

    if (isset($_POST['api_key_ids'])) {

        $count = count($_POST['api_key_ids']);

        // Cycle through array and delete each record
        foreach ($_POST['api_key_ids'] as $api_key_id) {

            $api_key_id = intval($api_key_id);

            // Get API Key Name
            $row = mysqli_fetch_assoc(mysqli_query($mysqli,"SELECT api_key_name, api_key_client_id FROM api_keys WHERE api_key_id = $api_key_id"));
            $api_key_name = sanitizeInput($row['api_key_name']);
            $client_id = intval($row['api_key_client_id']);

            mysqli_query($mysqli, "DELETE FROM api_keys WHERE api_key_id = $api_key_id");

            logAction("API Key", "Delete", "$session_name deleted API key $name", $client_id);

        }

        logAction("API Key", "Bulk Delete", "$session_name deleted $count API key(s)");

        flash_alert("Deleted <strong>$count</strong> API keys(s)", 'error');

    }

    redirect();

}
