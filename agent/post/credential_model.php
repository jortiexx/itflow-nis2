<?php
// Model of reusable variables for client credentials - not to be confused with the ITFLow login process
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$name = sanitizeInput($_POST['name']);
$description = sanitizeInput($_POST['description']);
$uri = sanitizeInput($_POST['uri']);
$uri_2 = sanitizeInput($_POST['uri_2']);
// $client_id is provided by the parent script (credential.php) and routes
// the encrypt to the per-client master key (phase 9, v3 ciphertexts).
$username = encryptCredentialEntry(trim($_POST['username']), $client_id ?? null);
$password = encryptCredentialEntry(trim($_POST['password']), $client_id ?? null);
// Phase 12: TOTP seed and notes are now encrypted with the same per-client
// path. Empty input stays empty (no encryption of zero bytes).
$_otp_secret_plain = trim((string)($_POST['otp_secret'] ?? ''));
$_note_plain       = trim((string)($_POST['note'] ?? ''));
$otp_secret = $_otp_secret_plain === ''
    ? ''
    : mysqli_real_escape_string($mysqli, encryptCredentialEntry($_otp_secret_plain, $client_id ?? null));
$note = $_note_plain === ''
    ? ''
    : mysqli_real_escape_string($mysqli, encryptCredentialEntry($_note_plain, $client_id ?? null));
$favorite = intval($_POST['favorite'] ?? 0);
$contact_id = intval($_POST['contact'] ?? 0);
$asset_id = intval($_POST['asset'] ?? 0);
