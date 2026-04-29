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
$otp_secret = sanitizeInput($_POST['otp_secret']);
$note = sanitizeInput($_POST['note']);
$favorite = intval($_POST['favorite'] ?? 0);
$contact_id = intval($_POST['contact'] ?? 0);
$asset_id = intval($_POST['asset'] ?? 0);
