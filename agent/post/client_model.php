<?php
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$name = cleanInput($_POST['name']);
// Primary legal entity (client_entities); the trading name stays in $name
$entity_name = cleanInput($_POST['entity_name'] ?? '');
$entity_kvk = cleanInput($_POST['entity_kvk'] ?? '');
$entity_vat = cleanInput($_POST['entity_vat'] ?? '');
$entity_kvk = $entity_kvk === '' ? null : $entity_kvk;
$entity_vat = $entity_vat === '' ? null : $entity_vat;
$type = cleanInput($_POST['type']);
$website = preg_replace("(^https?://)", "", cleanInput($_POST['website']));
$referral = cleanInput($_POST['referral']);
$rate = floatval($_POST['rate'] ?? 0);
$net_terms = intval($_POST['net_terms'] ?? $config_default_net_terms);
$tax_id_number = cleanInput($_POST['tax_id_number'] ?? '');
$abbreviation = cleanInput($_POST['abbreviation'] ?? '');
if (empty($abbreviation)) {
    $abbreviation = shortenClient($name);
}
$notes = cleanInput($_POST['notes'] ?? '');
$lead = intval($_POST['lead'] ?? 0);
