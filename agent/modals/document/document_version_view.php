<?php

require_once '../../../includes/modal_header.php';

// Initialize the HTML Purifier to prevent XSS
require_once "../../../plugins/htmlpurifier/HTMLPurifier.standalone.php";

$purifier_config = HTMLPurifier_Config::createDefault();
$purifier_config->set('Cache.DefinitionImpl', null); // Disable cache by setting a non-existent directory or an invalid one
$purifier_config->set('URI.AllowedSchemes', ['data' => true, 'src' => true, 'http' => true, 'https' => true]);
$purifier = new HTMLPurifier($purifier_config);

$document_version_id = intval($_GET['id']);

$sql = mysqli_query($mysqli,
    "SELECT document_versions.*, documents.document_client_id
     FROM document_versions
     LEFT JOIN documents ON documents.document_id = document_versions.document_version_document_id
     WHERE document_version_id = $document_version_id LIMIT 1");

$row = mysqli_fetch_assoc($sql);
$document_version_name = nullable_htmlentities($row['document_version_name']);
$document_client_id = intval($row['document_client_id'] ?? 0);
// Transitional: tolerates legacy v3 rows from the brief phase-13C window.
$document_version_content = $purifier->purify(decryptOptionalField($row['document_version_content'], $document_client_id));


// Generate the HTML form content using output buffering.
ob_start();
?>

<div class="modal-header bg-dark">
    <h5 class="modal-title text-white"><i class="fa fa-fw fa-file-alt mr-2"></i><?php echo $document_version_name; ?></h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<div class="modal-body prettyContent">
    <?php echo $document_version_content; ?>
</div>

<script src="../js/pretty_content.js"></script>

<?php
require_once '../../../includes/modal_footer.php';
