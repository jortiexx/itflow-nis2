<?php

if (!function_exists('buildAssetAutocompleteJson')) {
    function buildAssetAutocompleteJson($mysqli, string $column): string {
        static $allowed = ['asset_make', 'asset_model', 'asset_os'];
        if (!in_array($column, $allowed, true)) {
            return '[]';
        }
        $sql = mysqli_query($mysqli,
            "SELECT DISTINCT $column AS label
             FROM assets
             WHERE asset_archived_at IS NULL
               AND $column != ''
               AND $column IS NOT NULL
             ORDER BY $column ASC"
        );
        $arr = [];
        if ($sql) {
            while ($row = mysqli_fetch_assoc($sql)) {
                $label = $row['label'];
                $arr[] = ['label' => $label, 'value' => $label];
            }
        }
        return json_encode($arr, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }
}
