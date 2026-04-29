<?php
/*
 * File-storage helpers for phase 13.
 *
 *  - encryptFileAtRest($plaintext_bytes, $client_id) → encrypts with per-
 *    client master key (HKDF-expanded to 32 bytes) using AES-256-GCM and
 *    returns ['ciphertext' => ..., 'iv' => 12 bytes, 'tag' => 16 bytes].
 *
 *  - decryptFileAtRest($ciphertext, $iv, $tag, $client_id) → reverses,
 *    returns plaintext bytes or null on failure.
 *
 *  - fileHashSha256($plaintext_bytes) → 32 raw SHA-256 bytes.
 *
 *  - fileVerifyMimeMatchesExtension($tmp_path, $extension): true if the
 *    server-side detected MIME type is consistent with the claimed
 *    extension. Used at upload to reject mismatches (e.g. a renamed
 *    EXE pretending to be a PNG).
 *
 *  - fileLookupOrFail($file_id, $mysqli): array of file row + ACL check
 *    (current user must have a grant for file_client_id) or null.
 */

if (!function_exists('encryptFileAtRest')) {

    function encryptFileAtRest(#[\SensitiveParameter] string $plaintext, int $client_id, mysqli $mysqli): ?array
    {
        $client_id = intval($client_id);
        if ($client_id <= 0) return null;

        $client_master = function_exists('getClientMasterKeyViaGrant')
            ? getClientMasterKeyViaGrant($client_id, $mysqli)
            : null;
        if ($client_master === null) {
            $client_master = ensureClientMasterKey($client_id, $mysqli);
        }
        if ($client_master === null) {
            return null;
        }

        $key32 = expandMasterKeyToAes256($client_master);
        sodium_memzero($client_master);

        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt(
            $plaintext, 'aes-256-gcm', $key32,
            OPENSSL_RAW_DATA, $iv, $tag, '', 16
        );
        sodium_memzero($key32);
        if ($ct === false) {
            return null;
        }

        return ['ciphertext' => $ct, 'iv' => $iv, 'tag' => $tag];
    }

    function decryptFileAtRest(string $ciphertext, string $iv, string $tag, int $client_id, mysqli $mysqli): ?string
    {
        $client_id = intval($client_id);
        if (strlen($iv) !== 12 || strlen($tag) !== 16) return null;

        $client_master = function_exists('getClientMasterKeyViaGrant')
            ? getClientMasterKeyViaGrant($client_id, $mysqli)
            : null;
        if ($client_master === null) {
            $client_master = ensureClientMasterKey($client_id, $mysqli);
        }
        if ($client_master === null) {
            return null;
        }

        $key32 = expandMasterKeyToAes256($client_master);
        sodium_memzero($client_master);
        $pt = openssl_decrypt(
            $ciphertext, 'aes-256-gcm', $key32,
            OPENSSL_RAW_DATA, $iv, $tag
        );
        sodium_memzero($key32);
        return ($pt === false) ? null : $pt;
    }

    function fileHashSha256(string $plaintext): string
    {
        return hash('sha256', $plaintext, true);
    }

    /**
     * Map of safe (extension → expected MIME prefixes). The MIME is
     * detected with finfo on the server. We accept any of the listed
     * prefixes so vendors with slightly different MIME strings (e.g.
     * 'application/x-zip-compressed' vs 'application/zip') still pass.
     */
    function fileVerifyMimeMatchesExtension(string $tmp_path, string $extension): array
    {
        $extension = strtolower($extension);
        $detected = '';
        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) {
                $detected = (string) finfo_file($finfo, $tmp_path);
                finfo_close($finfo);
            }
        }
        if ($detected === '') {
            // Cannot verify; allow with a flag so caller can log.
            return ['ok' => true, 'detected' => null];
        }

        $allowlist = [
            'jpg'  => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png'  => ['image/png'],
            'gif'  => ['image/gif'],
            'webp' => ['image/webp'],
            'pdf'  => ['application/pdf'],
            'txt'  => ['text/plain'],
            'md'   => ['text/plain', 'text/markdown'],
            'doc'  => ['application/msword'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
            'odt'  => ['application/vnd.oasis.opendocument.text', 'application/zip'],
            'csv'  => ['text/csv', 'text/plain', 'application/csv'],
            'xls'  => ['application/vnd.ms-excel'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
            'ods'  => ['application/vnd.oasis.opendocument.spreadsheet', 'application/zip'],
            'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
            'odp'  => ['application/vnd.oasis.opendocument.presentation', 'application/zip'],
            'zip'  => ['application/zip', 'application/x-zip-compressed'],
            'tar'  => ['application/x-tar'],
            'gz'   => ['application/gzip', 'application/x-gzip'],
            'msg'  => ['application/vnd.ms-outlook', 'application/octet-stream', 'application/CDFV2'],
            'json' => ['application/json', 'text/plain'],
            'wav'  => ['audio/wav', 'audio/x-wav'],
            'mp3'  => ['audio/mpeg'],
            'ogg'  => ['audio/ogg', 'application/ogg'],
            'mov'  => ['video/quicktime'],
            'mp4'  => ['video/mp4'],
            'av1'  => ['video/av1', 'application/octet-stream'],
            'ovpn' => ['text/plain', 'application/octet-stream'],
            'cfg'  => ['text/plain', 'application/octet-stream'],
            'ps1'  => ['text/plain', 'application/octet-stream'],
            'vsdx' => ['application/zip', 'application/octet-stream'],
            'drawio' => ['application/octet-stream', 'text/xml', 'application/xml'],
            'pfx'  => ['application/x-pkcs12', 'application/octet-stream'],
            'pages' => ['application/zip', 'application/octet-stream'],
            'numbers' => ['application/zip', 'application/octet-stream'],
            'unf'  => ['application/octet-stream', 'text/plain'],
            'unifi' => ['application/octet-stream', 'text/plain'],
            'key'  => ['application/octet-stream', 'application/x-iwork-keynote-sffkey', 'application/zip', 'text/plain'],
            'bat'  => ['text/plain', 'application/x-bat', 'application/octet-stream'],
            'stk'  => ['application/octet-stream'],
            'swb'  => ['application/octet-stream'],
        ];

        if (!isset($allowlist[$extension])) {
            return ['ok' => false, 'detected' => $detected, 'reason' => 'extension not in allowlist'];
        }
        $expected = $allowlist[$extension];
        $ok = false;
        foreach ($expected as $prefix) {
            if (strncmp($detected, $prefix, strlen($prefix)) === 0) {
                $ok = true;
                break;
            }
        }
        return ['ok' => $ok, 'detected' => $detected, 'expected' => $expected];
    }
}
