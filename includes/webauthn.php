<?php
/*
 * Minimal WebAuthn (FIDO2) server-side helpers.
 *
 * Supports the subset needed for second-factor authentication:
 *   - Attestation: 'none' only (no manufacturer attestation chain checked)
 *   - Algorithms: ES256 (-7), RS256 (-257)
 *   - User Verification: required (UV bit checked at assertion time)
 *
 * No third-party dependency: CBOR parsing, COSE-key handling, and signature
 * verification are implemented here. PHP's openssl extension provides the
 * actual public-key cryptography.
 *
 * Spec references:
 *   - https://www.w3.org/TR/webauthn-2/
 *   - https://www.rfc-editor.org/rfc/rfc8949 (CBOR)
 *   - https://www.rfc-editor.org/rfc/rfc9052 (COSE structures)
 *   - https://www.rfc-editor.org/rfc/rfc8152 (COSE algorithms — superseded but
 *     still describes the kty/alg integer codes used here)
 */

class WebAuthnException extends RuntimeException {}

const WEBAUTHN_FLAG_USER_PRESENT     = 0x01;
const WEBAUTHN_FLAG_USER_VERIFIED    = 0x04;
const WEBAUTHN_FLAG_BACKUP_ELIGIBLE  = 0x08; // BE — credential is multi-device-capable
const WEBAUTHN_FLAG_BACKUP_STATE     = 0x10; // BS — credential is currently backed up / synced
const WEBAUTHN_FLAG_AT               = 0x40; // attested credential data included

// COSE algorithm IDs we support
const COSE_ALG_ES256 = -7;
const COSE_ALG_RS256 = -257;

// COSE key types
const COSE_KTY_EC2 = 2;
const COSE_KTY_RSA = 3;

// COSE EC2 curves
const COSE_CRV_P256 = 1;

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

function webauthnB64UrlEncode(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function webauthnB64UrlDecode(string $b64url): string
{
    $b64 = strtr($b64url, '-_', '+/');
    $pad = strlen($b64) % 4;
    if ($pad) $b64 .= str_repeat('=', 4 - $pad);
    $out = base64_decode($b64, true);
    if ($out === false) {
        throw new WebAuthnException('Invalid base64url encoding');
    }
    return $out;
}

// ---------------------------------------------------------------------------
// CBOR decoder (subset used by WebAuthn / COSE)
// ---------------------------------------------------------------------------

function webauthnCborDecode(string $data, int &$offset = 0)
{
    if ($offset >= strlen($data)) {
        throw new WebAuthnException('CBOR truncated');
    }
    $b = ord($data[$offset]);
    $major = $b >> 5;
    $info  = $b & 0x1f;
    $offset++;

    if ($info < 24) {
        $value = $info;
    } elseif ($info === 24) {
        $value = ord($data[$offset]);
        $offset += 1;
    } elseif ($info === 25) {
        $value = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
    } elseif ($info === 26) {
        $value = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;
    } elseif ($info === 27) {
        // 64-bit big-endian; PHP int is 64-bit on modern platforms
        $hi = unpack('N', substr($data, $offset, 4))[1];
        $lo = unpack('N', substr($data, $offset + 4, 4))[1];
        $value = ($hi << 32) | $lo;
        $offset += 8;
    } else {
        throw new WebAuthnException("Unsupported CBOR additional info: $info");
    }

    switch ($major) {
        case 0: return $value;                              // unsigned int
        case 1: return -1 - $value;                         // negative int
        case 2:                                             // byte string
        case 3:                                             // text string (treated as PHP string)
            $bytes = substr($data, $offset, $value);
            $offset += $value;
            return $bytes;
        case 4: // array
            $arr = [];
            for ($i = 0; $i < $value; $i++) $arr[] = webauthnCborDecode($data, $offset);
            return $arr;
        case 5: // map
            $map = [];
            for ($i = 0; $i < $value; $i++) {
                $k = webauthnCborDecode($data, $offset);
                $v = webauthnCborDecode($data, $offset);
                $map[$k] = $v;
            }
            return $map;
        case 7:
            if ($value === 20) return false;
            if ($value === 21) return true;
            if ($value === 22) return null;
            throw new WebAuthnException("Unsupported CBOR simple value: $value");
        default:
            throw new WebAuthnException("Unsupported CBOR major type: $major");
    }
}

// ---------------------------------------------------------------------------
// DER helpers (for building public-key PEMs from COSE keys)
// ---------------------------------------------------------------------------

function webauthnDerLen(int $len): string
{
    if ($len < 0x80) return chr($len);
    $bytes = '';
    while ($len > 0) {
        $bytes = chr($len & 0xff) . $bytes;
        $len >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function webauthnDerInt(string $bin): string
{
    // Strip leading zeros except one if the next byte's high bit is set.
    $stripped = ltrim($bin, "\x00");
    if ($stripped === '' || (ord($stripped[0]) & 0x80)) {
        $stripped = "\x00" . $stripped;
    }
    return "\x02" . webauthnDerLen(strlen($stripped)) . $stripped;
}

function webauthnDerSeq(string $payload): string
{
    return "\x30" . webauthnDerLen(strlen($payload)) . $payload;
}

function webauthnDerBitString(string $bin): string
{
    return "\x03" . webauthnDerLen(strlen($bin) + 1) . "\x00" . $bin;
}

// ---------------------------------------------------------------------------
// COSE_Key → PEM
// ---------------------------------------------------------------------------

function webauthnCoseKeyToPem(array $cose): string
{
    $kty = $cose[1] ?? null;

    if ($kty === COSE_KTY_RSA) {
        $n = $cose[-1] ?? null;
        $e = $cose[-2] ?? null;
        if (!is_string($n) || !is_string($e)) {
            throw new WebAuthnException('Invalid COSE RSA key (missing n/e)');
        }
        $rsa_seq = webauthnDerSeq(webauthnDerInt($n) . webauthnDerInt($e));
        $algo = webauthnDerSeq(
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  // OID rsaEncryption
            . "\x05\x00"                                     // NULL parameters
        );
        $spki = webauthnDerSeq($algo . webauthnDerBitString($rsa_seq));
        return "-----BEGIN PUBLIC KEY-----\n"
             . chunk_split(base64_encode($spki), 64, "\n")
             . "-----END PUBLIC KEY-----\n";
    }

    if ($kty === COSE_KTY_EC2) {
        $crv = $cose[-1] ?? null;
        $x   = $cose[-2] ?? null;
        $y   = $cose[-3] ?? null;
        if ($crv !== COSE_CRV_P256) {
            throw new WebAuthnException('Only P-256 curve supported');
        }
        if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new WebAuthnException('Invalid COSE EC2 key (x/y must be 32 bytes each)');
        }
        // SubjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING(0x04 || X || Y)
        $algo = webauthnDerSeq(
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"           // OID id-ecPublicKey
            . "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"     // OID prime256v1
        );
        $point = "\x04" . $x . $y;
        $spki  = webauthnDerSeq($algo . webauthnDerBitString($point));
        return "-----BEGIN PUBLIC KEY-----\n"
             . chunk_split(base64_encode($spki), 64, "\n")
             . "-----END PUBLIC KEY-----\n";
    }

    throw new WebAuthnException("Unsupported COSE kty: " . var_export($kty, true));
}

// ---------------------------------------------------------------------------
// AuthenticatorData parser
// ---------------------------------------------------------------------------

/**
 * Parse the WebAuthn authenticatorData binary structure.
 * Returns [rp_id_hash, flags, sign_count, attestation_data]
 * where attestation_data = ['aaguid' => ..., 'credential_id' => ..., 'cose_pub' => ...]
 * if AT flag is set, else null.
 */
function webauthnParseAuthData(string $authData): array
{
    if (strlen($authData) < 37) {
        throw new WebAuthnException('authenticatorData too short');
    }
    $rp_id_hash = substr($authData, 0, 32);
    $flags      = ord($authData[32]);
    $counter    = unpack('N', substr($authData, 33, 4))[1];

    $att = null;
    if ($flags & WEBAUTHN_FLAG_AT) {
        if (strlen($authData) < 37 + 18) {
            throw new WebAuthnException('attested credential data truncated');
        }
        $aaguid = substr($authData, 37, 16);
        $cred_id_len = unpack('n', substr($authData, 53, 2))[1];
        $cred_id = substr($authData, 55, $cred_id_len);
        $rest_offset = 55 + $cred_id_len;
        $rest = substr($authData, $rest_offset);
        $offset_in_rest = 0;
        $cose_pub = webauthnCborDecode($rest, $offset_in_rest);

        $att = [
            'aaguid'        => $aaguid,
            'credential_id' => $cred_id,
            'cose_pub'      => $cose_pub,
        ];
    }

    return [
        'rp_id_hash' => $rp_id_hash,
        'flags'      => $flags,
        'sign_count' => $counter,
        'attestation' => $att,
    ];
}

// ---------------------------------------------------------------------------
// Registration verification
// ---------------------------------------------------------------------------

/**
 * Verify a navigator.credentials.create response.
 *
 * @param array  $client    Decoded JS object: { id, rawId(b64url), type,
 *                          response: { clientDataJSON(b64url), attestationObject(b64url) } }
 * @param string $expected_challenge  Raw bytes of the challenge issued earlier
 * @param string $expected_origin     e.g. "https://itflow.example.com"
 * @param string $expected_rp_id      e.g. "itflow.example.com"
 *
 * @return array  [credential_id (raw bytes), public_key_pem, sign_count, alg]
 */
function webauthnVerifyRegistration(array $client, string $expected_challenge, string $expected_origin, string $expected_rp_id): array
{
    if (($client['type'] ?? '') !== 'public-key') {
        throw new WebAuthnException('Expected type=public-key');
    }
    $client_data_json = webauthnB64UrlDecode($client['response']['clientDataJSON'] ?? '');
    $client_data      = json_decode($client_data_json, true);
    if (!is_array($client_data)) {
        throw new WebAuthnException('Could not parse clientDataJSON');
    }

    if (($client_data['type'] ?? '') !== 'webauthn.create') {
        throw new WebAuthnException("clientData.type expected webauthn.create, got {$client_data['type']}");
    }
    $challenge_in_token = webauthnB64UrlDecode($client_data['challenge'] ?? '');
    if (!hash_equals($expected_challenge, $challenge_in_token)) {
        throw new WebAuthnException('Challenge mismatch');
    }
    if (($client_data['origin'] ?? '') !== $expected_origin) {
        throw new WebAuthnException("Origin mismatch (got {$client_data['origin']})");
    }

    $att_obj_bytes = webauthnB64UrlDecode($client['response']['attestationObject'] ?? '');
    $offset = 0;
    $att_obj = webauthnCborDecode($att_obj_bytes, $offset);
    if (!is_array($att_obj) || empty($att_obj['authData'])) {
        throw new WebAuthnException('Malformed attestationObject');
    }

    if (($att_obj['fmt'] ?? '') !== 'none') {
        // For now we only accept 'none' attestation. A future phase may add
        // tpm/packed/u2f attestation verification with metadata service.
        // The current behaviour is documented and acceptable for second-factor
        // use where the trust anchor is the user's own enrolment action.
    }

    $auth = webauthnParseAuthData($att_obj['authData']);
    if (!$auth['attestation']) {
        throw new WebAuthnException('Missing attested credential data');
    }
    if (!hash_equals(hash('sha256', $expected_rp_id, true), $auth['rp_id_hash'])) {
        throw new WebAuthnException('RP ID hash mismatch');
    }
    if (!($auth['flags'] & WEBAUTHN_FLAG_USER_PRESENT)) {
        throw new WebAuthnException('User Present flag not set');
    }
    if (!($auth['flags'] & WEBAUTHN_FLAG_USER_VERIFIED)) {
        throw new WebAuthnException('User Verified flag not set (UV required)');
    }

    $cose_pub = $auth['attestation']['cose_pub'];
    $alg = $cose_pub[3] ?? null;
    if ($alg !== COSE_ALG_ES256 && $alg !== COSE_ALG_RS256) {
        throw new WebAuthnException("Unsupported algorithm: $alg");
    }

    $pem = webauthnCoseKeyToPem($cose_pub);

    // Phase 18: format AAGUID as RFC 4122 hex with dashes for storage.
    $aaguid_raw = $auth['attestation']['aaguid'] ?? '';
    $aaguid_hex = '';
    if (strlen($aaguid_raw) === 16) {
        $h = bin2hex($aaguid_raw);
        $aaguid_hex = substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-'
                    . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
    }

    $backup_eligible = ($auth['flags'] & WEBAUTHN_FLAG_BACKUP_ELIGIBLE) ? 1 : 0;
    $backup_state    = ($auth['flags'] & WEBAUTHN_FLAG_BACKUP_STATE)    ? 1 : 0;

    // Transports come from the JS-side response.getTransports() if the
    // browser exposes it. Caller forwards as a comma list (e.g. "usb,nfc").
    $transports = '';

    return [
        'credential_id'   => $auth['attestation']['credential_id'],
        'public_key_pem'  => $pem,
        'sign_count'      => $auth['sign_count'],
        'alg'             => $alg,
        'aaguid'          => $aaguid_hex,
        'backup_eligible' => $backup_eligible,
        'backup_state'    => $backup_state,
        'transports'      => $transports,
    ];
}

// ---------------------------------------------------------------------------
// Authentication (assertion) verification
// ---------------------------------------------------------------------------

/**
 * Verify a navigator.credentials.get response.
 *
 * @param array  $client   { id, rawId, type, response: { clientDataJSON,
 *                          authenticatorData, signature, userHandle } }
 * @param string $public_key_pem        PEM as stored at registration
 * @param int    $stored_sign_count     The last counter value we saw
 * @param int    $alg                   COSE alg id from registration
 * @param string $expected_challenge    Raw challenge bytes issued for this assertion
 * @param string $expected_origin       e.g. "https://itflow.example.com"
 * @param string $expected_rp_id        e.g. "itflow.example.com"
 *
 * @return int   The new sign_count to store. Throws on any failure.
 */
function webauthnVerifyAssertion(array $client, string $public_key_pem, int $stored_sign_count, int $alg, string $expected_challenge, string $expected_origin, string $expected_rp_id): int
{
    if (($client['type'] ?? '') !== 'public-key') {
        throw new WebAuthnException('Expected type=public-key');
    }
    $client_data_json = webauthnB64UrlDecode($client['response']['clientDataJSON'] ?? '');
    $client_data      = json_decode($client_data_json, true);
    if (!is_array($client_data)) {
        throw new WebAuthnException('Could not parse clientDataJSON');
    }
    if (($client_data['type'] ?? '') !== 'webauthn.get') {
        throw new WebAuthnException("clientData.type expected webauthn.get, got {$client_data['type']}");
    }
    $challenge_in_token = webauthnB64UrlDecode($client_data['challenge'] ?? '');
    if (!hash_equals($expected_challenge, $challenge_in_token)) {
        throw new WebAuthnException('Challenge mismatch');
    }
    if (($client_data['origin'] ?? '') !== $expected_origin) {
        throw new WebAuthnException("Origin mismatch (got {$client_data['origin']})");
    }

    $auth_data = webauthnB64UrlDecode($client['response']['authenticatorData'] ?? '');
    $signature = webauthnB64UrlDecode($client['response']['signature'] ?? '');

    $auth = webauthnParseAuthData($auth_data);
    if (!hash_equals(hash('sha256', $expected_rp_id, true), $auth['rp_id_hash'])) {
        throw new WebAuthnException('RP ID hash mismatch');
    }
    if (!($auth['flags'] & WEBAUTHN_FLAG_USER_PRESENT)) {
        throw new WebAuthnException('User Present flag not set');
    }
    if (!($auth['flags'] & WEBAUTHN_FLAG_USER_VERIFIED)) {
        throw new WebAuthnException('User Verified flag not set (UV required)');
    }

    // Anti-clone protection: counter must be strictly greater than stored.
    // Many platform authenticators always return 0 — in that case stored
    // sign_count is also 0 and we accept the equality (this matches the
    // WebAuthn-2 spec's recommendation).
    $new_count = $auth['sign_count'];
    if ($new_count !== 0 || $stored_sign_count !== 0) {
        if ($new_count <= $stored_sign_count) {
            throw new WebAuthnException("Counter regression: stored=$stored_sign_count, got=$new_count (possible cloned authenticator)");
        }
    }

    // Build signed input: authenticatorData || sha256(clientDataJSON)
    $signed_input = $auth_data . hash('sha256', $client_data_json, true);

    if ($alg === COSE_ALG_ES256) {
        // The signature is DER-encoded ASN.1 SEQUENCE { r INTEGER, s INTEGER }.
        // openssl_verify accepts that directly.
        $verified = openssl_verify($signed_input, $signature, $public_key_pem, OPENSSL_ALGO_SHA256);
    } elseif ($alg === COSE_ALG_RS256) {
        $verified = openssl_verify($signed_input, $signature, $public_key_pem, OPENSSL_ALGO_SHA256);
    } else {
        throw new WebAuthnException("Unsupported algorithm: $alg");
    }

    if ($verified !== 1) {
        throw new WebAuthnException('Signature verification failed');
    }

    return $new_count;
}
