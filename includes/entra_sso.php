<?php
/*
 * Microsoft Entra ID (Azure AD) OIDC helpers for the agent SSO flow.
 *
 * Implements:
 *  - PKCE generation (S256)
 *  - Authorization URL construction
 *  - Authorization-code → token exchange (HTTPS POST)
 *  - ID token validation: RS256 signature against tenant JWKS, plus the
 *    standard OIDC claim checks (iss, aud, tid, exp, nbf, iat, nonce)
 *  - JWKS caching to disk (24h TTL)
 *
 * No third-party JWT library: PHP's openssl extension provides RS256
 * verification natively. Keeping this hand-rolled avoids pulling a
 * composer dependency into a project that does not currently use one.
 *
 * References:
 *  - https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow
 *  - https://learn.microsoft.com/entra/identity-platform/id-token-claims-reference
 *  - https://www.rfc-editor.org/rfc/rfc7519 (JWT)
 *  - https://www.rfc-editor.org/rfc/rfc7517 (JWK)
 *  - https://www.rfc-editor.org/rfc/rfc7636 (PKCE)
 */

const ENTRA_JWKS_CACHE_TTL = 86400; // 24 hours
const ENTRA_TOKEN_CLOCK_SKEW = 120; // ±2 minutes tolerance on exp/nbf/iat

class EntraSsoException extends RuntimeException {}

function entraBase64UrlEncode(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function entraBase64UrlDecode(string $b64url): string
{
    $b64 = strtr($b64url, '-_', '+/');
    $pad = strlen($b64) % 4;
    if ($pad) {
        $b64 .= str_repeat('=', 4 - $pad);
    }
    $out = base64_decode($b64, true);
    if ($out === false) {
        throw new EntraSsoException('Invalid base64url encoding');
    }
    return $out;
}

function entraGeneratePkcePair(): array
{
    $verifier  = entraBase64UrlEncode(random_bytes(32));
    $challenge = entraBase64UrlEncode(hash('sha256', $verifier, true));
    return ['verifier' => $verifier, 'challenge' => $challenge];
}

// OIDC scopes plus Microsoft Graph User.Read so the access_token issued
// can call /v1.0/me/checkMemberGroups. User.Read is one of the most
// basic Graph delegated permissions; it's auto-included on newly
// registered apps and requires only user-level consent. Needed for the
// group-gated JIT-provisioning check in phase 19.
const ENTRA_SSO_SCOPES = 'openid profile email User.Read';

function entraAuthorizationUrl(string $tenant_id, string $client_id, string $redirect_uri, string $state, string $nonce, string $pkce_challenge): string
{
    $params = [
        'client_id'             => $client_id,
        'response_type'         => 'code',
        'redirect_uri'          => $redirect_uri,
        'response_mode'         => 'query',
        'scope'                 => ENTRA_SSO_SCOPES,
        'state'                 => $state,
        'nonce'                 => $nonce,
        'code_challenge'        => $pkce_challenge,
        'code_challenge_method' => 'S256',
        'prompt'                => 'select_account',
    ];
    return "https://login.microsoftonline.com/" . rawurlencode($tenant_id)
        . "/oauth2/v2.0/authorize?" . http_build_query($params);
}

function entraExchangeCodeForTokens(string $tenant_id, string $client_id, string $client_secret, string $redirect_uri, string $code, string $pkce_verifier): array
{
    $token_url = "https://login.microsoftonline.com/" . rawurlencode($tenant_id) . "/oauth2/v2.0/token";

    $body = http_build_query([
        'client_id'     => $client_id,
        'scope'         => ENTRA_SSO_SCOPES,
        'code'          => $code,
        'redirect_uri'  => $redirect_uri,
        'grant_type'    => 'authorization_code',
        'client_secret' => $client_secret,
        'code_verifier' => $pkce_verifier,
    ]);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $token_url,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false) {
        throw new EntraSsoException("Token endpoint request failed: $err");
    }

    $resp = json_decode($raw, true);
    if (!is_array($resp)) {
        throw new EntraSsoException("Token endpoint returned non-JSON response");
    }
    if ($http_code !== 200 || isset($resp['error'])) {
        $err = $resp['error_description'] ?? $resp['error'] ?? "HTTP $http_code";
        throw new EntraSsoException("Token exchange failed: $err");
    }
    if (empty($resp['id_token'])) {
        throw new EntraSsoException("Token response missing id_token");
    }
    return $resp;
}

function entraJwksCachePath(string $tenant_id): string
{
    $cache_dir = sys_get_temp_dir() . '/itflow_entra_jwks';
    if (!is_dir($cache_dir)) {
        @mkdir($cache_dir, 0700, true);
    }
    return $cache_dir . '/' . hash('sha256', $tenant_id) . '.json';
}

function entraFetchJwks(string $tenant_id): array
{
    $cache_path = entraJwksCachePath($tenant_id);
    if (is_file($cache_path) && (time() - filemtime($cache_path)) < ENTRA_JWKS_CACHE_TTL) {
        $cached = @file_get_contents($cache_path);
        if ($cached !== false) {
            $decoded = json_decode($cached, true);
            if (is_array($decoded) && isset($decoded['keys'])) {
                return $decoded;
            }
        }
    }

    // Fetch the discovery document to learn the jwks_uri (it varies by tenant config)
    $discovery_url = "https://login.microsoftonline.com/" . rawurlencode($tenant_id) . "/v2.0/.well-known/openid-configuration";
    $discovery_raw = entraHttpGet($discovery_url);
    $discovery = json_decode($discovery_raw, true);
    if (!is_array($discovery) || empty($discovery['jwks_uri'])) {
        throw new EntraSsoException("Could not retrieve OIDC discovery document");
    }

    $jwks_raw = entraHttpGet($discovery['jwks_uri']);
    $jwks = json_decode($jwks_raw, true);
    if (!is_array($jwks) || empty($jwks['keys'])) {
        throw new EntraSsoException("JWKS endpoint returned no keys");
    }

    @file_put_contents($cache_path, $jwks_raw);
    return $jwks;
}

function entraHttpGet(string $url): string
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false || $http_code !== 200) {
        throw new EntraSsoException("HTTP GET $url failed: " . ($err ?: "HTTP $http_code"));
    }
    return $raw;
}

/**
 * Construct an OpenSSL-compatible PEM public key from a JWK with kty=RSA.
 */
function entraJwkRsaToPem(array $jwk): string
{
    if (($jwk['kty'] ?? '') !== 'RSA' || empty($jwk['n']) || empty($jwk['e'])) {
        throw new EntraSsoException("Unsupported JWK (need RSA with n and e)");
    }
    $n = entraBase64UrlDecode($jwk['n']);
    $e = entraBase64UrlDecode($jwk['e']);

    // Build DER-encoded RSA public key (RFC 8017 Appendix A.1.1)
    $modulus = "\x00" . $n; // leading zero so it's interpreted as positive
    $modulus_der = entraDerInteger($modulus);
    $exponent_der = entraDerInteger($e);
    $rsa_seq = entraDerSequence($modulus_der . $exponent_der);

    // Wrap in SubjectPublicKeyInfo with rsaEncryption OID
    $algorithm = entraDerSequence(
        "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" // OID 1.2.840.113549.1.1.1
        . "\x05\x00" // NULL
    );
    $bitstring = "\x03" . entraDerLength(strlen($rsa_seq) + 1) . "\x00" . $rsa_seq;
    $spki = entraDerSequence($algorithm . $bitstring);

    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    return $pem;
}

function entraDerInteger(string $bin): string
{
    return "\x02" . entraDerLength(strlen($bin)) . $bin;
}

function entraDerSequence(string $payload): string
{
    return "\x30" . entraDerLength(strlen($payload)) . $payload;
}

function entraDerLength(int $len): string
{
    if ($len < 0x80) {
        return chr($len);
    }
    $bytes = '';
    while ($len > 0) {
        $bytes = chr($len & 0xff) . $bytes;
        $len >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

/**
 * Validate an Entra ID-issued ID token and return its claims.
 *
 * @throws EntraSsoException on any signature, claim, or structural failure.
 */
function entraValidateIdToken(string $id_token, string $tenant_id, string $client_id, string $expected_nonce): array
{
    $parts = explode('.', $id_token);
    if (count($parts) !== 3) {
        throw new EntraSsoException("Malformed JWT (expected 3 parts)");
    }
    [$header_b64, $payload_b64, $signature_b64] = $parts;

    $header  = json_decode(entraBase64UrlDecode($header_b64), true);
    $payload = json_decode(entraBase64UrlDecode($payload_b64), true);
    $sig     = entraBase64UrlDecode($signature_b64);

    if (!is_array($header) || !is_array($payload)) {
        throw new EntraSsoException("Could not parse JWT header or payload");
    }
    if (($header['alg'] ?? '') !== 'RS256') {
        throw new EntraSsoException("Unsupported JWT algorithm: " . ($header['alg'] ?? 'none'));
    }
    if (empty($header['kid'])) {
        throw new EntraSsoException("JWT header missing kid");
    }

    $jwks = entraFetchJwks($tenant_id);
    $matching_key = null;
    foreach ($jwks['keys'] as $jwk) {
        if (($jwk['kid'] ?? '') === $header['kid']) {
            $matching_key = $jwk;
            break;
        }
    }
    if (!$matching_key) {
        // Possibly a key rotation; refetch ignoring cache once
        @unlink(entraJwksCachePath($tenant_id));
        $jwks = entraFetchJwks($tenant_id);
        foreach ($jwks['keys'] as $jwk) {
            if (($jwk['kid'] ?? '') === $header['kid']) {
                $matching_key = $jwk;
                break;
            }
        }
    }
    if (!$matching_key) {
        throw new EntraSsoException("JWT kid {$header['kid']} not found in tenant JWKS");
    }

    $pem = entraJwkRsaToPem($matching_key);
    $signed_input = $header_b64 . '.' . $payload_b64;
    $verified = openssl_verify($signed_input, $sig, $pem, OPENSSL_ALGO_SHA256);
    if ($verified !== 1) {
        throw new EntraSsoException("JWT signature verification failed");
    }

    // Claim validation
    $now = time();
    $expected_iss = "https://login.microsoftonline.com/$tenant_id/v2.0";
    if (($payload['iss'] ?? '') !== $expected_iss) {
        throw new EntraSsoException("Unexpected issuer: " . ($payload['iss'] ?? '(missing)'));
    }
    if (($payload['aud'] ?? '') !== $client_id) {
        throw new EntraSsoException("Audience mismatch: " . ($payload['aud'] ?? '(missing)'));
    }
    if (($payload['tid'] ?? '') !== $tenant_id) {
        throw new EntraSsoException("Tenant ID mismatch: " . ($payload['tid'] ?? '(missing)'));
    }
    if (!isset($payload['exp']) || $payload['exp'] + ENTRA_TOKEN_CLOCK_SKEW < $now) {
        throw new EntraSsoException("Token expired");
    }
    if (isset($payload['nbf']) && $payload['nbf'] - ENTRA_TOKEN_CLOCK_SKEW > $now) {
        throw new EntraSsoException("Token not yet valid");
    }
    if (isset($payload['iat']) && $payload['iat'] - ENTRA_TOKEN_CLOCK_SKEW > $now) {
        throw new EntraSsoException("Token issued in the future");
    }
    if (!isset($payload['nonce']) || !hash_equals($expected_nonce, (string)$payload['nonce'])) {
        throw new EntraSsoException("Nonce mismatch");
    }
    if (empty($payload['oid'])) {
        throw new EntraSsoException("Token missing oid claim");
    }

    return $payload;
}

/**
 * Group-gated JIT provisioning helper.
 *
 * POSTs to Microsoft Graph /v1.0/me/checkMemberGroups with the configured
 * group object ID and returns true if the signed-in user is a member
 * (direct or transitive). The endpoint correctly handles nested-group
 * membership without us having to walk the hierarchy. Requires the
 * access_token to have been issued with the User.Read delegated scope
 * (configured in ENTRA_SSO_SCOPES above).
 *
 * Throws EntraSsoException on transport / auth failure so the caller can
 * distinguish "user is not in the group" (returns false) from "we
 * couldn't verify" (throws). The callback treats both as ssoFail but
 * with different reason strings for the audit log.
 */
function entraCheckGroupMembership(string $access_token, string $required_group_id): bool
{
    $url  = 'https://graph.microsoft.com/v1.0/me/checkMemberGroups';
    $body = json_encode(['groupIds' => [$required_group_id]], JSON_UNESCAPED_SLASHES);
    if ($body === false) {
        throw new EntraSsoException('Failed to encode checkMemberGroups body');
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $access_token,
            'Content-Type: application/json',
            'Accept: application/json',
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $raw       = curl_exec($ch);
    $err       = curl_error($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false) {
        throw new EntraSsoException("Graph checkMemberGroups request failed: $err");
    }
    if ($http_code !== 200) {
        $hint = '';
        $decoded = json_decode($raw, true);
        if (is_array($decoded) && isset($decoded['error']['message'])) {
            $hint = ' — ' . $decoded['error']['message'];
        }
        throw new EntraSsoException("Graph checkMemberGroups returned HTTP $http_code$hint");
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !isset($decoded['value']) || !is_array($decoded['value'])) {
        throw new EntraSsoException('Graph checkMemberGroups returned malformed response');
    }

    return in_array($required_group_id, $decoded['value'], true);
}
