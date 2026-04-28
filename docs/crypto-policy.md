# Cryptographic Policy

This document defines the cryptographic algorithms, key lifecycle, and review cadence used by this ITFlow fork. It exists to satisfy NIS2 Article 21(2)(h) ("policies and procedures regarding the use of cryptography and, where appropriate, encryption") and to give operators a single reference document for compliance audits.

## Approved algorithms

| Purpose | Algorithm | Parameters | Source library |
|---------|-----------|------------|----------------|
| Symmetric encryption (data at rest) | AES-256-GCM | 96-bit IV, 128-bit auth tag | OpenSSL |
| Password-based key derivation | Argon2id | Interactive: opslimit=2, memlimit=64 MiB. Tunable per deployment. | libsodium |
| Hash function | SHA-256 | — | OpenSSL |
| Random number generation | CSPRNG via `random_bytes()` | — | PHP core |
| WebAuthn assertion verification | ECDSA P-256 / Ed25519 / RS256 | Per FIDO2 spec | `web-auth/webauthn-lib` |
| WebAuthn PRF derivation | HMAC-SHA256 (per WebAuthn spec) | 32-byte salt | Authenticator |

## Prohibited algorithms

| Algorithm | Reason |
|-----------|--------|
| AES-CBC without MAC | Not authenticated; padding-oracle exposure |
| AES-128 (any mode) for new ciphertexts | Insufficient key size for new data; legacy decrypt only |
| PBKDF2 with fewer than 600 000 iterations | Below current OWASP minimum |
| MD5, SHA-1 | Collision-broken |
| 3DES, Blowfish, RC4 | Deprecated |
| DES, ECB mode | Insecure |

The legacy AES-128-CBC + PBKDF2-100k decryption path is retained solely for reading data written by upstream ITFlow before migration. New writes must use the approved algorithms above.

## Ciphertext format

All ciphertexts written by this fork follow this layout:

```
+----------+----------+--------+-----------+--------+
| ver (1)  | alg (1)  | IV (12)| ciphertext| tag(16)|
+----------+----------+--------+-----------+--------+
```

- `ver = 0x02` — fork's encryption version 2 (upstream is implicit "v1")
- `alg = 0x01` — AES-256-GCM
- IV: 12 random bytes per encryption operation, never reused with the same key
- Tag: 16 bytes (128-bit), verified during decryption

Decryption is version-aware. Blobs without the `0x02` prefix are decrypted via the legacy v1 path (AES-128-CBC + PBKDF2-100k) and re-encrypted on the next write.

## Key hierarchy

```
Vault unlock factor (WebAuthn PRF output OR Argon2id(PIN))
        |
        v
   User KEK (32 bytes, Argon2id-derived)
        |
        v
   Master key (16 bytes, shared across all agents — legacy carry-over)
        |
        v (HKDF-SHA256 expansion to 32 bytes)
        |
   AES-256-GCM key
        |
        v
   Stored credential ciphertexts
```

The master key is wrapped once per user with a per-user KEK derived from the user's vault-unlock factor. There is no single key-encryption key stored on disk in plaintext.

The master key remains 16 bytes for backward compatibility with v1 ciphertexts. AES-256-GCM operations use an HKDF-SHA256-expanded 32-byte key derived from the same master key. The cipher is AES-256-GCM; input keying material has 128-bit entropy. A future phase may regenerate the master key as a fresh 32-byte value, requiring a one-time re-encryption pass.

## Key lifecycle

### Generation

- Master key: generated once during setup. Persisted only in encrypted form (wrapped per user).
- Per-user KEK: derived at unlock time via Argon2id, never stored.
- Per-encryption IVs: `random_bytes(12)` per operation, never reused with the same key.

### Storage

- Wrapped master key v1 (legacy): in `users.user_specific_encryption_ciphertext` (PBKDF2-SHA256 + AES-128-CBC).
- Wrapped master key v2: in `users.user_specific_encryption_ciphertext_v2` (Argon2id + AES-256-GCM).
- The v2 wrapping is generated lazily on first login per existing user.
- No keys ever logged.

### Rotation

- User-level rotation: triggered by password or vault PIN change. Re-wraps the master key under a new KEK; master key itself is unchanged.
- Master-key rotation: requires re-encryption of all stored credentials. No automated tooling in this fork; documented manual procedure available on request.

### Destruction

- On user deletion: corresponding row in `users` and `user_vault_unlock_methods` is hard-deleted, removing the wrapped master key for that user.
- On master-key destruction (catastrophic): the database is irrecoverable by design. This is the intended security property.

## Review cadence

- Algorithm choices reviewed annually against ENISA *Cryptographic Algorithms* publication and BSI TR-02102.
- Argon2id memory/time parameters re-tuned annually based on hardware progress.
- Any deviation from this policy in code requires sign-off recorded in the corresponding pull request.

## Compliance mapping

| NIS2 / Implementing Regulation 2024/2690 requirement | This fork |
|------------------------------------------------------|-----------|
| Art. 21(2)(h) — cryptographic policy | This document |
| UV §6.8 — state-of-the-art algorithms | AES-256-GCM, Argon2id |
| UV §6.8 — key lifecycle | Sections above |
| Art. 21(2)(j) — phishing-resistant MFA | WebAuthn (FIDO2) |
| Art. 21(2)(i) — federated identity / SSO | Entra ID OIDC |

## Operator responsibilities

This document covers the application-layer crypto. Operators remain responsible for:

- TLS termination and HSTS configuration on the web server.
- Database-at-rest encryption (filesystem-level or cloud-provider-managed).
- Backup encryption and integrity protection.
- Hosting environment hardening (OS patches, firewall, IAM).
- Access reviews of agent accounts and SSO group mappings.
