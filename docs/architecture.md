# Architecture — identity, vault unlock, credential decryption

This document describes how an agent goes from "I'm at my desk" to "I can read a stored client password" in this NIS2-aligned fork. It is intended for operators, auditors, and developers who need to reason about which factor controls what.

The reference flow assumes Phase 7 enrolment (Entra ID SSO + WebAuthn PRF + vault PIN as fallback). Other combinations (password-only, SSO + PIN, etc.) are subsets of the same layering.

## Layer diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 0 — Device identity                                           │
│   Windows / macOS login + biometric or PIN                          │
│   Establishes a hardware-bound Primary Refresh Token (PRT) with     │
│   Microsoft Entra ID. The OS knows who is at the keyboard.          │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ PRT
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 1 — Federated identity (NIS2 Art. 21(2)(i))                   │
│   Microsoft Entra ID OIDC                                           │
│     - Authorization code flow with PKCE                             │
│     - State + nonce CSRF protection                                 │
│     - ID token (RS256) validated against tenant JWKS                │
│     - Tenant-restricted issuer + audience + tid claim checks        │
│   Output: id_token with immutable `oid` claim                       │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ id_token
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 2 — ITFlow session                                            │
│   agent/login_entra_callback.php                                    │
│     - Verifies signature + claims                                   │
│     - Maps `oid` → ITFlow user_id (immutable binding)               │
│     - session_regenerate_id(true)                                   │
│   Output: $_SESSION = { user_id, logged=true, csrf_token }          │
│   Vault is locked: no master key in session yet.                    │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ authenticated, vault locked
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3 — Vault unlock (NIS2 Art. 21(2)(h))                         │
│   agent/vault_unlock.php picks the strongest enrolled method:       │
│                                                                     │
│   Primary: WebAuthn PRF (Phase 7)                                   │
│     - Challenge issued, evalByCredential maps credential→PRF salt   │
│     - Browser does one assertion ceremony                           │
│     - Authenticator returns signature + 32-byte PRF output          │
│     - Server verifies signature against stored public key           │
│     - KEK = HKDF-SHA256(PRF output, "itflow-vault-prf-v1")          │
│                                                                     │
│   Fallback: Vault PIN (Phase 3)                                     │
│     - User types PIN (≥ 8 chars)                                    │
│     - KEK = Argon2id(PIN, salt) via libsodium INTERACTIVE preset    │
│                                                                     │
│   Either way: master_key = AES-256-GCM-decrypt(wrapped_master, KEK) │
│   Then: generateUserSessionKey(master_key)                          │
│     - Random session_key generated                                  │
│     - Session ciphertext stored in $_SESSION                        │
│     - session_key set as HttpOnly cookie                            │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ master key wrapped under session key
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4 — Credential decryption                                     │
│   decryptCredentialEntry($stored_blob)                              │
│     - Reads session_key from cookie                                 │
│     - Decrypts session ciphertext → master key                      │
│     - For "v2:..." stored credentials: AES-256-GCM with             │
│       HKDF-expanded master key                                      │
│     - For legacy credentials: AES-128-CBC with raw master key       │
│   Output: cleartext credential password                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Who controls what

| Layer | Trust anchor | Compromise impact |
|-------|--------------|-------------------|
| 0 — Device | OS + TPM + Entra device join | Attacker at the unlocked workstation reaches Layer 1 silently |
| 1 — Entra | Microsoft Entra tenant policies, conditional access, sign-in risk | Entra outage blocks new logins; tenant takeover yields ITFlow accounts |
| 2 — ITFlow session | Server-side session, regenerated on privilege transitions | Session hijack via XSS impersonates the agent **but** vault stays locked |
| 3 — Vault unlock | PRF: hardware-bound key. PIN: Argon2id-protected secret | Without this, an attacker with Layer 2 cannot read any credential |
| 4 — Credential | Master key wrapping, AES-256-GCM AEAD | Even with DB dump, a tampered ciphertext fails the GCM auth tag |

## Defense in depth

The architecture composes independent factors so a single compromise does not yield credentials:

- **DB-only leak**: ciphertexts are present, but the master key is wrapped under either Argon2id(PIN) or HKDF(PRF). Argon2id is memory-hard; PRF output never appears in the DB. Both are computationally or physically infeasible to brute-force at scale.
- **Stolen unlocked workstation**: Layer 2 session is active, but Layer 3 still requires either touching a hardware authenticator (PRF) or knowing the vault PIN.
- **Phished SSO credentials**: Entra MFA + conditional access blocks issuance of an `id_token`. Even if an `id_token` were obtained out of band, Layer 3 PRF is origin-bound — phishing site cannot retrieve a usable PRF output.
- **Compromised ITFlow code (RCE)**: this is out of scope; full server compromise can read live session state. Mitigation is operational (host hardening, restricted admin access, monitoring).

## Persisted material per layer

| Where | What | Sensitive? |
|-------|------|------------|
| `users.user_password` | Bcrypt hash of password | Sensitive (offline attackable; modern bcrypt cost mitigates) |
| `users.user_specific_encryption_ciphertext` | v1 wrapped master key (legacy AES-128-CBC) | Yes — DB-leak threat |
| `users.user_specific_encryption_ciphertext_v2` | v2 wrapped master key (AES-256-GCM, Argon2id KEK) | Yes — DB-leak threat |
| `users.user_entra_oid` | Immutable Entra user GUID | Low — public-ish identifier |
| `user_vault_unlock_methods` | PIN: salt + wrapped master. PRF: credential id, public key, prf salt, wrapped master, sign counter | Yes — DB-leak threat |
| `user_webauthn_credentials` | 2FA WebAuthn credentials (cred id, public key, sign counter) | Public keys; not sensitive |
| `security_audit_log` | Hash-chained event log | Integrity-sensitive (chain breaks if rows are altered) |
| `settings.config_agent_sso_client_secret` | Entra OIDC client secret | Yes — server filesystem / DB leak threat |
| `$_SESSION` (filesystem) | Per-request session, includes wrapped master key after unlock | Yes — server filesystem leak |
| Cookie `user_encryption_session_key` | The session key that wraps the master in $_SESSION | Yes — XSS / network-layer threat |

## Audit chain

Every authentication, vault unlock, and method change emits an entry in `security_audit_log`. The `entry_hash = SHA256(prev_hash || canonical_json(fields))` is computed at write time. `scripts/audit_verify.php` walks the chain and reports inconsistencies. Operators are expected to:

1. Run the verifier from a daily cron with non-zero-exit alerting.
2. Periodically pin the latest `entry_hash` externally (SIEM, paper, cold storage). Any future tamper that does not also rewrite the externally-pinned hash is detectable.

## What is *not* in scope

- **Per-client compartmentalisation**: there is one master key for all stored credentials. A user with Layer 4 access reads any credential they have application-level access to. Future work item.
- **Admin-driven enrolment for JIT-only SSO agents**: an agent provisioned via Entra JIT cannot bootstrap a vault PIN themselves. Today the workaround is: temporary password + manual PIN setup → password disabled. Future work item.
- **Full server RCE**: not mitigated by this fork. Operators are responsible for OS-level hardening, restricted admin shells, and host monitoring.

## References

- NIS2 Directive (EU 2022/2555) — Article 21
- Implementing Regulation 2024/2690 — §6.8 Cryptography
- ENISA *Cryptographic Algorithms* — annual publication
- BSI TR-02102-1 — German baseline; Argon2id and AES-256-GCM aligned
- WebAuthn-2 spec — https://www.w3.org/TR/webauthn-2/
- WebAuthn PRF extension — https://www.w3.org/TR/webauthn-3/#prf-extension
