# Release notes — itflow-nis2 fork

This file tracks changes specific to this fork. The upstream `CHANGELOG.md` continues to track upstream releases as merged in.

## Unreleased — Phase 6: WebAuthn second factor

This phase adds phishing-resistant MFA via WebAuthn (FIDO2). Agents can register hardware security keys (YubiKey, platform passkeys, Touch ID, Windows Hello) and use them as a second factor instead of TOTP. Closes NIS2 Article 21(2)(j) for ITFlow's authentication path.

### Added
- `includes/webauthn.php` — hand-rolled WebAuthn server library (no composer dependency). Implements:
  - CBOR decoder (subset needed for COSE / attestation objects)
  - DER builders for SubjectPublicKeyInfo
  - COSE_Key → PEM conversion for both EC2 (P-256) and RSA
  - Authenticator data parser (flags, counter, attested credential data)
  - `webauthnVerifyRegistration()` — full registration validation: clientDataJSON challenge/origin/type, RP ID hash, UP/UV flags, supported algorithm. Attestation format `none`.
  - `webauthnVerifyAssertion()` — full assertion validation: signature against stored public key, challenge/origin checks, counter regression detection.
- `scripts/webauthn_self_test.php` — 15-test self-test covering CBOR primitives, COSE EC2 + RSA round-trips against fresh keypairs, end-to-end registration with synthetic attestation, end-to-end assertion verification, counter regression rejection, challenge mismatch rejection. All passing.
- `agent/user/webauthn_register_options.php` — issues PublicKeyCredentialCreationOptions JSON.
- `agent/user/webauthn_register_verify.php` — verifies the registration response and stores the credential (label, public key PEM, COSE alg, sign count).
- `agent/user/post/webauthn.php` — credential delete handler (CSRF-protected).
- `login_webauthn_options.php` — issues PublicKeyCredentialRequestOptions during the MFA step.
- `login_webauthn_verify.php` — verifies the assertion, regenerates the session id, sets up encryption session keys (mirrors the post-MFA branch of login.php), logs the event.
- `plugins/webauthn/webauthn-login.js` — small browser-side helper for the assertion ceremony. External file so the strict CSP on the login page allows it.
- New table `user_webauthn_credentials`.

### Changed
- `agent/user/user_security.php` — adds a "Security keys (WebAuthn)" card with credential list and registration form. The registration JS calls navigator.credentials.create() against the options endpoint, then POSTs the response to the verify endpoint.
- `login.php` — when a user reaches the MFA step and has at least one WebAuthn credential enrolled, a "Use security key" button is rendered alongside the TOTP code field. JavaScript loaded from `/plugins/webauthn/webauthn-login.js`.
- Database version: `2.4.4.4 → 2.4.4.5`.

### Schema
New table `user_webauthn_credentials`:
- `cred_id INT PRIMARY KEY`
- `user_id INT` (FK → users, ON DELETE CASCADE)
- `credential_id VARCHAR(512) UNIQUE` — base64url
- `public_key_pem TEXT` — converted from the COSE_Key the authenticator returned
- `cose_alg INT` — -7 (ES256) or -257 (RS256)
- `sign_count BIGINT UNSIGNED` — anti-clone counter
- `label VARCHAR(100)`, `created_at`, `last_used_at`

### Operator action required
1. Run the database migration: **Admin → Update → Update Database** or `php scripts/update_cli.php --update_db`.
2. Run the self-test: `php scripts/webauthn_self_test.php`.
3. Have agents enroll keys via **My Account → Security → Security keys (WebAuthn)**. They need a HTTPS deployment — WebAuthn refuses HTTP except on localhost.
4. Once enrolled, the next sign-in will offer "Use security key" alongside the TOTP code field.

### Security properties
- Phishing-resistant: the assertion is bound to the origin via clientDataJSON and the RP ID hash. Phishing sites cannot forward the assertion to the real site.
- Replay-resistant: each assertion uses a fresh server-issued challenge. Sign counter increases monotonically; regression rejected as a likely cloned authenticator.
- User Verification required: assertions where the UV bit is not set are rejected. This forces a PIN or biometric on the authenticator side.
- Transport: CBOR / COSE / signature checks all done server-side; the JS helper is purely transport.

### Known limitations
- Attestation is `none`. We trust the user's own enrolment action; we do not validate the authenticator's manufacturer chain. A future hardening step could require packed/tpm/u2f attestation against a metadata service.
- WebAuthn complements but does not replace TOTP — both flows remain available. Operators who want to enforce phishing-resistant MFA must remove TOTP enrolment for the relevant agents manually.
- WebAuthn is not yet wired into the SSO + vault unlock path (Phase 3 PIN remains the only vault unlock method). The user_vault_unlock_methods schema's PRF columns are still reserved for a future phase.

## v0.6.0-nis2-audit — Phase 5: Tamper-evident security audit log

This phase adds an append-only, hash-chained security audit log alongside the existing application logs. NIS2 Article 21(2)(b) (incident handling) and 21(2)(f) (effectiveness assessment) require evidence that security-relevant events have not been retroactively modified or deleted. The hash chain provides that evidence cryptographically.

### Added
- `includes/security_audit.php` — append-only audit log with SHA-256 hash chain. Each entry's hash covers `prev_hash || canonical_json(entry_fields)`, where the canonical form is a fixed-key-order JSON serialization. Concurrent inserts are serialized via `LOCK TABLES … WRITE` so the chain cannot fork.
- `scripts/audit_verify.php` — CLI verifier that walks the chain and reports any inconsistency. Exits non-zero on tampering. Supports `--from` / `--to` to bound the walk.
- `scripts/security_audit_self_test.php` — six-test offline self-test covering canonical serialization, hash chain consistency, tamper detection on a modified row, and chain breakage on a removed row. All passing.
- `admin/security_audit.php` — admin viewer with filter on `event_type` and `user_id`, paginated. Surfaces the latest entry hash so an operator can pin it externally for forensic anchoring.
- Sidebar entry under Settings → Security audit log.

### Schema (migration `2.4.4.3 → 2.4.4.4`)
New table `security_audit_log`:
- `log_id BIGINT PK`
- `event_time DATETIME(6)` — microsecond resolution
- `event_type VARCHAR(60)` — symbolic name (e.g. `login.password.success`, `vault.unlock.failed`)
- `user_id INT NULL` (no FK on purpose — audit retention may outlive user deletion)
- `target_type VARCHAR(50) NULL` / `target_id INT NULL` — what the event acted on
- `source_ip VARCHAR(45) NULL` / `user_agent VARCHAR(500) NULL`
- `metadata TEXT NULL` — JSON blob for event-specific details
- `prev_hash VARBINARY(32)` — hash of the previous entry (or zeros for the first)
- `entry_hash VARBINARY(32)` — `SHA256(prev_hash || canonical_json(fields))`

### Events instrumented
Currently emitted:

| Event | Where |
|-------|-------|
| `login.password.failed` | `login.php` (no user identified) |
| `login.password.success` | `login.php` (after password + optional MFA) |
| `login.mfa.failed` | `login.php` (TOTP verification failed) |
| `sso.login.failed` | `agent/login_entra_callback.php` (any failure mode) |
| `sso.login.success` | `agent/login_entra_callback.php` (post-validation, post-mapping) |
| `vault.unlock.success` | `agent/vault_unlock.php` (PIN accepted) |
| `vault.unlock.failed` | `agent/vault_unlock.php` (wrong PIN or method locked) |
| `vault.method.created` | `agent/user/post/vault_methods.php` (PIN set) |
| `vault.method.removed` | `agent/user/post/vault_methods.php` (method deleted) |

Credential read events are **not** audited by default — they would be too noisy for operational logs and the master key is already gated by session unlock. A future phase may add an opt-in mode for high-security deployments.

### Threat model

| Adversary | Outcome |
|-----------|---------|
| Application bug / accidental DBA edit on one row | Detected: row hash + downstream prev_hash both fail. |
| SQL injection that deletes a single row | Detected: chain breaks at the next row. |
| SQL injection that deletes the entire table | Trivially detectable — verifier walks zero entries. Pin the latest hash externally to detect this. |
| Full DB write access by a sophisticated attacker | **Not detected** — they can rebuild the chain end-to-end. The chain is only useful in combination with an external pinning of the latest hash (SIEM, paper, cold storage). |
| Read-only DB compromise | Hash chain unaffected; this phase does not alter confidentiality posture of the audit log itself. Future hardening could encrypt `metadata` at rest. |

### Operator action required
- Run the database migration: **Admin → Update → Update Database** or `php scripts/update_cli.php --update_db`.
- Verify the implementation:
  ```
  php scripts/security_audit_self_test.php
  ```
- After accumulating some events, walk the live chain:
  ```
  php scripts/audit_verify.php
  ```
- (Recommended) Set up a daily cron that runs the verifier and alerts on non-zero exit.
- (Recommended) Periodically pin the latest entry hash externally — the admin page surfaces it. Even a paper note in a safe is valuable: it creates a verifiable anchor for forensic timelines.

### NIS2 mapping (cumulative through Phase 5)

| Domain | Status |
|--------|--------|
| Algorithm choice (Art. 21(2)(h)) | ✅ AES-256-GCM, Argon2id |
| Crypto policy | ✅ |
| Vulnerability handling (Art. 21(2)(e)) | ✅ CI scans + SBOM |
| SSO (Art. 21(2)(i)) | ✅ Entra ID OIDC |
| Vault unlock for SSO users | ✅ PIN |
| Transport security | ✅ HSTS + headers + rate limits |
| Incident handling (Art. 21(2)(b)) | ✅ Tamper-evident audit log |
| Effectiveness assessment (Art. 21(2)(f)) | ✅ Verifier exit code drives alerting |
| MFA (Art. 21(2)(j)) | ⚠️ TOTP; WebAuthn deferred |

## v0.5.0-nis2-hardening — Phase 4: Operational hardening

This phase adds standard security response headers to every entry point, IP-based rate limiting on credential-style endpoints, and session-id rotation at the vault unlock privilege boundary. Phishing-resistant MFA via WebAuthn is reserved for a future phase to keep this release shippable.

### Added
- `includes/security_headers.php` — sets HSTS (when HTTPS is enforced), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and a Permissions-Policy that denies browser features ITFlow does not use. Verified to apply on `/login.php` against a live Apache instance.
- `includes/rate_limit.php` — `rateLimitCheck($log_type, $log_action, $max, $window_s)` consults the existing `logs` table, emits HTTP 429 + Retry-After when the threshold is exceeded, and writes a "Blocked" log entry. Reuses log entries the application already produces, so no separate buckets/cache.

### Changed
- `includes/session_init.php` — pulls in `security_headers.php`. This means every page that goes through `check_login.php` (which is virtually all authenticated pages) gets the headers automatically.
- `login.php`, `agent/login_entra.php`, `agent/login_entra_callback.php`, `agent/vault_unlock.php` — explicit `require_once` of `security_headers.php` since they do not load `check_login.php`.
- `agent/login_entra_callback.php` — calls `rateLimitCheck('SSO Login', 'Failed', 20, 600)` early in the handler. Twenty failed SSO attempts from the same IP in 10 minutes triggers HTTP 429.
- `agent/vault_unlock.php` — calls `rateLimitCheck('Vault', 'Unlock failed', 20, 600)` on POST. Twenty failed PIN attempts from the same IP in 10 minutes triggers HTTP 429. Per-method lockout from Phase 3 still applies (5 strikes / 15 min per user).
- `agent/vault_unlock.php` — successful PIN unlock now calls `session_regenerate_id(true)` and rotates the CSRF token, defending against session-fixation across the privilege transition from "logged in, vault locked" to "vault unlocked".

### Headers set on every page

| Header | Value |
|--------|-------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` (HTTPS only) |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Cross-Origin-Opener-Policy | `same-origin` |
| Cross-Origin-Resource-Policy | `same-origin` |
| Permissions-Policy | denies camera/microphone/usb/geolocation/etc; allows fullscreen+sync-xhr+webauthn-get only on self |

### Not changed
- Content-Security-Policy is intentionally left as-is. ITFlow uses inline scripts and event handlers throughout; a strict CSP would break the app. The login page retains its existing minimal CSP. Broader CSP rollout requires a refactor that is out of scope for this phase.
- `__Host-` cookie prefix is not applied. Migrating session cookies to a `__Host-` prefix would invalidate every existing session; out of scope.

### Operator action required
- No database migration in this phase.
- After deployment, verify the headers with curl (or a browser dev tools network panel):
  ```
  curl -sI https://your-itflow-host/login.php | grep -E '^(Strict-Transport|X-Frame|X-Content|Referrer|Cross-Origin|Permissions)'
  ```
  All five non-HSTS headers should be present on every page; HSTS only on HTTPS.

### NIS2 mapping (cumulative through Phase 4)

| Domain | Status |
|--------|--------|
| Algorithm choice (Art. 21(2)(h)) | ✅ AES-256-GCM, Argon2id |
| Crypto policy | ✅ `docs/crypto-policy.md` |
| Vulnerability handling (Art. 21(2)(e)) | ✅ CI security scans + SBOM |
| Toegangscontrole / SSO (Art. 21(2)(i)) | ✅ Entra ID OIDC for agents |
| Vault unlock for SSO users | ✅ PIN |
| Transport security (Art. 21(2)(d)) | ✅ HSTS, security headers, rate limits |
| MFA (Art. 21(2)(j)) | ⚠️ TOTP for password users; WebAuthn deferred |

## v0.4.0-nis2-vault — Phase 3: Vault unlock with PIN

This phase adds a vault PIN as an unlock method, letting SSO-authenticated agents decrypt stored credentials without their account password. WebAuthn PRF is reserved as a future unlock method type — the schema is forward-compatible and a later phase can add it without further migrations.

### Added
- `includes/vault_unlock.php` — vault unlock layer:
  - `vaultSetPin()` — wraps the master key under an Argon2id-derived KEK and stores it.
  - `vaultTryUnlockWithPin()` — verifies a PIN, returns the unwrapped master key on success. Increments `failed_attempts` on failure; locks the method for 15 minutes after 5 failed attempts.
  - `vaultListMethods()`, `vaultDeleteMethod()`, `vaultUserHasMethod()`, `vaultMasterKeyFromSession()`.
- `agent/vault_unlock.php` — PIN entry page for SSO-authenticated agents. After a successful PIN, calls `generateUserSessionKey()` so credential decryption works for the rest of the session.
- `agent/user/post/vault_methods.php` — POST handler for setting a PIN and removing methods. CSRF-protected. PIN ≥ 8 characters; mismatch and master-key-absence both return user-visible errors.
- `agent/user/user_security.php` — UI block listing enrolled vault unlock methods (with status, last-used, lock indicator) and a form to set or update the vault PIN. The PIN form is gated on the master key being present in the current session, so SSO-only sessions cannot set a PIN until the user signs in once with their account password.
- `scripts/vault_unlock_self_test.php` — five-test offline self-test covering PIN wrap/unwrap, wrong-PIN rejection, wrong-salt rejection, IV uniqueness, and tamper detection. All passing.

### Changed
- `agent/login_entra_callback.php` — after successful SSO, redirects to `/agent/vault_unlock.php` if the user has a PIN enrolled. Sessions without an enrolled method continue to the start page with the vault locked.
- Database version: `2.4.4.2 → 2.4.4.3`.

### Schema
New table `user_vault_unlock_methods`:
- `method_id INT PRIMARY KEY`
- `user_id INT` (FK → users, ON DELETE CASCADE)
- `method_type ENUM('pin','webauthn_prf')` — webauthn_prf reserved for a future phase
- `label`, `salt`, `wrapped_master_key`
- `credential_id`, `public_key`, `sign_count`, `prf_salt` — reserved for future WebAuthn PRF support; null for PIN methods
- `failed_attempts`, `locked_until` — rate-limit state
- `created_at`, `last_used_at`

### Operator action required
- Run the database migration: **Admin → Update → Update Database** or `php scripts/update_cli.php --update_db`.
- Run the self-tests:
  ```
  php scripts/crypto_self_test.php
  php scripts/entra_sso_self_test.php
  php scripts/vault_unlock_self_test.php
  ```

### Workflow

**For an existing agent who wants to use SSO + PIN going forward:**
1. Sign in once with the account password (this puts the master key in session).
2. Go to **My Account → Security → Vault unlock methods** and set a PIN.
3. From now on, sign in via Microsoft. After SSO succeeds, ITFlow asks for the PIN before showing any credential pages.

**For a JIT-provisioned SSO-only agent:**
- They have no password, so they cannot bootstrap a PIN themselves. An admin needs to create a temporary password, share it out-of-band, have the user log in once and set a PIN, then optionally delete the password.
- Phase 4+ may add an admin-driven enrollment flow that does not require a password round-trip.

### Security properties
- PIN is hashed with Argon2id (libsodium INTERACTIVE preset, 16-byte salt) before deriving the KEK. The PIN itself is never stored.
- Master key is wrapped under the PIN-KEK using AES-256-GCM (the same v2 stack as Phase 1).
- Failed PIN attempts are throttled per method: 5 strikes lock the method for 15 minutes. The user can still unlock via another enrolled method (when more methods exist).
- `generateUserSessionKey()` is called after a successful unlock, so the session-level wrapping (HttpOnly cookie + server-side ciphertext) is the same as for password-based logins. Existing credential decryption code paths are unchanged.
- The vault PIN is intentionally distinct from the account password. Users should not reuse them.

### Known limitations
- WebAuthn PRF (the planned hardware-bound unlock factor) is not implemented yet. Schema columns are reserved.
- Admin-driven enrollment for SSO-only users is not implemented.
- The password-login flow does not yet require a separate PIN unlock; password sign-in unlocks the vault as it always has. The PIN is purely additive.

## v0.3.0-nis2-sso — Phase 2: Microsoft Entra ID SSO for agents

This phase adds OIDC sign-in via Microsoft Entra ID (Azure AD) for agent users. The flow is implemented from scratch with security properties that the upstream client-portal Azure flow does not provide: PKCE, nonce, RS256 ID-token signature verification against the tenant JWKS, and tenant-restricted issuer validation.

Vault unlock for SSO-authenticated agents is **out of scope for this phase**: SSO agents authenticate but their credential vault is not unlocked (no master key in session). Phase 3 will add WebAuthn PRF (primary) and a vault PIN (fallback) to unlock the vault after SSO. Until then, SSO agents can use ITFlow features that do not require credential decryption (tickets, clients, assets metadata, invoicing) but cannot view or write encrypted credentials.

### Added
- `includes/entra_sso.php` — hand-rolled OIDC helpers:
  - PKCE pair generation (S256 method per RFC 7636)
  - Authorization-URL construction with state, nonce, PKCE challenge, `prompt=select_account`
  - Token exchange via curl with TLS verification on
  - JWKS fetch with 24-hour disk cache and automatic refetch on `kid` miss (handles key rotation)
  - JWK (RSA) → PEM conversion (DER-encoded SubjectPublicKeyInfo)
  - ID-token validation: RS256 signature against tenant JWKS, plus claim checks for `iss`, `aud`, `tid`, `exp`, `nbf`, `iat`, `nonce`, and presence of `oid`. ±2 minutes clock skew tolerance.
- `agent/login_entra.php` — initiation endpoint. Generates state/nonce/PKCE, stashes them in the session, redirects to Entra.
- `agent/login_entra_callback.php` — callback endpoint. Verifies state, exchanges code, validates ID token, maps to a local agent account by `oid` (immutable) or email, optionally JIT-provisions, regenerates the session ID, sets login session, logs audit events.
- `admin/agent_sso_settings.php` + `admin/post/agent_sso_settings.php` — admin UI to configure tenant ID, client ID, client secret, redirect URI, JIT provisioning toggle, default JIT role.
- Sidebar entry under Settings → Agent SSO (Entra).
- "Sign in with Microsoft" button on the main login page when SSO is enabled.
- `scripts/entra_sso_self_test.php` — 11-test self-test covering PKCE generation, base64url round-trip, RSA JWK → PEM conversion against a fresh keypair, signature verification + rejection of mismatched keys, and end-to-end JWT signing + verification.

### Changed
- `login.php` — reads `config_agent_sso_enabled` and renders the SSO button when enabled. Surfaces SSO callback errors via `$_SESSION['login_message']`.
- Database version: `2.4.4.1 → 2.4.4.2`.

### Schema
- `users.user_entra_oid VARCHAR(64) NULL` (unique). Immutable Entra user identifier; preferred lookup key.
- `settings.config_agent_sso_enabled TINYINT(1) DEFAULT 0`
- `settings.config_agent_sso_tenant_id VARCHAR(64)`
- `settings.config_agent_sso_client_id VARCHAR(64)`
- `settings.config_agent_sso_client_secret VARCHAR(512)`
- `settings.config_agent_sso_redirect_uri VARCHAR(255)`
- `settings.config_agent_sso_jit_provisioning TINYINT(1) DEFAULT 0`
- `settings.config_agent_sso_default_role_id INT(11) DEFAULT 0`

### Setup steps for an operator
1. **Register an application in Entra ID** (App registrations → New registration). Single tenant. Redirect URI (Web platform): `https://{your-itflow-host}/agent/login_entra_callback.php`.
2. **Create a client secret** under Certificates & secrets. Copy the secret value (shown once).
3. In ITFlow, go to **Settings → Agent SSO (Entra)**: enter tenant ID, client ID, secret, set status to Enabled. Save.
4. (Recommended) In Entra → **Enterprise applications → your app → Properties**, set "Assignment required" = Yes. Then assign only the agents/groups you want to allow.
5. (Optional) Map an existing agent account to an Entra user: log in once with that agent's email; the system binds the `oid` automatically. Subsequent logins match by `oid` directly.
6. (Optional) Enable JIT provisioning to let new Entra users be created as ITFlow agents on first sign-in. Choose a default role with the minimum privileges that fit your use case.

### Security properties of this flow (vs. the existing client-portal flow)
| Property | Client portal (`client/login_microsoft.php`) | Agent flow (this phase) |
|----------|----------------------------------------------|-------------------------|
| State CSRF protection | `session_id()` | `random_bytes(16)` per request |
| PKCE | No | Yes (S256) |
| Nonce | No | Yes (validated against ID token) |
| ID token signature verification | No (relies on Graph API) | Yes (RS256 against tenant JWKS) |
| Tenant restriction | Uses `/organizations/` (any tenant) | Single configured tenant |
| Issuer / aud / tid validation | No | Yes |
| Identity binding | Email only | Immutable `oid`, with email fallback (binds `oid` on first match) |
| Clock skew tolerance | n/a | ±120 seconds |
| Session fixation defense | No | `session_regenerate_id(true)` post-auth |

### Operator action required
- Run the database migration: **Admin → Update → Update Database** or `php scripts/update_cli.php --update_db`.
- Run the self-tests before deploying:
  ```
  php scripts/crypto_self_test.php
  php scripts/entra_sso_self_test.php
  ```
- Configure the Entra tenant and ITFlow as above.

### Known limitations
- SSO agents cannot decrypt credentials until Phase 3 ships (WebAuthn PRF / vault PIN). Show empty placeholders for credential reads.
- Group-based role mapping is intentionally not implemented in this phase. Use Entra-side enterprise-application user assignment for access control. Group-based role mapping can be added later if needed.
- The client secret is stored in the `settings` table in plaintext. Treat the database as a secret-equivalent asset. A future hardening step may move the secret to an environment variable or external secret store.

## v0.2.0-nis2-crypto — Phase 1: Crypto modernisation

This phase introduces the v2 cryptographic stack (AES-256-GCM + Argon2id). Both v1 and v2 ciphertexts coexist for backward compatibility; v1 data is migrated lazily on read/login and on credential update.

### Added
- `functions.php` — v2 crypto helpers:
  - `cryptoEncryptV2()` / `cryptoDecryptV2()` — AES-256-GCM with versioned ciphertext header (`0x02 0x01`).
  - `deriveKekArgon2id()` — Argon2id KEK derivation via libsodium (`SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE`, `SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE`).
  - `expandMasterKeyToAes256()` — HKDF-SHA256 expansion of the 16-byte legacy master key into a 32-byte key for AES-256-GCM operations.
  - `encryptUserSpecificKeyV2()` / `decryptUserSpecificKeyV2()` — wrap/unwrap the master key under an Argon2id-derived KEK.
  - `encryptCredentialEntryV2()` / `decryptCredentialEntryV2()` — credential ciphertexts with `v2:` prefix and base64-encoded versioned blob.
  - `unlockUserMasterKey()` — login-time helper that reads the v2 wrapped key when present, falls back to v1, and lazy-migrates to v2.
- `scripts/crypto_self_test.php` — CLI self-test covering AES-256-GCM round-trip, tamper rejection, Argon2id determinism, key wrap/unwrap, HKDF expansion, credential round-trip, IV uniqueness. Twenty tests; exits non-zero on any failure.
- New schema column `users.user_specific_encryption_ciphertext_v2` (varchar 512), populated on first login per existing user.
- Database migration `2.4.4 → 2.4.4.1`.

### Changed
- `decryptCredentialEntry()` — version-aware: tries v2 first when the stored value carries the `v2:` prefix, falls back to legacy v1 (AES-128-CBC) otherwise.
- `encryptCredentialEntry()` — always writes v2; existing v1 ciphertexts are migrated to v2 on the next save of that credential.
- `apiDecryptCredentialEntry()` / `apiEncryptCredentialEntry()` — same v2-aware behaviour for API access.
- `login.php` — agent decrypt paths use `unlockUserMasterKey()` instead of direct `decryptUserSpecificKey()`, enabling lazy migration on login.
- `admin/post/users.php`, `agent/user/post/profile.php` — password change and admin password reset now also clear `user_specific_encryption_ciphertext_v2` so the v2 wrapping is regenerated on the user's next login.

### Migration behaviour
- **Existing users:** continue to log in normally. On their first successful login after upgrade, `unlockUserMasterKey()` reads the v1 wrapping, decrypts the master key, generates a v2 wrapping, and stores it. Subsequent logins use v2.
- **Existing credentials:** remain readable as v1. The next save of any credential rewrites it as v2. Read paths transparently handle both.
- **API consumers:** API keys continue to use the v1 wrapping path; they remain operational. v2 is only invoked on credential ciphertexts, not on the API key wrapping itself.
- **No re-encryption job is required.** Migration is fully online and lazy.

### Cryptographic notes
- The underlying master key remains 16 bytes (128-bit security) for backward compatibility. AES-256-GCM operations use an HKDF-expanded 32-byte key derived from the master key. The cipher and authentication are AES-256-GCM; the input keying material has 128-bit entropy, which remains within ENISA / BSI TR-02102 acceptable bounds. A future phase may replace the master key with a freshly generated 32-byte key requiring a one-time re-encryption pass.
- The v2 ciphertext format includes an explicit version byte (`0x02`) and algorithm byte (`0x01`), enabling future migrations without ambiguity.
- Argon2id parameters are tunable; current defaults match libsodium's INTERACTIVE preset (~64 MiB memory, opslimit 2). Adjust `deriveKekArgon2id()` for higher-traffic deployments where memory pressure is a concern.

### Operator action required
- Ensure PHP libsodium extension is enabled (`extension=sodium` in `php.ini`). Verify with `php -r "echo extension_loaded('sodium') ? 'ok' : 'missing';"`. The crypto self-test will refuse to run without it.
- After deploying this release, run the database migration: `Admin > Update > Update Database` (or `php scripts/update_cli.php --update_db`).
- After at least one successful login per user, verify v2 migration in the database: `SELECT user_id, user_email FROM users WHERE user_specific_encryption_ciphertext_v2 IS NULL AND user_archived_at IS NULL AND user_status = 1`. Rows returned indicate users who have not yet logged in since the upgrade.

## v0.1.0-nis2-foundation — Phase 0: Foundation

Foundational changes that prepare the codebase for the NIS2 hardening work in subsequent phases. **No cryptographic changes yet** — that arrives in Phase 1.

### Added
- `SECURITY.md` — fork-specific security policy and threat model.
- `docs/crypto-policy.md` — cryptographic policy document required by NIS2 Art. 21(2)(h).
- `RELEASE_NOTES.md` — this file.
- `.github/workflows/security.yml` — CI workflow with PHP syntax checking on 8.2 and 8.3, gitleaks secret scanning, Composer/npm audit, CodeQL analysis, and SBOM generation on master.
- Source/branch banner on the `Admin > Update` page so operators see at a glance which remote and branch they are updating from.

### Fixed
- `admin/post/update.php` — telemetry condition contained an assignment (`OR $config_telemetry = 2`) that always evaluated true, sending telemetry on every update regardless of operator preference. Replaced with proper comparison.

### Changed
- `admin/post/update.php` — force-update no longer hardcodes `origin/master`; now uses the configured `$repo_branch` consistent with the standard update path.
- `scripts/update_cli.php` — same change for the CLI updater.

### Migration
None. Phase 0 is code-only and introduces no schema or data changes.

### Operator action required
Servers that previously ran upstream `itflow-org/itflow` and want to switch to this fork:

```bash
cd /path/to/itflow
git remote set-url origin https://github.com/jortiexx/itflow-nis2.git
git fetch origin
git reset --hard origin/master
```

After this, the in-app updater (`Admin > Update`) and CLI (`scripts/update_cli.php`) pull from this fork.

### Roadmap

| Phase | Status | Scope |
|-------|--------|-------|
| 0. Foundation | In progress | Fork setup, CI, docs, update-mechanism patches |
| 1. Crypto modernisation | Planned | AES-256-GCM, Argon2id, ciphertext versioning, lazy migration on login |
| 2. Entra ID SSO for agents | Planned | OIDC + group-based role mapping |
| 3. Vault unlock | Planned | WebAuthn PRF (primary) + PIN fallback |
| 4. Phishing-resistant MFA + hardening | Planned | WebAuthn as 2FA for non-SSO users |

See `SECURITY.md` for the threat model and `docs/crypto-policy.md` for the cryptographic posture.
