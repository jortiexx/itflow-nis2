# Release notes — itflow-nis2 fork

This file tracks changes specific to this fork. The upstream `CHANGELOG.md` continues to track upstream releases as merged in.

## Unreleased — Phase 1: Crypto modernisation

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
