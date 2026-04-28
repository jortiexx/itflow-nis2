# Release notes — itflow-nis2 fork

This file tracks changes specific to this fork. The upstream `CHANGELOG.md` continues to track upstream releases as merged in.

## Unreleased — Phase 0: Foundation

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
