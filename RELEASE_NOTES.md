# Release notes — itflow-nis2 fork

This file tracks changes specific to this fork. The upstream `CHANGELOG.md` continues to track upstream releases as merged in.

## v0.18.0-nis2-vault-hardening — Phase 18: vault hardening

Closes the open technical gaps from a security review of phase 13–17: AAD on
authenticated encryption, GCM at the session layer, vault idle TTL with
step-up freshness, FIDO2 metadata capture, hardware-bound attestation policy,
per-account exponential lockout, and a self-service kill-switch. See
`docs/vault-runbook.md` for the operator playbook.

### Schema (DB version 2.4.4.13)
Eight columns on `user_vault_unlock_methods`:
- `kdf_version` — distinguishes legacy AAD-less wraps from current
- `cose_alg`, `aaguid`, `backup_eligible`, `backup_state`, `transports` — FIDO2 metadata
- `disabled_at`, `disabled_by_user_id` — kill-switch

Two columns on `users`:
- `vault_consecutive_failures`, `vault_locked_until` — per-account lockout

Three columns on `settings`:
- `config_vault_idle_ttl_seconds` (default 1800)
- `config_vault_lockout_max_seconds` (default 3600)
- `config_require_hardware_bound_authenticators` (default 0)

### Crypto changes
- `cryptoEncryptV2` / `cryptoDecryptV2` accept optional AAD; vault wraps now
  bind ciphertext to `user_id` via `vaultWrapAad()`. Lazy-migrates on next
  successful unlock (PIN + PRF paths both handle legacy + current side-by-side
  during transition).
- Session-layer wrap of master key + privkey moved from AES-128-CBC (no auth
  tag) to AES-256-GCM with user-bound AAD. New helper `sessionUnwrapMasterKey()`
  centralises decryption; legacy CBC fallback retained for in-flight sessions
  and auto-upgrades on next login.
- `vaultDeriveKekFromPrf()` v2 mixes `user_id` into HKDF info and uses the
  per-method `prf_salt` as HKDF salt for defence-in-depth.

### Lifecycle controls
- Idle TTL: `vault_unlocked_at` touched on every credential read; vault
  re-locks after `config_vault_idle_ttl_seconds` of inactivity.
- Step-up freshness: separate `vault_step_up_at` timestamp set only by an
  explicit unlock ceremony (PIN re-prompt, PRF re-tap, fresh login). Default
  300 s window before step-up is required again.
- `requireFreshVaultUnlock(int $max_age = 300)` redirects to
  `/agent/vault_unlock.php?step_up=1&return_to=...` when the window expires.
  POST flows return to the Referer to preserve operator context.

### Step-up wired at the destructive perimeter
The mechanism is intentionally **not** wired everywhere. Step-up gates passive
risk (idle session, walk-away); against an active attacker with a stolen
session it only delays. Wiring it everywhere would force operators to re-prompt
every credential reveal (~30–50/day per agent), driving them to workarounds
(browser-cached PIN, longer sessions, fatigue-blind clicking). The endpoints
that *do* require step-up are the ones where one click has high blast-radius:

| Endpoint | Why |
|---|---|
| `admin/post/api_keys.php → add_api_key` | Mints long-lived bearer that bypasses MFA |
| `admin/post/api_keys.php → revoke_api_key` | Silent revocation of bearer access |
| `admin/post/api_keys.php → delete_api_key` | Same |
| `admin/post/api_keys.php → bulk_delete_api_keys` | Mass revocation |
| `admin/post/users.php → archive_user` | Cascades unlock methods + grants |
| `admin/post/users.php → restore_user` (with new password) | Regenerates user wrap |
| `admin/post/users.php → ir_reset_user_password` | Mass IR action across all agents |
| `admin/post/users.php → force_vault_reenrol` | Wipes another user's unlock methods |
| `agent/post/credential.php → export_credentials_csv` | Bulk bearer secrets to operator disk |

Routine reads (single credential reveal, file download, list pages, AJAX) are
**not** gated. See `docs/vault-runbook.md` for the threat-model rationale.

### FIDO2 metadata + policy
- `webauthnVerifyRegistration()` returns `aaguid`, `backup_eligible`,
  `backup_state`. JS-side captures `transports` via `response.getTransports()`.
- `vault_unlock_prf_verify` uses stored `cose_alg` instead of trial-and-error;
  backfills NULL for pre-phase-18 rows on first successful unlock.
- Hardware-bound policy: when `config_require_hardware_bound_authenticators`
  is set, registering a credential with `BE=1` (synced passkey: iCloud
  Keychain, Bitwarden, etc.) is rejected at registration time.

### Per-account lockout with exponential backoff
On top of the existing per-method 5-strike lockout, the helpers
`vaultAccountSecondsUntilUnlock` / `Register` / `Clear` enforce a per-user
backoff of `min(2^failures, config_vault_lockout_max_seconds)`. Wired into
PIN + PRF unlock paths. Reset on success.

### Kill-switch UI
- Self-service: `agent/user/user_security.php` per-row Disable/Enable/Remove
  buttons. Disabled rows are filtered out of PRF assertion options + lookup.
- Admin-side: `admin/modals/user/user_edit.php` "Force vault re-enrolment"
  button calls `vaultForceReenrol()` and emits
  `securityAudit('vault.method.force_reenrol')`. Step-up gated.
- `archive_user` now cascades unlock-method deletion and emits
  `securityAudit('user.archive')` + `'grant.revoke'` with grants_revoked count.

### What this does NOT do
- Live FIDO MDS3 sync (AAGUID is captured for future blocklist support).
- Master key rotation UI (existing CLI `scripts/reset_master_key.php` remains
  the path; runbook covers when to use it).
- Step-up on routine credential reveal / single file download (UX cost
  outweighs benefit; see threat model in runbook).

## v0.17.0-nis2-ratelimits — Phase 16: configurable rate limits + API auth throttling

Closes two of the technical gaps flagged at the end of phase 15:
- API key authentication had no rate limit (a brute-forcer could try keys all day).
- Existing throttles on login / vault unlock / SSO were hardcoded; admin had no way to tighten or loosen them.

### Schema (DB version 2.4.4.12)
Eleven new columns on `settings`:
- `config_ratelimit_enabled` (default 1)
- `config_ratelimit_login_max` / `_window` (default 10 / 600 s)
- `config_ratelimit_vault_max` / `_window` (default 20 / 600 s)
- `config_ratelimit_sso_max` / `_window` (default 20 / 600 s)
- `config_ratelimit_api_max` / `_window` (default 30 / 600 s)
- `config_ratelimit_pwreset_max` / `_window` (default 5 / 3600 s)

### Helper layer
`includes/rate_limit.php` gains two new entry points alongside the existing low-level `rateLimitCheck()`:
- `rateLimitConfig($mysqli)` — reads thresholds from `settings`, falls back to baked-in defaults if columns are missing (mid-upgrade safe). Static-cached so subsequent calls are free.
- `rateLimitCheckScope($scope, $mysqli)` — looks up the named scope (`login` / `vault` / `sso` / `api` / `pwreset`), enforces it, no-op when global enable is off.

### Settings UI
`admin/settings_security.php` (existing page) gains a "Rate limiting" section: master on/off switch + per-scope max/window inputs, each with a description of what it does and its default. Form values are clamped on save (`max ≥ 1`, `window ≥ 60 s`) so an admin can't accidentally configure "always block" or "useless 1-second window".

### Enforcement points wired
| Entry point | Scope | Notes |
|---|---|---|
| `login.php` | `login` | Replaces the old hardcoded 15/10min throttle |
| `agent/vault_unlock.php` | `vault` | PIN unlock POST |
| `agent/vault_unlock_prf_verify.php` | `vault` | WebAuthn-PRF unlock |
| `agent/login_entra_callback.php` | `sso` | Entra ID callback failures |
| `api/v1/validate_api_key.php` | `api` | **NEW** — was previously unthrottled |
| `client/login_reset.php` | `pwreset` | **NEW** — stops password-reset email bombing |

All sites use `rateLimitCheckScope($scope, $mysqli)`, so changing the threshold from the admin UI takes effect on the next request without a code change.

### API endpoint audit (companion to phase 16)
Reviewed `api/v1/credentials/*` and `api/v1/documents/*` for crypto correctness:
- Credentials API write/read uses `apiEncryptCredentialEntry` / `apiDecryptCredentialEntry` with `$client_id` (per-client v3 path). ✓
- Documents API stores `document_content` as plaintext, consistent with the v0.14.1 revert (document body is content, not a bearer secret). ✓

No code changes needed for the API beyond adding the rate-limit hook.

### Operator action required
- After deploy: visit Admin → Settings → Security. Confirm the new "Rate limiting" section is present. Defaults are sane; tighten if your install is more sensitive.
- Optional: tail `logs` table for `Blocked` entries after a few days to spot unintended blocks. If a legitimate workflow trips the limit (e.g. an automation that does many API requests), raise that scope's threshold or extend the window.

## v0.16.1-nis2-sweeper — Phase 15: first-login migration UI with progress bar

Replaces the silent once-per-hour opportunistic sweep from v0.16.0 with a one-shot blocking migration UI on the first admin login after upgrade.

### What it does
- After login + vault unlock, if there are still plaintext files this admin can encrypt, the next page navigation redirects to `/agent/migrate_legacy_files.php`.
- The page shows a Bootstrap progress bar + "X / Y encrypted" status line. JS polls `/agent/migrate_legacy_files_step.php` continuously (50ms between batches).
- Each batch: up to 100 files, hard 3-second time budget, race-safe via `flock(LOCK_EX)` per file. Same AES-256-GCM encryption + SHA-256 + MIME-fill as before.
- When `remaining` hits zero, the page redirects to the home URL.
- Stuck-detection: if 5 consecutive batches make no progress, the UI stops and tells the operator to run the CLI script.

### Throughput
Each batch ~3 seconds, ~100 files (depends on file size — large files self-throttle via the time budget). For 10,000 legacy files: ~5 minutes of progress-bar time. For 1,000: ~30 seconds.

### Why admin-only
The redirect fires only when `$session_is_admin === true`. Non-admins might hit grant gaps mid-sweep (per-user keypair compartmentalisation under phase 10) which would stall the bar. They're better off navigating normally; the admin completes the migration once.

### Skipped paths (no redirect)
- The migration page + AJAX endpoint themselves
- Form handlers (`/agent/post.php`)
- AJAX endpoints (`/agent/ajax.php`)
- Any request with `X-Requested-With: XMLHttpRequest`

### Vault still locked?
The migration page detects `no_master_key` from the sweeper and redirects to `/agent/vault_unlock.php`. After unlock, the next page navigation re-routes back to the migration page.

### CLI alternative
`scripts/encrypt_legacy_files.php` from v0.16.0 still works for ops who prefer running it offline.

## v0.16.0-nis2-sweeper — Phase 15: legacy file encryption sweep (auto on first login after upgrade)

Closes the gap left by phase 13's lazy migration: files that were on disk **before** phase 13 was deployed stayed plaintext (`file_encrypted = 0`) — including `.pfx` keystores, `.ovpn` configs, exported credentials, and any other bearer-shaped attachment. Phase 13 only encrypted *new* uploads.

### Why "auto" can't strictly mean "during the DB migration"

The encryption requires the per-client master key, which is wrapped under the session-master and is only derivable when an admin's vault is unlocked. A DB migration runs in a context where no one is logged in yet — there is no session-master. So a strict "encrypt during migration" is cryptographically impossible.

### What "auto" actually does

Schema migration `2.4.4.10 → 2.4.4.11` adds `client_master_keys.legacy_files_swept_at` (NULLable). NULL = "this client may still have plaintext files; sweep me." NOT NULL = "fully migrated, never scan again."

`includes/load_user_session.php` now calls `sweepLegacyFilesOpportunistic()` once per session per hour:
- Looks up one client (lowest `client_id`) where `legacy_files_swept_at IS NULL` AND there are still `file_encrypted = 0` rows AND the current user has access.
- Encrypts up to **25 files** with a hard **1-second** time budget per call.
- Each file: `flock LOCK_EX` (race-safe vs. multiple admins logging in at once), read plaintext, AES-256-GCM encrypt with the per-client key, `ftruncate` + `fwrite` ciphertext atomically over the same file handle, `UPDATE files SET file_encrypted=1, file_encryption_iv=?, file_encryption_tag=?, file_sha256=?, file_mime_verified=COALESCE(...)`. Audits each as `file.migrate.encrypted`.
- When a client has zero plaintext rows left, sets `legacy_files_swept_at = NOW()` and emits `file.migrate.client_complete`.
- Failures (missing on disk, write error, DB UPDATE rejected) are logged + counted; the disk write rolls back via decrypt-with-the-just-generated-key if the SQL update failed, so the on-disk and DB state stay consistent.

For a small install (a few hundred files, one admin): the entire backlog clears in a few logins. For a large install (tens of thousands of files): the work distributes across logins; ops can also force-finish via the CLI script.

### CLI script (`scripts/encrypt_legacy_files.php`)

For ops who want to push through the backlog in one go:

```
php scripts/encrypt_legacy_files.php           # process everything
php scripts/encrypt_legacy_files.php --dry-run # report counts only
php scripts/encrypt_legacy_files.php --client-id=42
php scripts/encrypt_legacy_files.php --batch=500
```

Same primitive as the in-app sweeper. Requires the per-client master key derivable from the running shell context — typically only useful inside a vault-aware environment.

### What this does NOT solve

- **Existing backups** still contain the plaintext bytes. Encrypting going-forward does not retroactively scrub backup tapes / S3 versioned objects / off-site copies. Operational sanitisation of those is outside code scope.
- **Archived files** (`file_archived_at IS NOT NULL`) are deliberately skipped — they're not in the active corpus and a future "purge archived" pass can address them.
- **`uploads/documents/*` inline images** stay plaintext (operator-authored illustrations, not bearer material; `.htaccess` allows direct read from phase-14 hotfix).

### Operator action required

After deploy + first login: nothing. Just log in and use the app normally. After ~1 hour you can verify progress via:
```sql
SELECT COUNT(*) FROM files WHERE file_encrypted = 0 AND file_archived_at IS NULL;
SELECT client_id, legacy_files_swept_at FROM client_master_keys ORDER BY client_id;
SELECT COUNT(*), audit_event_type FROM security_audit_log
 WHERE audit_event_type LIKE 'file.migrate.%' GROUP BY audit_event_type;
```

If you want to force-complete: run the CLI script.

## v0.15.1-nis2-photos — Hotfix: re-allow public branding paths

Phase 14's full default-deny on `uploads/.htaccess` over-reached. Three
public-by-design asset categories live in the same `uploads/` tree as
customer data and must remain reachable without a session:

- `uploads/favicon.ico` — `<link rel=icon>` on every page including
  pre-auth login + vault unlock pages.
- `uploads/settings/<company_logo>` — rendered on the login page, vault
  unlock, vault enrol, client portal header, and guest share-views.
- `uploads/documents/<id>/<inline_image>` — TinyMCE-embedded images
  inside document bodies; the document body is gated by ACL but the
  `<img>` tags fetch directly.

Fix: parent `uploads/.htaccess` keeps the default-deny, with a `<Files
"favicon.ico">` override for the favicon. New `uploads/settings/.htaccess`
and `uploads/documents/.htaccess` re-grant access in those subtrees, with
their own deny-list for executable extensions as belt-and-braces.

Also: `guest/guest_view_ticket.php` now forces the initials fallback for
ticket-reply avatars (the `<img>` was previously rendering as a broken
image because `$user_avatar` was non-empty even though the URL 403'd).
Token-scoped photo access for guest share-views remains out of scope.

No other code changes. The customer-data tree (`uploads/clients/*`,
`uploads/users/*`) stays fully default-deny.

## v0.15.0-nis2-photos — Phase 14: PHP-mediated photo endpoint + uploads default-deny

Closes the photo gap left open at the end of phase 13. Asset, contact, rack, and location photos plus user/operator avatars no longer come from direct `/uploads/...` URLs. Every photo fetch now routes through `/photo.php`, which:

1. Requires an authenticated session — agent (`$_SESSION['logged']`) OR client portal (`$_SESSION['client_logged_in']`).
2. Looks up the canonical filename from the parent table (`contacts.contact_photo`, `assets.asset_photo`, `racks.rack_photo`, `locations.location_photo`, `users.user_avatar`).
3. Verifies the viewer is allowed to see that client's data — admin bypass, explicit `user_client_permissions` grant, unrestricted-default-fallback, OR (for client portal) `session.client_id === photo.client_id`.
4. Confirms the bytes are actually an image via server-side `finfo` (`image/jpeg|png|gif|webp|svg+xml|x-icon|vnd.microsoft.icon` only). Refuses anything else.
5. Audits denials as `photo.access.denied`. Successes are intentionally **not** audited per fetch — list pages render dozens of thumbnails and would flood the audit log; the access stream is captured by web-server access logs (which include the authenticated session and the URL).

URLs replaced across the agent UI (`asset_details`, `contact_details`, `client_overview`, `contacts`, `racks`, `ticket`), all four asset/contact/rack/location modals, the client portal (`client/ticket.php`, `client/includes/header.php`), the admin user management views (`admin/users.php` + three user modals), the global top-nav, and the per-user details page. Net effect: 18 sites switched to `/photo.php?type=...&id=...`.

`uploads/.htaccess` is now **fully default-deny**: the image-extension allowlist from phase 13 is gone. Direct `GET /uploads/clients/<X>/<Y>.jpg` returns 403 from Apache without any PHP involvement. PHP-side `readfile`/`file_get_contents` paths inside `agent/file_download.php` and `photo.php` are unaffected because they read the bytes via the filesystem, not via Apache.

### Known limitation
`guest/guest_view_ticket.php` still constructs direct `/uploads/...` paths for share-link viewers who have no authenticated session. After this phase those `<img>` tags 404 → graceful fallback to initials. This is documented behavior, not a regression. Token-based access for guest views is a future phase.

### Why now
Phase 13 closed the file-download gap but left an explicit image-extension allowlist in `uploads/.htaccess` so that profile/asset/rack/location photos kept working. That allowlist meant: if someone has the URL (browser cache, screenshot, ex-employee bookmark, archived email), they fetch the photo with no session check, no ACL, no audit. Random 16-char reference filenames make the URLs unguessable but don't help once a URL has leaked. For NIS2 / GDPR alignment around personal-data photos this was a real gap. This phase closes it.

### Cumulative
Tests unchanged (147/0). No new self-test added because the endpoint exercises existing primitives (session check + DB lookup + finfo + readfile) that are already covered by phase-13 tests.

### Operator action required
- After deploy: confirm a contact-photo `<img>` renders (server returns 200 from `/photo.php?type=contact&id=...`). Test that an unauthenticated curl against `/uploads/clients/X/photo.jpg` returns 403.
- Optional: review `security_audit_log` for `photo.access.denied` after letting it run a few hours. Spike here means a stale link or a buggy access pattern.

## v0.14.1-nis2-files — Phase 13C reverted

`document_content` (and `document_versions.document_version_content`) are no
longer encrypted at the application layer. The `agent/post/document.php`
write paths are restored to plaintext storage. Reasoning: a document body
is *content*, not a bearer secret. Encrypting it duplicated work that
belongs at the infrastructure layer (encrypted filesystem, encrypted DB
backups), broke the FULLTEXT search index alignment, and silently degraded
the client-portal / API document-read paths. This contradicted the line
established in phase 12 — app-layer encryption is for bearer secrets
(credential password, OTP seed, credential note); content-shaped fields
rely on infra-layer at-rest protection.

The read sites (`agent/document_details.php`, the four document modals,
`client/document.php`, `guest/guest_view_item.php`, the PDF-export path)
keep `decryptOptionalField` as a transitional shim — it is a passthrough
for plaintext rows and decrypts any leftover v3 rows from the brief window
phase-13C was deployed. No data migration required; on the next save each
document falls back to plaintext naturally. The shim can be removed in a
later cleanup pass.

The other phase-13 items (A file-download endpoint, B file at-rest
encryption, D SHA-256 integrity, E version retention pruning, F MIME
validation) are unchanged. The decision boundary is: file uploads
frequently *are* bearer material (`.pfx`, `.ovpn`, exported password
lists), so B is consistent with the principle. Document bodies are not.

## v0.14.0-nis2-files — Phase 13: file storage hardening

Closes the six known weaknesses in how ITFlow stores client-uploaded files and document bodies on disk and in the database. The data path is now: PHP-mediated download with ACL + audit, AES-256-GCM at rest under the per-client master key, server-side MIME validation, integrity hash verified on every fetch, and a retention sweeper for old document versions.

### A. PHP-mediated file download (`agent/file_download.php`)
Direct linking to `/uploads/clients/X/Y` is gone. Every file fetch now goes through `agent/file_download.php?id=N` (or `&inline=1` for `<img>`). The endpoint:
1. Authenticates via `check_login`.
2. Verifies the user has app-layer access to the file's client (admin OR matching `user_client_permissions` row OR unrestricted user).
3. Reads the disk blob from `uploads/clients/<client_id>/<reference_name>`.
4. Decrypts if `file_encrypted = 1` (phase-13 uploads); falls through if the row is pre-13 plaintext.
5. Verifies the SHA-256 if `file_sha256` is set — refuses to serve a tampered file (audits `file.integrity.failed`).
6. Audits `file.download` (or `file.download.denied` / `file.download.decrypt_failed`).
7. Streams with `Content-Disposition`, `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`.

URLs replaced across the agent UI: `agent/asset_details.php`, `agent/contact_details.php`, `agent/files.php` (5 sites), `agent/global_search.php`, `agent/quote.php`, `agent/modals/asset/asset_details.php`, `agent/modals/contact/contact_details.php`.

### B. Encrypt files at rest (per-client master key)
New helper `includes/file_storage.php`:
- `encryptFileAtRest($plaintext, $client_id, $mysqli)` returns `[ciphertext, iv (12 bytes), tag (16 bytes)]` using AES-256-GCM under the per-client master key (HKDF-expanded to 32 bytes).
- `decryptFileAtRest(...)` reverses it; returns `null` on auth-tag failure.

`agent/post/file.php`'s `upload_files` handler now: validates MIME → reads the plaintext bytes → hashes them → encrypts → writes ciphertext to disk → unlinks the tmp plaintext copy → persists `file_encrypted=1`, `file_encryption_iv`, `file_encryption_tag`, `file_sha256`, `file_mime_verified` via a prepared `INSERT` (binary-safe for VARBINARY columns).

If the vault is locked at upload time (no client master derivable), the file falls through to plaintext storage and the event is audited as `file.upload.encryption_unavailable`. The download path handles both rows uniformly.

### C. Encrypt `document_content` + `document_versions.document_version_content`
At write: `agent/post/document.php` (`add_document`, `add_document_from_template`, `edit_document`) now wraps `document_content` with `encryptCredentialEntry($content, $client_id)` (the same v3 path used for credential passwords). When new versions are minted, the existing ciphertext is copied verbatim into `document_versions` — no re-encryption, no plaintext exposure window.

At read: `agent/document_details.php`, `agent/modals/document/document_view.php`, `agent/modals/document/document_version_view.php`, `agent/modals/document/document_edit.php`, the PDF-export path in `agent/post/document.php`, plus client portal sites `client/document.php` and `guest/guest_view_item.php` all wrap reads in `decryptOptionalField($row['document_content'], $client_id)`. Pre-13 plaintext rows pass through untouched (lazy migration).

`document_content_raw` is intentionally **not** encrypted because it backs the `FULLTEXT` index used by document search (`agent/files.php` and `agent/global_search.php`). This is a documented trade-off — encrypted full-text search would require either client-side index encryption or per-client search compartmentalisation, both of which are out of scope for this phase.

### D. SHA-256 integrity hash on every file
`fileHashSha256($plaintext)` returns 32 raw bytes; computed at upload (over the plaintext, before encryption) and stored in `files.file_sha256` (`VARBINARY(32)`). The download endpoint re-hashes after decrypt and refuses to serve on mismatch. This catches both at-rest tampering and decryption returning corrupted plaintext.

### E. Document-version retention pruning (`scripts/document_version_prune.php`)
New CLI script. Reads `settings.config_document_version_retention_days` (default 365). Deletes `document_versions` rows older than the cutoff. Supports `--dry-run` and `--verbose`. Always emits a `document_version.prune` audit record summarising the run. Intended for nightly cron.

### F. Server-side MIME validation
`fileVerifyMimeMatchesExtension($tmp_path, $extension)` opens the uploaded tmp file with `finfo`, looks up the claimed extension in a 40-entry allowlist, and confirms the detected MIME starts with one of the expected prefixes. Rejects:
- extension not in the allowlist
- detected MIME inconsistent with the extension (a renamed-EXE-as-PNG)

`agent/post/file.php` now invokes this **before** moving the upload, audits rejections as `file.upload.mime_rejected`, and stores the detected MIME in `files.file_mime_verified`. Browser-supplied `$_FILES['type']` is no longer trusted as authoritative.

### Schema (DB version 2.4.4.10)
```sql
ALTER TABLE files
  ADD COLUMN file_encrypted          TINYINT(1)     NOT NULL DEFAULT 0,
  ADD COLUMN file_encryption_iv      VARBINARY(12)  NULL,
  ADD COLUMN file_encryption_tag     VARBINARY(16)  NULL,
  ADD COLUMN file_sha256             VARBINARY(32)  NULL,
  ADD COLUMN file_mime_verified      VARCHAR(100)   NULL;
ALTER TABLE settings
  ADD COLUMN config_document_version_retention_days INT NOT NULL DEFAULT 365;
```

`uploads/.htaccess` is now default-deny: only image extensions (`jpg|jpeg|png|gif|webp|svg|ico`) are served directly (for asset/contact/rack/location photos that do not yet live in the `files` table). Everything else — PDFs, ZIPs, Office docs, scripts — must come through `file_download.php`.

### Self-test (`scripts/phase13_self_test.php`)
21 offline tests:
- SHA-256: length, reference vector, distinctness, stability
- AES-256-GCM round-trip: encrypt/decrypt with the same `expandMasterKeyToAes256` path the helper uses
- Tamper detection: flipped ciphertext bit, flipped tag bit, wrong key
- MIME validation: plain text accepted, valid PNG accepted, PNG-claiming-PDF rejected, extension-not-in-allowlist rejected
- 64 KB blob round-trip + SHA verification across plaintext vs ciphertext

### Cumulative
**147 / 0 failures** across 12 suites: crypto 20, Entra SSO 11, vault PIN 5, vault PRF 7, vault enrolment 6, audit log 6, WebAuthn 15, client master keys 13, keypair 15, phase 11 13, phase 12 15, phase 13 21.

### Migration
- Run database update: `2.4.4.9 → 2.4.4.10` adds the new columns. Existing files keep working with `file_encrypted = 0` until the next time they're uploaded — there is no bulk re-encryption of historical content.
- Existing documents continue to read/write transparently; new edits encrypt.
- `uploads/.htaccess` default-deny may break custom workflows that depended on direct linking outside the files table — review that table.

### Operator action required
- After deploy: open an existing client, upload a new file, confirm `files.file_encrypted = 1`, `file_encryption_iv` is 12 bytes, `file_sha256` is 32 bytes. Download via the new endpoint; check that an `audit.file.download` record appears in `security_audit_log`.
- Confirm document edit + view round-trips; check that `documents.document_content` of a freshly-saved doc starts with `v3:`.
- Schedule `scripts/document_version_prune.php` (e.g. nightly cron). Optionally adjust `config_document_version_retention_days` in the settings row.

## v0.13.0-nis2-phase12 — Phase 12: encrypt OTP secret + credential note

Two credential fields that are routinely used to store secrets but were never encrypted at the application layer are now wrapped with the same per-client v3 path used for `credential_username` / `credential_password`:

- `credentials.credential_otp_secret` — the TOTP seed
- `credentials.credential_note` — the free-text notes field where operators frequently paste extra passwords or instructions

### Why these two

TOTP seeds are bearer secrets that generate second-factor codes. A leaked seed = ongoing 2FA bypass. Notes are unstructured text that operators in practice use to store recovery codes, secondary credentials, and "the database root password is ..." tips. Both deserve the same protection as the password column.

(`software.software_license_key` was considered and dropped: license keys are identifiers, not bearer secrets — vendors enforce licence usage via online activation, not via key secrecy.)

### How

New helper `decryptOptionalField($value, $client_id)`:
- empty / null → empty string
- starts with `v2:` or `v3:` → run `decryptCredentialEntry`
- anything else (legacy plaintext) → return as-is

The asymmetry vs `decryptCredentialEntry` matters: `credential_otp_secret` and `credential_note` were stored as plain text since installation, so falling into the v1 path (which assumes a 16-byte IV prefix) would garble them.

Write side, `agent/post/credential_model.php` and `api/v1/credentials/credential_model.php`: when these fields come in via POST, encrypt with `encryptCredentialEntry` / `apiEncryptCredentialEntry` (per-client v3 path).

Read side, all 13 call sites under `agent/` updated to wrap reads in `decryptOptionalField($row['credential_*'], $row['credential_client_id'])`. Includes the `credential_id_with_secret` JS-data-attribute pattern that several pages use to embed the seed for client-side TOTP code generation, and `agent/ajax.php`'s `get_totp_token_via_id` endpoint.

### Migration
Lazy. Existing rows stay plaintext until next save. Save a credential, OTP and note become v3-encrypted automatically.

### Bug fix bundled
`agent/modals/credential/credential_view.php` was calling `decryptLoginEntry()` — a function that doesn't exist anywhere in the codebase. Replaced with `decryptCredentialEntry($..., $row['credential_client_id'])`. This had been broken in the credential view modal since at least Phase 9; nobody noticed because most credential reading happens via other modals.

### Self-test (`scripts/phase12_self_test.php`)
15 offline tests:
- empty / null pass-through
- legacy plaintext (TOTP-style, multi-line note, alphanumeric) unchanged
- prefix detection (v2/v3 routing decisions)
- v3 round-trip via low-level helper
- note round-trip preserves whitespace and special characters

### Cumulative
**126 / 0 failures** across 11 suites: crypto 20, Entra SSO 11, vault PIN 5, vault PRF 7, vault enrolment 6, audit log 6, WebAuthn 15, client master keys 13, keypair 15, phase 11 13, phase 12 15.

### Operator action required
- No database migration in this phase.
- Existing OTP secrets and notes keep working as plaintext until the credential is saved again.
- After deploy: edit and save any credential to test that OTP + note round-trip; check the DB column starts with `v3:` after the save.

## v0.12.0-nis2-phase11 — Phase 11: Closing the three Phase 10 gaps

Closes the three known limitations from Phase 10:

1. **SSO + PIN / SSO + PRF unlock paths** now restore the user's privkey to the session, so compartmentalisation survives those flows.
2. **API keys** scoped to a single client (`api_key_client_id > 0`) now use a per-client wrapping that bypasses the shared master entirely — a compromised client-scoped API key cannot reach any other client's data.
3. **Admin grant management UI**: editing a user's client access in the existing user-edit modal now keeps `user_client_grants` in sync — adds and revokes wrapping rows under the target user's pubkey on save.

### Schema migration `2.4.4.8 → 2.4.4.9`
- `user_vault_unlock_methods.wrapped_privkey` (varchar 512, nullable) — privkey wrapped under PIN/PRF KEK
- `api_keys.api_key_client_master_wrapped` (varchar 512, nullable) — per-client master wrapped under API password

### Fix #1 — Privkey under PIN/PRF KEK

PIN setup (`vaultSetPin`) and PRF registration (`vaultStorePrfMethod`) now accept the user's current session privkey and wrap it under the same KEK that wraps the master key. Different IVs, same Argon2id-derived (PIN) or HKDF-derived (PRF) KEK.

Unlock path returns both:
- `vaultUnlockWithPin($user_id, $pin, $mysqli)` returns `['master' => ..., 'privkey' => ?...]`
- `vaultUnlockWithPrf($method_id, $prf_output, $mysqli)` returns the same shape
- `vaultTryUnlockWithPin` / `vaultTryUnlockWithPrf` retain their string-only signature for backward compat

`agent/vault_unlock.php` and `agent/vault_unlock_prf_verify.php` push both materials to the session via `pushUserPrivkeyToSession()` after a successful unlock.

**Net effect:** an SSO-authenticated agent who unlocks via PIN or PRF restores their privkey to the session. Subsequent credential reads use `getClientMasterKeyViaGrant()` — full Phase 10 compartmentalisation, not the shared-master fallback.

**Existing PIN/PRF enrolments**: `wrapped_privkey` is NULL until the user re-enrols their PIN or registers a new PRF credential. They keep working but fall back to shared-master path for credential reads. Document in operator runbook.

### Fix #2 — Per-client API key compartmentalisation

API keys with a specific `api_key_client_id` now carry their own wrapping of that client's master key, encrypted under the API password using Argon2id+AES-256-GCM. Stored in `api_keys.api_key_client_master_wrapped`.

API decrypt path checks this column FIRST. When present, the API key recovers the scoped client's master key directly — no shared master key is involved at any point. A compromised API key (or a leak of `api_key_decrypt_password`) only exposes that one client.

`apiUnlockClientMasterKey($api_key_row, $api_password)` is the unwrap helper. It is the first thing `apiDecryptCredentialEntry` and `apiEncryptCredentialEntry` try.

Global API keys (`api_key_client_id = 0`) leave the column NULL and continue to use the shared-master path. Document this is intentionally non-compartmentalised — operators wanting compartmentalisation should issue per-client keys.

Existing API keys in the DB pre-Phase-11 have NULL `api_key_client_master_wrapped`. They keep working via shared-master. To move them to the per-client path: revoke and reissue.

### Fix #3 — Admin grant sync

`admin/post/users.php` user-edit save now syncs `user_client_grants` to match the new permission set:

1. Build target client list: explicit list from POST, OR all non-archived clients if unrestricted
2. Read current grants for the user
3. For clients in current-grants minus target → `adminRevokeClientGrant()`
4. For clients in target minus current-grants → `adminGrantClientToUser()`

`adminGrantClientToUser` is idempotent (`INSERT … ON DUPLICATE KEY UPDATE`). If the target user has no pubkey yet (never logged in post-Phase-10), grant creation silently no-ops — the lazy backfill at the user's next login picks it up.

This makes the admin UI "do the right thing" for grants without any new modal or button. Just edit the user's client access list and save — grants follow.

### Self-test
`scripts/phase11_self_test.php` — 13 tests covering:
- PIN KEK dual-wrap of master + privkey, with both round-tripping under correct PIN and rejecting under wrong PIN
- PRF KEK dual-wrap, same properties
- Per-client API key wrapping recovers ONLY the scoped client master, with wrong-password rejection
- Empty/absent column returns null (global API key behaviour)

### Cumulative self-tests
**111 / 0 failures** across 10 suites: crypto 20, Entra SSO 11, vault PIN 5, vault PRF 7, vault enrolment 6, audit log 6, WebAuthn 15, client master keys 13, keypair 15, phase 11 13.

### Operator action required
1. Run database migration: `Admin → Update → Update Database`.
2. Run the new self-test: `php scripts/phase11_self_test.php`.
3. **For existing PIN/PRF unlock methods** (set up before Phase 11): they keep working but fall back to shared-master path. To get compartmentalisation through PIN/PRF, users must re-enrol their PIN or PRF method while logged in via password (so the privkey is in their session).
4. **For existing API keys**: per-client compartmentalisation requires reissue. Consider rotating client-scoped API keys.
5. **Admin grant sync** kicks in automatically on next user-edit save.

### Remaining known limitations (small, documented)
- **JIT-only users without password**: cannot bootstrap a keypair until they have a session with the master key. Magic-link enrolment + PIN setup currently does not generate a keypair (no privkey to wrap). They fall back to shared-master path. A small follow-up could generate a keypair purely under PIN at enrolment time for JIT-only users.
- **Global API keys** (`api_key_client_id = 0`): explicitly non-compartmentalised by design. Migrate to per-client API keys for compartmentalisation.

## v0.11.0-nis2-keypair — Phase 10: Per-user keypair compartmentalisation

True cryptographic compartmentalisation. Each user gets their own X25519 keypair. The private key is wrapped under their unlock factor (Argon2id KEK from password). Client master keys are sealed-box encrypted to each authorised user's public key, stored in `user_client_grants`. **A compromised user can decrypt only the clients for which a grant exists for them in the database — other clients' grants are sealed under other users' public keys and unopenable.**

This is what the original NIS2 Art. 21(2)(i) blast-radius reduction asked for and what phase 9 stopped short of.

### Schema migration `2.4.4.7 → 2.4.4.8`
- `users.user_pubkey` (varchar 128) — base64 X25519 public key
- `users.user_privkey_wrapped` (varchar 512) — base64 of `salt(16) || cryptoEncryptV2(privkey, Argon2id(password, salt))`
- New table `user_client_grants(user_id, client_id, wrapped_client_key, granted_at, granted_by_user_id, last_used_at)` — one row per authorised (user, client) pair, unique constraint, FK-cascaded on user and client.

### Cryptographic helpers (`functions.php`)
- `userGenerateKeypairForPassword($password)` — generate X25519 keypair, wrap privkey under Argon2id KEK.
- `userUnwrapPrivkey($wrapped, $password)` — recover privkey from wrapping.
- `userRewrapPrivkey($wrapped, $old_pw, $new_pw)` — preserve keypair across password change.
- `wrapClientKeyForUser($client_master, $recipient_pubkey)` — sealed-box (anonymous-sender) using libsodium `crypto_box_seal`.
- `unwrapClientKeyFromGrant($wrapped, $privkey)` — `crypto_box_seal_open`.
- `pushUserPrivkeyToSession($privkey)` / `userPrivkeyFromSession()` — session-level wrap of privkey alongside the master key, using the same `user_encryption_session_key` cookie.
- `backfillUserCryptoMaterial($user_id, $password, $shared_master, $mysqli)` — at login: ensure keypair exists; for every client the user has app-layer access to, materialise a per-user grant. Idempotent and lazy.
- `getClientMasterKeyViaGrant($client_id, $mysqli)` — preferred unwrap path; returns null if no grant.
- `materialiseGrantForCurrentUser($client_id, $client_master, $mysqli)` — opportunistic grant write when shared-master fallback is used during writes.
- `adminGrantClientToUser($admin_id, $target_user_id, $client_id, $mysqli)` — admin-driven grant. Requires the target user to have a public key (i.e. has logged in at least once since the migration).
- `adminRevokeClientGrant($target_user_id, $client_id, $mysqli)` — destroys the grant; user can no longer decrypt that client via the compartmentalised path.

### Login flow (`login.php`)
- After `unlockUserMasterKey()` succeeds, `backfillUserCryptoMaterial()` runs while the password is in scope. The unwrapped privkey is stashed in `pending_dual_login` / `pending_mfa_login` (alongside `agent_master_key`) and ultimately `pushUserPrivkeyToSession()`'d at the success branch.
- `login_webauthn_verify.php` also pushes the privkey to session after WebAuthn 2FA succeeds.

### Decrypt path
`decryptCredentialEntry($ct, $client_id)` for v3 ciphertexts now:
1. Tries `getClientMasterKeyViaGrant($client_id)` — the compartmentalised path.
2. Falls back to `ensureClientMasterKey($client_id)` — the legacy shared-master path during the migration window.

Once all users have logged in once post-migration, every authorised access goes through the grant path.

### Encrypt path
`encryptCredentialEntry($pt, $client_id)` similarly prefers the grant path. When the fallback path is used, `materialiseGrantForCurrentUser()` opportunistically writes a grant for the current user so subsequent reads use the compartmentalised path immediately.

### Password change / admin reset
- Self-change in `agent/user/post/profile.php`: drops `user_pubkey` and `user_privkey_wrapped` (the privkey was wrapped under the OLD password), and deletes all rows in `user_client_grants` for that user. Lazy backfill at next login regenerates everything from scratch using `user_client_permissions`.
- Admin reset in `admin/post/users.php`: same treatment.
- User archive in `admin/post/users.php`: clears keypair material and deletes grants alongside the existing master-key-clear.

### Self-test (`scripts/keypair_self_test.php`)
15 offline tests, all passing. Notably:
- **Bob's privkey cannot open Alice's grant**, even though both grants wrap the same client master key under different recipients' public keys. This is the compartmentalisation property the phase delivers.
- Tamper detection on the sealed box.
- Password change rewrap preserves the keypair (round-trip under the new password).

### Cumulative self-tests
98 / 0 failures across 9 suites: crypto 20, Entra SSO 11, vault PIN 5, vault PRF 7, vault enrolment 6, audit log 6, WebAuthn 15, client master keys 13, keypair 15.

### Compromise model after phase 10

| Adversary | Outcome |
|-----------|---------|
| Compromised agent X with vault unlocked | Can decrypt clients they have a grant for. **Cannot decrypt other clients** — those grants are sealed under other users' public keys. |
| Compromised agent X with no grants | Can fall back to shared-master path (legacy). After the migration is complete and the shared-master wrapping is dropped (future phase), this fallback closes. |
| Database leak | Wrappings are present, but each privkey is Argon2id-protected by its user's password. Per-user brute-force required; one cracked password gives only that user's grants. |
| Stolen unlocked workstation | Layer 4 still holds. Vault is unlocked → privkey is in session → grants can be opened. Unchanged from earlier phases. |

### Operator action required
1. Run database migration: `Admin → Update → Update Database` (or `php scripts/update_cli.php --update_db`).
2. Run the self-test: `php scripts/keypair_self_test.php` should report `15 tests, 0 failures`.
3. Have all agents log in once via password (or via password followed by MFA). The first such login generates their keypair and back-fills grants for every client they have app-layer access to.
4. After every active agent has logged in: verify with
   ```sql
   SELECT user_id, user_email,
          CASE WHEN user_pubkey IS NULL THEN 'no keypair yet' ELSE 'migrated' END AS keypair,
          (SELECT COUNT(*) FROM user_client_grants g WHERE g.user_id = u.user_id) AS grants
   FROM users u WHERE user_status = 1 AND user_archived_at IS NULL;
   ```
   All active agents should show `migrated` and a non-zero grant count.
5. (Future, deferred) Once the migration is complete, drop the shared-master fallback by clearing `client_master_keys.wrapped_under_shared`. After that point, a user without a grant truly cannot decrypt that client's data.

### Known limitations
- **SSO + PIN / SSO + PRF unlock paths**: the privkey is wrapped only under the password, not under the PIN or PRF KEK. Users who unlock via PIN/PRF get the master key in session but not the privkey, so they fall back to the shared-master path (no compartmentalisation for them yet). This is the next-most-important follow-up — wrap a copy of the privkey under each enrolled vault unlock method. Schema columns are already there (`user_vault_unlock_methods.salt` / `wrapped_master_key` could be extended) but it's a separate phase.
- **API keys** still use the legacy shared-master path. API consumers do not get compartmentalisation in this phase.
- **Admin grant management UI**: not added in this phase. The lazy backfill at user login covers most operational cases. Explicit admin grant operations are exposed via `adminGrantClientToUser()` / `adminRevokeClientGrant()` for future UI work.

### Forward compatibility
The shared-master fallback is a deliberate transition aid and not a permanent feature. Once you have confirmed every active agent has a populated `user_pubkey` and grants for all their clients, you can run a one-off cleanup (`UPDATE client_master_keys SET wrapped_under_shared = NULL`) to remove the escrow. After that, only the per-user grant path works — full compartmentalisation enforced.

## v0.10.0-nis2-per-client — Phase 9: Per-client master keys

Each client now has its own master key. New credentials are encrypted under the client's key (v3 ciphertext format), wrapped under the existing shared master key. This enables per-client key rotation, per-client secure delete (destroy a client's key → all their credentials become unrecoverable), and forensic separation in incident notifications.

### What this is, and what it isn't

**What it is:**
- Each `clients` row gets a unique 16-byte master key (lazy-created on first credential write for that client)
- New credentials use the v3 format: `"v3:" || base64(AES-256-GCM(plaintext, HKDF(client_master_key)))`
- The client's master key is stored wrapped under the shared session master key in `client_master_keys.wrapped_under_shared`
- Read paths transparently handle v1, v2 (shared), and v3 (per-client) ciphertexts
- Old credentials remain readable in their existing format and are migrated to v3 on the next save

**What it isn't (yet):**
This phase does NOT achieve full cryptographic compartmentalisation against a malicious user. All client keys are wrapped under the same shared session master key, so a user with vault access can technically unwrap any client's key. Full compartmentalisation requires per-user keypairs (Bitwarden-style) and is reserved for a future phase. The wins this phase delivers are:
- **Per-client rotation** — re-key one client without touching others
- **Per-client secure delete** — drop a client's key in `client_master_keys` and that client's credentials become unrecoverable, even if the encrypted data remains in backups
- **Forensic separation** — for Article 23 incident notification, the encryption boundary aligns with the application boundary
- **Architecture readiness** — the schema and helpers are in place for phase 10+ (per-user keypairs)

### Schema migration `2.4.4.6 → 2.4.4.7`
- New table `client_master_keys` (one row per client, FK to `clients` with `ON DELETE CASCADE`)

### Added
- `functions.php`:
  - `ensureClientMasterKey($client_id, $mysqli)` — read or lazy-create a client's master key. Requires the session master key (vault unlocked).
  - `encryptCredentialEntryV3()` / `decryptCredentialEntryV3()` — v3 wrap/unwrap.
  - `isCredentialV3()` detector.
  - `decryptCredentialEntry()` and `encryptCredentialEntry()` extended with optional `$client_id` parameter. v3 ciphertexts require it; v1/v2 ignore it.
  - `apiDecryptCredentialEntry()` / `apiEncryptCredentialEntry()` extended with `$client_id` for the API path; lazy-creates client keys directly without going through the session.
- `scripts/client_master_key_self_test.php` — 13 offline tests covering wrap/unwrap, v3 round-trip, cross-client decrypt failure, prefix detection, tamper detection.

### Changed
- All credential read sites now pass `$row['credential_client_id']`:
  - `agent/credentials.php`, `agent/global_search.php`, `agent/contact_details.php`, `agent/client_overview.php`, `agent/asset_details.php`, `agent/ajax.php`
  - `agent/modals/credential/credential_edit.php`, `agent/modals/contact/contact_details.php`, `agent/modals/asset/asset_details.php`
  - `agent/post/credential.php` (compare-old-and-new path), `agent/post/client.php` (export path)
  - `api/v1/credentials/read.php`
- All credential write sites now pass `$client_id`:
  - `agent/post/credential_model.php` (using `$client_id` from parent scope)
  - `agent/post/credential.php` (CSV import path)
  - `agent/post/asset.php` (asset-bound credential)
  - `api/v1/credentials/credential_model.php`
- `agent/post/credential.php` reordered so `$client_id` is set BEFORE `require_once 'credential_model.php'` (the model now uses it).

### Operator action required
- Run database migration: `Admin → Update → Update Database` or `php scripts/update_cli.php --update_db`.
- No manual data migration. Existing credentials stay v1/v2 and are upgraded to v3 on next save (lazy migration, same pattern as Phase 1).
- New credentials and any save of an existing credential auto-create the client's master key on first use.

### Verifying the migration ran
```sql
SELECT c.client_id, c.client_name,
       CASE WHEN cmk.client_id IS NULL THEN 'no key yet'
            ELSE 'created ' END AS status,
       cmk.created_at, cmk.key_version
FROM clients c
LEFT JOIN client_master_keys cmk ON cmk.client_id = c.client_id
WHERE c.client_archived_at IS NULL;
```

A client with no row in `client_master_keys` simply has not had a credential saved since the migration. Save any credential for that client and the key materialises.

### Known limitations
- No cryptographic compartmentalisation against a malicious user (deferred to phase 10).
- Per-client key rotation tooling is not shipped here (you'd `DELETE FROM client_master_keys WHERE client_id = X`, save all that client's credentials again, repeat). Phase 10+ may add a CLI rotation script.
- Per-client secure-delete is functional today: `DELETE FROM client_master_keys WHERE client_id = X` permanently removes the unwrap path. Existing v3 ciphertexts for that client are no longer decryptable. Document this in your data-retention procedures.

### Cumulative self-tests
83 / 0 failures across crypto (20), Entra SSO (11), vault PIN (5), vault PRF (7), vault enrolment (6), audit log (6), WebAuthn (15), client master keys (13).

## v0.9.0-nis2-ops — Phase 8: Operationalisation

Four NIS2-relevant operational improvements bundled. Each is independently small but together they close visible gaps from the post-phase-7 NIS2 review.

### Schema migration `2.4.4.5 → 2.4.4.6`
- `api_keys.api_key_decrypt_hash_v2` (VARCHAR 512, nullable) — v2 wrapped master key
- `settings.config_security_audit_retention_days` (INT, default 365)
- `settings.config_force_phishing_resistant_mfa` (TINYINT) — global flag, currently used as future-proofing; per-user enforcement is via `users.user_force_webauthn`
- `users.user_force_webauthn` (TINYINT) — admin-set per-user flag
- New table `pending_vault_enrolments` for magic-link enrolment

### 8a — API key v2 wrapping (NIS2 Art. 21(2)(h))

API keys previously wrapped the master key with the legacy v1 stack (PBKDF2-SHA256 + AES-128-CBC) regardless of the user-side v2 migration done in Phase 1. They now use the same Argon2id + AES-256-GCM stack as user wrappings:

- `apiUnlockMasterKey()` helper — v2 first, v1 fallback, lazy migration on first successful v1 unwrap.
- `apiEncryptCredentialEntry` / `apiDecryptCredentialEntry` accept either the full `api_keys` row (preferred) or the legacy hash string (backward-compatible callers).
- New API keys created via `admin/post/api_keys.php` get both v1 and v2 wrappings written at create time.
- `api/v1/validate_api_key.php` exposes the row to downstream credential helpers.
- API consumers do not need to change anything; the password they pass is unwrapped via whichever method is present.

### 8b — Audit log retention (NIS2 Art. 21(2)(b))

The hash-chained `security_audit_log` previously grew unbounded. The configurable retention period is honoured by a new prune script:

- `scripts/audit_prune.php` — reads `config_security_audit_retention_days`, writes entries older than the cutoff to a gzip-compressed JSONL archive in `uploads/audit_archive/`, computes its SHA-256, inserts a synthetic `audit.archived` event with metadata pointing to the archive, and re-anchors the live chain (the marker uses `prev_hash = NULL_HASH` so the chain after pruning verifies cleanly from genesis).
- `scripts/audit_verify.php` updated: when no `--from` is given and an `audit.archived` marker exists, the verifier auto-anchors at the latest marker. Pre-marker entries are in the archive and verifiable offline against the SHA-256 stored in the marker. Pass `--all` to walk pre-marker rows (will report inconsistencies once a chain crosses an archive boundary).
- Recommended cron: `0 3 * * *  /usr/bin/php /path/to/itflow/scripts/audit_prune.php`

### 8c — Magic-link vault enrolment for SSO-only / JIT agents (NIS2 Art. 21(2)(i))

Resolves the long-standing chicken-and-egg for JIT-provisioned SSO users: they have no password, so the master key was never wrapped under any factor for them, so they could not enrol PIN/PRF themselves.

- `includes/vault_enrolment.php`:
  - `vaultIssueEnrolmentToken()` — generates a 32-byte token, derives a one-shot KEK via Argon2id, wraps the master key under it, stores token bcrypt-hash + wrapped key + salt in `pending_vault_enrolments` with 1-hour expiry. Caller must already have the master key in their session.
  - `vaultRedeemEnrolmentToken()` — atomically claims the row (single use), recovers the master key.
- `agent/vault_enrol.php` — endpoint reachable via the magic link. Requires the user to be SSO-authenticated (bounces to `/login.php` otherwise so they SSO and return). On successful redemption: regenerates session id, generates session encryption material, sends the user to `/agent/user/user_security.php?enrolment=ok` to complete PIN / PRF enrolment.
- `admin/post/users.php` — handler for `?send_vault_enrolment&user_id=…&csrf_token=…`. Issues the token and emails it via the existing mail queue. If SMTP is not configured, surfaces the link via flash alert so the admin can hand it off out of band.
- `admin/modals/user/user_edit.php` — adds a "Send vault enrolment link" button per user.
- Audit events emitted: `vault.enrolment.created`, `vault.enrolment.redeemed`, `vault.enrolment.failed`.

Threat model:
- Email interception: attacker also needs to be SSO-authenticated as the target user (Entra MFA + conditional access blocks this).
- Replay: token is single-use; `consumed_at` is set atomically before crypto unwrap proceeds.
- Stale links: 1-hour TTL.

### 8d — Phishing-resistant MFA enforcement (NIS2 Art. 21(2)(j))

Per-user admin flag `user_force_webauthn`. When set:
- `login.php` rejects TOTP code submissions for that user (the `current_code` field is ignored).
- The remember-me cookie bypass is disabled for that user.
- The user must complete the WebAuthn ceremony to log in.

UI:
- Checkbox "Require phishing-resistant MFA (WebAuthn only)" added to `admin/modals/user/user_edit.php` next to the existing Force MFA toggle.

This is per-user rather than global because not every agent will have a hardware authenticator immediately. Admins flip the bit once the user has enrolled at least one WebAuthn credential.

### Self-tests
New `scripts/vault_enrolment_self_test.php` covers the magic-link wrap/unwrap round-trip, wrong-token rejection, wrong-salt rejection, and tamper detection. Six tests, all passing. Cumulative: 70 self-tests, 0 failures across crypto / SSO / vault PIN / vault PRF / vault enrolment / audit log / WebAuthn.

### Operator action required
- Run database migration: `Admin → Update → Update Database` (or `php scripts/update_cli.php --update_db`).
- Add `php scripts/audit_prune.php` to a daily cron.
- (Optional) For SSO-only agents: edit each user → "Send vault enrolment link" so they can self-enrol PIN / PRF without an out-of-band password.
- (Optional) For agents who have enrolled WebAuthn: set "Require phishing-resistant MFA" so TOTP becomes unavailable for those accounts.

### Not in scope (deferred)
- **Per-client master keys** — the largest remaining technical NIS2 gap. Touches every credential read/write path and requires a substantial data migration. Will ship as Phase 9 separately to give it the attention it warrants.

## v0.8.0-nis2-prf — Phase 7: WebAuthn PRF for vault unlock

This phase adds hardware-bound vault unlock via the WebAuthn PRF extension. After SSO sign-in, agents tap their security key (Touch ID, Windows Hello, YubiKey 5+, platform passkey) and the vault unlocks in a single ceremony — no PIN typing. The existing PIN method remains as the recovery fallback.

### Added
- `includes/vault_unlock.php` PRF helpers:
  - `vaultDeriveKekFromPrf()` — HKDF-SHA256 expansion of the 32-byte PRF output to a 32-byte AES-256-GCM key, namespaced with the label `itflow-vault-prf-v1`.
  - `vaultStorePrfMethod()` — wraps the master key under the PRF-derived KEK and stores a `webauthn_prf` row using the schema columns reserved in Phase 3 (`credential_id`, `public_key`, `sign_count`, `prf_salt`).
  - `vaultFindPrfMethodByCredentialId()` and `vaultTryUnlockWithPrf()` for the unlock path, including the same per-method 5-strikes/15-min lockout used by PIN.
- Enrollment endpoints:
  - `agent/user/webauthn_prf_register_options.php` — issues `PublicKeyCredentialCreationOptions` with the PRF extension (`extensions.prf.eval.first`).
  - `agent/user/webauthn_prf_register_verify.php` — verifies the registration response, requires the PRF result returned by the authenticator at registration, wraps the master key, stores the row.
- Unlock endpoints:
  - `agent/vault_unlock_prf_options.php` — issues `PublicKeyCredentialRequestOptions` with `extensions.prf.evalByCredential` so each enrolled credential gets its own PRF salt.
  - `agent/vault_unlock_prf_verify.php` — verifies the assertion signature, decodes the PRF output, unwraps the master key, calls `generateUserSessionKey()`. Tries ES256 then RS256 against the stored PEM.
- Browser-side helpers (external files; strict CSP allows them as same-origin scripts):
  - `plugins/webauthn/vault-prf-enroll.js`
  - `plugins/webauthn/vault-prf-unlock.js`
- `scripts/vault_prf_self_test.php` — 7-test offline check covering PRF KEK derivation determinism, length, sensitivity, wrap/unwrap round-trip, wrong-PRF rejection, and tamper detection. All passing.

### Changed
- `agent/vault_unlock.php` — when at least one PRF method is enrolled, renders a "Unlock with security key" button that auto-starts the ceremony on page load (`data-autostart="1"`). The PIN form is shown beneath it as a fallback when also enrolled. PIN-only users see the PIN form directly (unchanged).
- `agent/user/user_security.php` — adds an "Add hardware unlock" form alongside the existing PIN setup. Both are gated on the master key being present in the current session (so they require a password sign-in or PIN unlock first).

### No schema migration
Phase 3 already reserved the columns: `credential_id`, `public_key`, `sign_count`, `prf_salt` in `user_vault_unlock_methods`. The PRF rows are stored with `method_type = 'webauthn_prf'` and `salt = ''` (the per-Argon2id salt column is unused for PRF; it's `NOT NULL` in the schema so we store an empty string).

### Security properties

| Property | Vault PIN (Phase 3) | WebAuthn PRF (this phase) |
|----------|--------------------|---------------------------|
| KEK derivation | Argon2id(PIN, salt) | HKDF-SHA256(PRF output) |
| Brute-force at DB-leak | Argon2id-bounded (slow but possible) | Impossible — PRF output never leaves the authenticator |
| Phishing | PIN typeable on attacker site | Origin-bound; PRF result differs per origin |
| Replay | Per-method lockout | Server-issued challenge + assertion signature |
| Recovery | n/a | PIN method retained as fallback (recommended) |

### Operator action required
- No database migration. Existing self-tests still pass; the new PRF self-test (`scripts/vault_prf_self_test.php`) confirms the KEK derivation and wrap/unwrap.
- HTTPS is required for WebAuthn except on `localhost`. Production deployments must terminate TLS.
- Recommended policy (document in your risk register):
  > Agents must keep at least one PIN method enrolled in addition to PRF, so a lost or unavailable authenticator does not lock them out of the vault permanently.

### Known limitations
- Cross-device passkey portability depends on the authenticator. Platform passkeys (Touch ID via iCloud, Windows Hello synced via Microsoft account) carry across the user's devices; YubiKeys do not.
- Bitwarden's passkey storage does not yet support the PRF extension consistently. Recommend using Windows Hello / Touch ID / a hardware key that supports CTAP 2.1+ for PRF.
- The `cose_alg` is not stored separately for PRF rows; the verifier tries ES256 first then RS256 against the stored PEM. This works for the supported algorithms but is slightly less explicit than the `user_webauthn_credentials` table where it is recorded.

## v0.7.0-nis2-webauthn — Phase 6: WebAuthn second factor

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
