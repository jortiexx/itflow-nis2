# Upgrade test playbook

End-to-end validation that a vanilla **itflow-org/itflow** install upgrades cleanly to this fork (`jortiexx/itflow-nis2`) without losing data or breaking features.

Goal: prove that an existing customer with a real ITFlow database can drop in this fork's code, click "Update Database" once, and end up with everything working — credentials still readable, files still downloadable, photos still rendering, audit log intact.

Run this in a throwaway environment (a fresh XAMPP / Docker / VM). Do **not** run it against production.

---

## 0 — Prerequisites

- PHP 8.2+ with the usual ITFlow extensions (mysqli, gd, openssl, sodium, mbstring, intl).
- MySQL/MariaDB.
- Apache or nginx with rewrite rules (XAMPP works).
- `git` on the path.

Make a note of:
- The MySQL root password.
- A throwaway database name (e.g. `itflow_upgrade_test`).
- The webroot path (e.g. `C:/xampp/htdocs/itflow_test/`).

---

## 1 — Install vanilla ITFlow

```bash
cd /path/to/your/webroot
git clone https://github.com/itflow-org/itflow.git itflow_test
cd itflow_test
git checkout master   # or pin to the release you'd consider "current upstream"
```

Browse to `http://localhost/itflow_test/` → `setup/index.php` will run. Walk through the wizard:

1. Create the database (`itflow_upgrade_test`).
2. Create the first admin user — note the email + password; you'll log in as this user later.
3. Skip company-logo upload for now (we'll add it in step 4).
4. Finish the wizard.

After setup, log in once at `/login.php` to confirm the app works on vanilla.

**Sanity check before upgrading:**
- Note `Admin → Update`'s "Current DB Version" — write it down.
- Note that `uploads/.htaccess` is the upstream version (only blocks PHP execution).

---

## 2 — Seed sample data

From the install root:

```bash
php scripts/seed_sample_data.php --verbose
```

Wait — `scripts/seed_sample_data.php` lives in **this fork**, not vanilla. Two options:

**Option A — copy the seeder over before the fork swap.**
Download just the seeder file from this fork and drop it in:
```bash
curl -o scripts/seed_sample_data.php \
  https://raw.githubusercontent.com/jortiexx/itflow-nis2/master/scripts/seed_sample_data.php
php scripts/seed_sample_data.php --verbose
```

**Option B — seed after the fork swap.**
Skip this section, do step 3 first, then run the seeder. Either order works because the seeder uses INSERTs that target the upstream schema (clients, contacts, assets, credentials, documents, files); none of the fork-specific columns are required at insert time.

After seeding you should see:
```
Clients created:     3
Contacts created:    6
Assets created:      5
Credentials created: 5
Documents created:   3
Files created:       5
```

Verify in the UI:
- `Admin → Clients` → Acme, Globex, Initech are listed.
- Click into Acme → contacts, assets, credentials, documents tabs are populated.
- Open one credential — the password is plaintext (no `v2:` / `v3:` prefix). This is intentional: it represents a pre-fork install.
- Open one file — it downloads as plaintext (since vanilla doesn't encrypt files).

---

## 3 — Switch the remote to this fork

```bash
git remote -v          # confirm origin is itflow-org/itflow
git remote set-url origin https://github.com/jortiexx/itflow-nis2.git
git fetch origin
git checkout master
git reset --hard origin/master   # WARNING: discards any local changes
```

You're now sitting on the fork's code with vanilla's database. Refresh the browser and open any agent page.

**Expected:** the page loads. Even though the DB schema is missing every fork-added column (`file_encrypted`, `client_master_keys.legacy_files_swept_at`, `config_ratelimit_*`, etc.), the helpers all detect missing-schema and short-circuit. (Bug we hit live and fixed in v0.17.1 — the schema-ready guards in `legacy_file_sweeper.php` and try/catch in `rate_limit.php`.)

---

## 4 — Run the database migrations

Browse to `Admin → Update`. The "Update Database" alert should appear with current version below latest.

**If it says you're up to date but you know you aren't**, the version_compare fix from v0.17.2 hasn't applied yet — re-pull, hard-refresh.

Click **Update Database**. The button POSTs to `post.php?update_db`, which runs all pending migrations in a single request. (Pre-v0.17.2: only one migration step ran per click and you'd have to click many times; the loop in `database_updates.php` resolves that.)

Expected on success:
- Flash alert: "Database structure update successful"
- `Admin → Update` now shows the latest version
- No PHP errors in the log

**Verify in DB:**
```sql
SELECT config_current_database_version FROM settings;
-- should show the latest, e.g. 2.4.4.12

SHOW COLUMNS FROM files LIKE 'file_encrypted';                        -- present
SHOW COLUMNS FROM client_master_keys LIKE 'legacy_files_swept_at';    -- present
SHOW COLUMNS FROM settings LIKE 'config_ratelimit_login_max';         -- present
```

---

## 5 — First admin login → vault unlock → legacy file sweep

Log out, then log back in as the admin.

If the admin has a vault method enrolled (PIN or WebAuthn-PRF), `vault_unlock.php` prompts. If not, set one up via the user profile menu.

After vault unlock, **the next page navigation should redirect to `/agent/migrate_legacy_files.php`** — the progress-bar UI for re-encrypting the seeded plaintext files.

You should see:
- "A one-time sweep is encrypting **5** file(s)..."
- Progress bar fills from 0% → 100% within a few seconds (5 files is trivial)
- "Done! Redirecting…" then drops back to the home page

**Verify in DB:**
```sql
SELECT COUNT(*) FROM files WHERE file_encrypted = 1;        -- should be 5
SELECT COUNT(*) FROM files WHERE file_encrypted = 0;        -- should be 0
SELECT client_id, legacy_files_swept_at FROM client_master_keys;
-- should show 3 rows, all with legacy_files_swept_at filled in
```

**Verify in audit log:**
```sql
SELECT audit_event_type, COUNT(*) FROM security_audit_log
 WHERE audit_event_type LIKE 'file.migrate.%'
 GROUP BY audit_event_type;
-- expect file.migrate.encrypted (5) + file.migrate.client_complete (3)
```

**Verify on disk:**
```bash
xxd uploads/clients/1/<reference>.txt | head
```
The bytes should look like ciphertext (no readable text), not the plaintext you seeded.

---

## 6 — Verify reads still work

For each of the seeded clients:

**Files:** open the client → `Files` → click a file → it downloads → contents match what the seeder put in. (Decrypted on the way out by `agent/file_download.php`.)

**Credentials:** open one credential → click reveal-password → the seeded password (`pl@inText-Adm1n!`, etc.) appears. The DB column is still raw plaintext at this point because the credential hasn't been re-saved yet — `decryptCredentialEntry` passes plaintext through.

**Re-encrypt one credential:** edit the credential, click Save without changing anything. The password is now stored as `v3:…` in the DB. Verify:
```sql
SELECT credential_password FROM credentials WHERE credential_id = 1;
-- should start with the bytes "v3:"
```
Re-open the credential in the UI — same password decrypts back. ✓

**Documents:** open a document → content renders normally. (Document content was deliberately *not* encrypted post-v0.14.1; this is the right behavior.)

**Photos:** none seeded by default. Upload a profile photo on a contact → confirm it renders via `/photo.php?type=contact&id=N` (network tab in devtools).

---

## 7 — Verify rate limits

`Admin → Settings → Security` → scroll to "Rate limiting" section. Defaults are visible:
- Login: 10 / 600s
- Vault: 20 / 600s
- SSO: 20 / 600s
- API: 30 / 600s
- Password reset: 5 / 3600s

Tighten one (e.g. login to 3 / 60s), save. Log out, deliberately fail login 3 times, then a 4th time — should see HTTP 429.

```sql
SELECT log_action, log_ip, log_created_at FROM logs
 WHERE log_type = 'Login' ORDER BY log_id DESC LIMIT 10;
-- expect a 'Blocked' entry after the failures
```

Reset the threshold to defaults afterwards.

---

## 8 — Cleanup

```bash
php scripts/seed_sample_data.php --reset
```

This deletes the seeded clients + their files, contacts, assets, credentials, documents. Drop the DB if you want to start over.

---

## What to flag if something breaks

If any step fails, capture:
- The exact step + expected vs actual.
- PHP error log excerpt (`logs/php_error.log` or your webserver's error log).
- Browser network tab screenshot if the failure is client-side.
- `SELECT * FROM logs ORDER BY log_id DESC LIMIT 20`.
- Current DB version (`SELECT config_current_database_version FROM settings`).

Most likely failure modes (sorted by probability):
1. **Schema migration aborts mid-way.** Either (a) the loop detects no progress and breaks (look at `migration_iterations`), or (b) one of the ALTER statements clashes with existing data. The `database_updates.php` ALTERs are pure DDL — they shouldn't, unless your install has been heavily customized.
2. **Vault doesn't unlock.** Phase 9+ requires a PIN/PRF method enrolled. If the seeded admin has none, set one via the profile menu.
3. **Legacy file sweep stalls.** `migrate_legacy_files.php` shows "5 batches with no progress" → that means a per-client master key couldn't be derived. Check `client_master_keys` exists and the admin has grants in `user_client_grants`.
4. **A header is missing on a page.** The `security_headers.php` include path is brittle — if a public entry point doesn't include it explicitly, the headers don't apply. `curl -I https://your-host/login.php` to verify.
