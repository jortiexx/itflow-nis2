# Vault operations runbook

Operator-facing playbook for the per-client encrypted vault (phase 13+).
This is the document an admin pulls up at 02:00 when something is on fire.
Bookmark it.

## Glossary in one paragraph

A **master key** decrypts every per-client master key in the database.
Each agent owns one or more **unlock methods** (`pin`, `webauthn_prf`)
that wrap the master key under a method-specific KEK. Removing a method
revokes the agent's *path* to the master; it does **not** invalidate the
master itself. If the master has leaked, a rotation is required.

## Choosing the right control

| Symptom | Use |
|---|---|
| User wants to retire one security key but keep their PIN | **Disable** the FIDO2 row (self-service, reversible) |
| User lost a security key but is sure it wasn't stolen | **Remove** the row (self-service, not reversible) |
| User left the company / extended leave | Admin → Archive user (cascades unlock methods + grants) |
| Suspected device theft, no DB access concern | **Force vault re-enrolment** (admin) + send fresh enrolment link |
| Confirmed compromise of the master key (memory dump, malicious admin, DB exfil with KEK material) | Force re-enrolment for affected users **+** master-key rotation (`scripts/reset_master_key.php`) |
| Suspected DB-only exfil (no KEK material leaked) | No rotation needed — bearer secrets remain encrypted under the per-client master |

## Self-service: Disable vs Remove

In **My Account → Security**, each unlock method has two buttons:

- **Disable** (pause icon) — sets `disabled_at` on the row. The method is
  excluded from PRF assertion options and PIN unlock paths. Reversible
  via the Re-enable (play icon) button.
- **Remove** (trash icon) — `DELETE`s the row. Not reversible; the user
  must re-enrol.

Disable is the right choice when in doubt. It preserves the audit row
and lets you re-enable without a fresh enrolment ceremony.

## Admin: Force vault re-enrolment

Admin → Users → Edit → "Vault — incident response" → **Force vault
re-enrolment** wipes every PIN and FIDO2 method for the target user.
After this:

1. The user can still log in (their account password / SSO is untouched).
2. They cannot decrypt any credential or master-keyed file.
3. They need a fresh **vault enrolment link** (button immediately above)
   to set up a new PIN or FIDO2 method.

The action is logged via `securityAudit('vault.method.force_reenrol')`
with the actor, target, and methods-removed count.

## Master key rotation

`scripts/reset_master_key.php` is a destructive CLI tool. It generates a
new master key and re-encrypts every bearer secret (credentials,
TOTP secrets, OAuth refresh tokens, per-client masters, etc.) under the
new master, then re-wraps the new master under each user's existing
unlock methods.

Run it when **any of the following is true**:

- A copy of the master key may exist outside the vault (memory dump,
  swap file, debug log, malicious admin observation).
- A KEK with a wrap of the master may have leaked (full DB dump shipped
  to a forensic vendor; an old backup restored to an untrusted host).
- An audit / regulator demands it after an incident, regardless of
  evidence of actual compromise.

Do **not** run it for routine staff turnover or device retirement —
revoke the unlock method, that's enough.

### Rotation checklist

1. Quiesce: announce a 5–10 minute maintenance window. Active sessions
   keep working but new credential writes during rotation may land
   under the wrong key; safer to lock out.
2. Backup the database. The script is idempotent for read-only failures
   but a botched run is much easier to recover with a snapshot.
3. Run `php scripts/reset_master_key.php --confirm`. The `--confirm`
   flag is a deliberate safety net.
4. Verify: log in as a non-admin user, decrypt a credential. If it
   reads, rotation succeeded.
5. Audit: `securityAudit('vault.master.rotated')` is emitted by the
   script and chain-anchored. Verify the chain is intact via the
   security audit log viewer.

## Phase-18 controls reference

| Control | Default | Where to change |
|---|---|---|
| Vault idle timeout | 1800s (30 min) | Admin → Security → Vault hardening |
| Per-account lockout cap | 3600s (1 h) | Admin → Security → Vault hardening |
| Hardware-bound authenticators only | off | Admin → Security → Vault hardening |
| Step-up freshness window | 300s (5 min) | constant `VAULT_STEP_UP_DEFAULT_SECONDS` in `includes/vault_unlock.php` |
| Per-method PIN/PRF lockout (5 fails) | 15 min | constants `VAULT_LOCKOUT_*` in `includes/vault_unlock.php` |

## What NOT to do

- **Don't** delete `client_master_keys` rows by hand. The per-client
  master key is the only thing that can decrypt that client's
  credentials. Lose it, lose the data.
- **Don't** truncate `user_client_grants` to "fix" access issues. Run
  the lazy-backfill via a normal login instead — grants regenerate.
- **Don't** edit `wrapped_master_key` or `wrapped_privkey` in the DB.
  AAD is bound to user_id; manual edits will fail GCM verification.
- **Don't** share enrolment links via Slack/Teams/email-without-tls.
  They are bearer tokens valid for an hour. Use the admin's flash
  message to hand them off in person if SMTP is down.
