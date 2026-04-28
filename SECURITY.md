# Security Policy

This is a security-hardened fork of [itflow-org/itflow](https://github.com/itflow-org/itflow). It modifies the upstream codebase to align with NIS2 cryptographic and access-control expectations.

## Threat model

This fork is intended for use by Managed Service Providers (MSPs) operating under EU NIS2 obligations. The relevant threat actors and assets are:

| Asset | Confidentiality | Integrity | Availability |
|-------|-----------------|-----------|--------------|
| Stored client credentials (passwords, keys) | Critical | Critical | High |
| Agent identities and roles | High | Critical | High |
| Audit and login logs | Medium | Critical | Medium |
| Customer business data (tickets, assets) | High | High | High |

### In-scope adversaries

1. **Database compromise** — read access to the `itflow` database via SQL injection, leaked backup, or stolen storage. Must not yield plaintext credentials without an additional online interaction.
2. **Network attacker on the LAN** — must not be able to intercept session material in transit. HTTPS is mandatory in any production deployment.
3. **Phished agent** — must not yield session takeover when phishing-resistant MFA (WebAuthn) is enrolled.
4. **Compromised agent workstation** — limited mitigation possible at application layer; partly mitigated by per-session unlock and short session lifetime.

### Out of scope

- Full compromise of the application server (root RCE on the host running ITFlow). At that point all in-memory secrets are accessible. Operational hardening of the host is the operator's responsibility.
- Compromise of the identity provider (Microsoft Entra ID) — outside ITFlow's trust boundary.
- Side-channel attacks against the underlying CPU/cloud platform.

## Reporting a vulnerability

Report vulnerabilities privately via GitHub Security Advisories on this repository. Do not file public issues for security problems. Acknowledgement within 5 working days; expected fix turnaround within 30 days for high-severity issues.

For coordinated disclosure with upstream itflow-org, this fork's maintainer will forward applicable findings via the upstream project's GitHub Security Advisories.

## Cryptographic posture

See [docs/crypto-policy.md](docs/crypto-policy.md) for the canonical statement of approved algorithms, key lifecycle, and review cadence.

Summary of differences from upstream:

| Aspect | Upstream | This fork |
|--------|----------|-----------|
| Symmetric cipher | AES-128-CBC | AES-256-GCM |
| Authenticated encryption | No | Yes |
| Password KDF | PBKDF2-SHA256 (100k) | Argon2id (interactive params) |
| Ciphertext versioning | None | 2-byte header (version + algorithm) |
| Agent SSO | Not supported | Microsoft Entra ID (OIDC) |
| Vault unlock for SSO users | n/a | WebAuthn PRF + PIN fallback |
| Phishing-resistant MFA | TOTP only | WebAuthn (FIDO2) |
| Telemetry | Sent on update if enabled | Respects opt-out (upstream bug fixed) |

## Supported versions

Only the `master` branch of this fork is supported. Security fixes are not back-ported to earlier states.

## Update mechanism

This fork ships with the upstream-style in-app updater (`Admin > Update`) and CLI updater (`scripts/update_cli.php`), modified to respect the configured `$repo_branch` instead of the hardcoded `master`. Both run a `git pull` against the configured remote, which should be set to this fork.

Recommended remote setup on a server that previously ran upstream:

```bash
cd /path/to/itflow
git remote set-url origin https://github.com/jortiexx/itflow-nis2.git
git fetch origin
git reset --hard origin/master
```

After this point the in-app updater pulls from this fork.
