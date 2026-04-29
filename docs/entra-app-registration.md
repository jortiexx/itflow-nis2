# Registering the Entra ID app via PowerShell

The portal walkthrough lives in `admin/agent_sso_settings.php` (Setup notice at the top of that page). This document covers the same flow scripted via Azure CLI from PowerShell — useful when you do not want to click through the portal, or when you want a repeatable record of the registration for an audit trail.

The end state is identical to the portal flow:
- A single-tenant app named "ITFlow Agent SSO" with a Web redirect URI of `http(s)://<your-host>/agent/login_entra_callback.php`
- A client secret valid for 24 months
- ID-token issuance enabled
- (Recommended) Assignment required, with explicit user/group assignments

After this script, run `php scripts/configure_entra_sso.php <tenant_id> <client_id> <secret> [redirect_uri]` to inject the values into ITFlow.

## Prerequisites

- Windows machine with PowerShell 7+ (PowerShell 5.1 also works)
- Network access to `login.microsoftonline.com` and `graph.microsoft.com`
- An Entra admin role with permission to create app registrations and consent on behalf of the tenant (Application Administrator, Cloud Application Administrator, or Global Administrator)
- A working ITFlow install with this fork applied (database at version `≥ 2.4.4.2`)

## Step 1 — Install Azure CLI

```powershell
winget install -e --id Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
```

Skip if `az --version` already prints a version. If `winget` is not available, download the MSI from <https://aka.ms/installazurecliwindows>.

After install, the binary lives at `C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az`. Either restart the shell or extend `$env:PATH` for the current session:

```powershell
$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;" + $env:PATH
az --version | Select-Object -First 3
```

## Step 2 — Sign in to the tenant

Device-code flow keeps your browser separate from the shell:

```powershell
az login --use-device-code --tenant <your-tenant>.onmicrosoft.com --allow-no-subscriptions
```

Substitute your tenant's domain (e.g. `syso.it`) or its ID. The command prints a URL and a code; open the URL in any browser, sign in with an admin account, and paste the code. The shell call returns when the browser flow completes.

`--allow-no-subscriptions` lets the login succeed even if your account has no Azure subscriptions — for app registrations only Entra (formerly Azure AD) access is needed.

## Step 3 — Create the app and the client secret

```powershell
# Tenant id (from `az account show`)
$tenant_id = (az account show --query tenantId -o tsv)

# Redirect URI for ITFlow's agent SSO callback
# Use https://<host>/... for production, http://localhost/... for local dev
$redirect = "http://localhost/agent/login_entra_callback.php"

# Create the app — single tenant, web platform with the redirect URI,
# id-token issuance enabled (required for OIDC sign-in)
$app_json = az ad app create `
    --display-name "ITFlow Agent SSO" `
    --sign-in-audience AzureADMyOrg `
    --web-redirect-uris $redirect `
    --enable-id-token-issuance true `
    --output json --only-show-errors
$app = $app_json | ConvertFrom-Json
$client_id     = $app.appId
$app_object_id = $app.id

# Create a 24-month client secret
$end_date = (Get-Date).AddMonths(24).ToString("yyyy-MM-ddTHH:mm:ssZ")
$secret_raw = az ad app credential reset `
    --id $app_object_id `
    --display-name "itflow-sso" `
    --end-date $end_date `
    --output json --only-show-errors
$secret = $secret_raw | ConvertFrom-Json
$secret_value = $secret.password

Write-Output "Tenant ID:    $tenant_id"
Write-Output "Client ID:    $client_id"
Write-Output "Redirect URI: $redirect"
Write-Output "Client secret (copy now — only shown once):"
Write-Output $secret_value
```

`--only-show-errors` suppresses the deprecation/upgrade chatter Az CLI prints, so the JSON parse stays clean.

The `password` field of the credential reset response is the secret VALUE — that is what you paste into ITFlow. The Secret ID shown in the portal is a separate identifier.

## Step 4 — Inject the values into ITFlow

From any shell on the ITFlow host:

```powershell
& "C:\xampp\php\php.exe" scripts/configure_entra_sso.php $tenant_id $client_id $secret_value $redirect
```

(Linux/macOS: `php scripts/configure_entra_sso.php "$tenant_id" "$client_id" "$secret_value" "$redirect"`.)

The script validates that tenant_id and client_id are GUIDs and the redirect URI is an absolute http(s) URL, writes the four values into `settings`, and sets `config_agent_sso_enabled = 1`. JIT provisioning stays off (which you almost certainly want — see below).

## Step 5 — (Recommended) Assignment required

By default any user in the tenant can sign in to the app. Locking that down to explicit assignments is part of NIS2 access-control hygiene.

```powershell
# Get the service principal (Enterprise Application) that materialised when the app was created
$sp_id = (az ad sp list --filter "appId eq '$client_id'" --query "[0].id" -o tsv --only-show-errors)

# Set "Assignment required" = Yes
az ad sp update --id $sp_id --set "appRoleAssignmentRequired=true" --only-show-errors

# Grant access to a specific user (repeat per user, or use group assignments via the portal)
$user_principal = "j.groen@your-tenant.onmicrosoft.com"
$user_id = (az ad user show --id $user_principal --query id -o tsv --only-show-errors)

# Default app role id "00000000-0000-0000-0000-000000000000" = the implicit "User" role
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$sp_id/appRoleAssignments" `
    --body @"
{
  "principalId": "$user_id",
  "resourceId": "$sp_id",
  "appRoleId": "00000000-0000-0000-0000-000000000000"
}
"@ --headers "Content-Type=application/json" --only-show-errors
```

For group-based assignment, replace the user lookup with `az ad group show --group "<group-name>"` and POST the group's `id` as `principalId`.

## Step 6 — Bind your existing ITFlow agent to the Entra `oid` (optional)

If your ITFlow agent's email differs from the Entra UPN of the user you want to use, the SSO callback's email-fallback match will fail and refuse to log you in. Two options:

**A. Update the ITFlow user_email** to match the Entra UPN, then sign in via SSO once — the callback will bind the `oid` automatically on first match.

**B. Pre-bind the `oid`** so SSO works regardless of email:

```powershell
# Get your own oid
$my_oid = (az ad signed-in-user show --query id -o tsv --only-show-errors)
Write-Output "Your Entra oid: $my_oid"

# Inject into the ITFlow user row (substitute <user_id>)
$mysql = "C:\xampp\mysql\bin\mysql.exe"
& $mysql -u root itflow -e "UPDATE users SET user_entra_oid = '$my_oid', user_auth_method = 'entra' WHERE user_id = <user_id>"
```

After this, the SSO callback matches by `oid` (immutable) regardless of what the user's ITFlow email is.

## Step 7 — Test

1. Log out of ITFlow.
2. On the login page click **Sign in with Microsoft**.
3. If your Windows is Entra-joined the SSO is silent (the device's Primary Refresh Token issues the token without a prompt). Otherwise the browser shows the Entra sign-in.
4. You land on `agent/vault_unlock.php`. Enter your vault PIN (or tap your security key if you have a WebAuthn PRF method enrolled).
5. You arrive at the ITFlow start page with the vault unlocked.

If something fails the redirect carries `?error=<msg>` — check `agent/login_entra_callback.php`'s logs and `Admin → Security audit log` (event_type `sso.login.failed`).

## Rolling the secret

Client secrets expire. Rotate before they do:

```powershell
$end_date = (Get-Date).AddMonths(24).ToString("yyyy-MM-ddTHH:mm:ssZ")
$secret_raw = az ad app credential reset --id $app_object_id --display-name "itflow-sso-$(Get-Date -Format yyyyMM)" --end-date $end_date --output json --only-show-errors
$new_secret = ($secret_raw | ConvertFrom-Json).password

& "C:\xampp\php\php.exe" scripts/configure_entra_sso.php $tenant_id $client_id $new_secret $redirect
```

`az ad app credential reset` adds a NEW credential. Old credentials remain valid until you explicitly delete them (`az ad app credential delete --id $app_object_id --key-id <oldKeyId>`), so you can roll without downtime: deploy the new secret, verify, then revoke the old one.

## Tearing down

```powershell
az ad app delete --id $app_object_id
```

This removes the app registration, the service principal, and any assignments. Run `php scripts/configure_entra_sso.php` against an unregistered tenant/client/secret triple to clear the ITFlow side, or just toggle `Status = Disabled` in the admin UI.
