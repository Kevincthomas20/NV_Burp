# NightVision SSO setup — version 0.5.8

This build adds **Sign in with SSO** and **Use saved login** to Burp. It also
includes the request/response evidence fixes from version 0.2.1.

## One-time setup

1. Install or update the official NightVision CLI on the desktop running Burp:
   [NightVision installation instructions](https://docs.nightviz.ai/welcome/tutorials-and-guides/installing-the-cli/).
   The CLI is a separate dependency and is not bundled in this ZIP.
2. Extract the ZIP to a permanent folder. Save notes and export any validations
   you want as a separate record, then unload the old extension.
3. In **Burp → Extensions → Installed → Add → Java**, select
   `nightvision-burp/dist/nightvision-burp-0.5.8.jar`.
4. In the **NightVision** tab, leave **API origin** as
   `https://api.nightvision.net`. Leave the manual token field blank.
5. If needed, click **Browse** beside **NightVision CLI** and select the actual
   executable, such as `nightvision.exe` on Windows. Do not include quotes or
   command arguments in the field. This non-secret path is remembered by Burp.
6. Click **Sign in with SSO**. In the browser NightVision opens, choose your
   organization's SSO option and finish the normal login/MFA steps.
7. Wait for the extension to verify your account and load scans. The status
   line shows the account email when NightVision provides it.

The extension never asks for your SSO password. The official CLI owns the
browser login and saves a reusable credential for your OS account. The
extension reads it and sends it only to NightVision's production API.

## Later Burp sessions

Click **Use saved login**. This verifies and reuses the credential saved by
NightVision, without launching a new login process or copying a token. If it is
missing, expired, or revoked, use **Sign in with SSO** again.

To have Burp reload the extension itself at startup, enable
**Settings → Extensions → Core extension settings → Automatically reload
extensions on startup**, keep its **Loaded** checkbox selected, and keep the
JAR at the same permanent path. Automatic extension loading and reconnecting
to NightVision are separate operations.

## If browser sign-in cannot launch from Burp

1. Open a normal desktop terminal as the same OS user who runs Burp.
2. Run `nightvision login` and complete SSO in your browser.
3. Return to Burp and click **Use saved login**.

The extension no longer passes `--timeout`; it enforces its own five-minute
limit, including for older CLI versions. A failed launch now reports the exit
code and a fixed explanation in **Connection diagnostics**, without showing
raw process output.
Windows Burp uses the Windows user's saved credential; a login performed only
inside WSL/Linux has a different credential location.

## If browser login succeeds but Burp reports SSLHandshakeException

The extension’s Java API connection may not trust the certificate chain that
your browser and CLI accept. On Windows, leave **Use trusted Windows roots**
enabled and try **Use saved login**. If your environment needs an additional
company CA, select the IT-provided issuer/root certificate with **Browse CA**,
then reconnect. **Connection diagnostics** now shows Java/TLS settings and
classifies trust-chain, hostname, expiry, or protocol failures.

See **TLS-SETUP.md** for the complete workflow. These settings apply to the
extension’s API connections; certificate and hostname checks remain enabled.

## Cancel and disconnect

**Cancel sign-in** stops the pending extension connection and its CLI login
listener. **Disconnect** clears the extension's in-memory connection. Neither
action closes your browser, signs out of SSO, deletes the saved CLI credential,
or revokes a token. Unloading during sign-in also stops the CLI listener.

The current CLI owns the saved credential in the top-level `token` field of
`%USERPROFILE%\.nightvision\nightvision.yml` on Windows or
`~/.nightvision/nightvision.yml` on Linux/macOS. The extension also recognizes
YAML/JSON filename variants and the legacy `.nightvision/token` file.

If auto-detection does not find your terminal login, click **Browse login
file**, choose your `nightvision.yml`, then click **Use saved login**. This
file choice applies to saved-login reuse. It is remembered as a path only.
The config is read without changing it; malformed config or incompatible API
metadata is not silently replaced with an unrelated saved credential.

**Connection diagnostics** lists checked paths, the loaded source, CLI exit
code, and fixed failure hints. It does not show credential contents or raw
CLI output. Send that diagnostic text for troubleshooting; never send your
config contents or token.

The extension does not write the credential to Burp preferences, exports, or logs. Only non-secret executable, saved-login/CA paths and TLS options
are saved by the extension. Use saved login is explicit; no credential is read
or API connection made automatically when the extension starts.

## Validation

The build passed **403 checks**, including subprocess completion,
credential reuse, failure without stale-credential fallback, cancellation,
timeout, unloading, account verification, and existing evidence/update flows.
Regression tests include a CLI that rejects `--timeout` and writes a YAML
config, along with JSON/legacy formats and safe diagnostic handling.
TLS checks also use a real local HTTPS server with temporary test certificates
to verify trust and hostname matching; they make no external API calls.
SSO tests use synthetic credentials, child Java fixtures, and mocked API
responses. Live login with your organization's identity provider still needs
testing in your Burp installation.

See **README.md** for every feature, data handling, troubleshooting, and builds.
