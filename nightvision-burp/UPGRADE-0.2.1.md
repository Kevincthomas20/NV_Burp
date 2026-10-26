# Upgrade to NightVision Finding Validator 0.2.1

## Fix for empty Request and Original response tabs

Version 0.2.0 did not read NightVision's `extra_info.http_requests` and
`extra_info.http_responses` arrays. This build reads their structured captured
messages and retains support for the older raw HTTP fields.

1. Save analyst notes and export validations you want as a separate record.
2. In Burp Extensions > Installed, unload the old NightVision extension.
3. Extract this ZIP. Add the Java extension from
   `nightvision-burp/dist/nightvision-burp-0.2.1.jar`.
4. Confirm the extension Output log says `NightVision validator 0.2.1 loaded`.
5. Reconnect, load a scan, select a finding, and click **Fetch full finding**.
6. Open **Request (editable)** and **Original response**. Use their captured-message
   selectors when multiple messages are present.

The label above each editor states whether the message is captured raw text,
reconstructed from structured fields, absent, or unsupported. Selecting a
captured request updates the destination from its URL when available. Verify
the service, Host header, body, and current target credentials before replay.
Requests and responses can be browsed independently; their array positions do
not prove they belong to the same exchange. Changing captured requests discards
request edits; browsing responses keeps the current request edits.

If a tab is still empty after fetching detail, inspect **Full finding JSON**:
- Missing or empty `http_requests` / `http_responses` means that side's capture
  was not returned in that API record.
- A selector entry with an unsupported-format label means a capture exists but
  cannot be represented by this text editor. Its original JSON remains visible.
- If NightVision's web UI has traffic while these fields are absent or use a
  different format, provide only a sanitized sample of the relevant field names
  and structure. Remove tokens, cookies, credentials, internal hostnames, and
  sensitive body content. Do not send an API token or the entire tenant export.

Structured request messages use HTTP/1.1 text for editable replay. This is not
byte-exact binary traffic replay. Explicit base64 UTF-8 bodies are supported;
binary or unknown encodings are explained rather than corrupted. Existing
local validation and remote false-positive workflows are unchanged.

## Validation

92 offline checks passed, including a mocked list-to-detail API flow populating
both tabs, multiple message selection, duplicate headers, cookies, postData,
content, body preservation, destination selection, and existing remote writes.
No live tenant credentials or running Burp instance were available during this
fix. Verify one finding against its NightVision web evidence after upgrading.

See README.md for all features and build instructions.
