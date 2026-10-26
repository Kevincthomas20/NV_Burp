# NightVision Finding Validator for Burp Suite

**Extension version:** 0.2.0  
**Documentation updated:** October 22, 2026

NightVision Finding Validator brings NightVision scan findings into Burp Suite for manual review. Connect to NightVision, select a scan, examine the evidence, open a finding's HTTP request in Repeater, and record your assessment. When you determine that a finding is a false positive, you can explicitly update its resolution in NightVision and verify that the change saved.

The extension is a Java JAR loaded inside Burp Suite. It is not a separate website, monitoring service, or scanner. It connects directly to the NightVision REST API; using MCP is not required.

## Contents

- [1. Features at a glance](#1-features-at-a-glance)
- [2. Requirements and compatibility](#2-requirements-and-compatibility)
- [3. Install, upgrade, and unload](#3-install-upgrade-and-unload)
- [4. Quick start](#4-quick-start)
- [5. Connect to NightVision](#5-connect-to-nightvision)
- [6. Select scans and load findings](#6-select-scans-and-load-findings)
- [7. Search, sort, and navigate findings](#7-search-sort-and-navigate-findings)
- [8. Review evidence and HTTP traffic](#8-review-evidence-and-http-traffic)
- [9. Open a request in Repeater](#9-open-a-request-in-repeater)
- [10. Save local validation and analyst notes](#10-save-local-validation-and-analyst-notes)
- [11. Mark a finding false positive in NightVision](#11-mark-a-finding-false-positive-in-nightvision)
- [12. Export validation results](#12-export-validation-results)
- [13. Use the offline demo](#13-use-the-offline-demo)
- [14. Storage and data handling](#14-storage-and-data-handling)
- [15. API operations and limits](#15-api-operations-and-limits)
- [16. Troubleshooting](#16-troubleshooting)
- [17. Build from source](#17-build-from-source)
- [18. Verification and test coverage](#18-verification-and-test-coverage)
- [19. Project files and dependencies](#19-project-files-and-dependencies)
- [20. Current limitations](#20-current-limitations)
- [21. Frequently asked questions](#21-frequently-asked-questions)
- [22. Release history and references](#22-release-history-and-references)

## 1. Features at a glance

| Feature or control | What it does |
| --- | --- |
| API origin | Selects the NightVision API server used when you connect. |
| API token (memory only) | Supplies the token used to authenticate NightVision API requests. |
| Project UUID (optional) | Limits the scan list returned when connecting. |
| Connect / load scans | Establishes the API connection and loads accessible scans. |
| Disconnect | Drops the connection, clears the token field, and clears loaded scans and findings. |
| Scan dropdown | Shows loaded scans with target name, scan status, creation time, and scan UUID. |
| Scan UUID | Allows you to specify an accessible scan directly. |
| Load findings | Retrieves the selected scan's issues across returned pages, within the collection limits. |
| Filter findings | Filters the displayed table using a case-insensitive text match. |
| Column sorting | Sorts the table through its column headers. |
| Fetch full finding | Retrieves the selected issue's current detail record from NightVision. |
| Finding / evidence | Displays the title, severity, resolution, parameter, payload, evidence, and explanation. |
| Request (editable) | Displays recognized original request text and lets you edit or replace it. |
| Original response | Displays recognized response text from the NightVision finding. |
| Full finding JSON | Displays the complete loaded issue as formatted, read-only JSON. |
| Destination URL | Sets the HTTP connection service used when opening the request in Repeater. |
| Open in Repeater | Creates a Repeater tab containing the request for manual sending. |
| Local validation | Lets you choose an analyst assessment for the selected finding. |
| Analyst notes | Holds your test observations and reasoning. |
| Save local validation | Saves the local assessment, notes, and timestamp in Burp's extension preferences. |
| Mark false positive in NightVision | Updates the selected issue's resolution and retrieves it again to verify the result. |
| Export local validations | Saves loaded finding identifiers and saved local annotations as JSON. |
| Offline demo | Loads a synthetic finding without requiring an API token. |
| Status line | Reports progress, record counts, save and sync results, and errors. |
| Adjustable layout | Lets you resize the divider between the findings table and detail area. |

## 2. Requirements and compatibility

### Run the supplied extension

| Requirement | Details |
| --- | --- |
| Burp Suite | A desktop Community or Professional installation with Montoya API support. |
| API dependency | Compiled against Montoya API 2026.7. Compatibility with your installed Burp version still needs verification. |
| Java runtime | Targets Java 17 bytecode. Burp must run on Java 17 or later; a compatible Burp installation's bundled runtime can provide this. |
| NightVision access | An API token with access to the scans and issues you want to review. |
| Remote updates | Permission to update issues is also required for the false-positive action. |
| Network access | HTTPS access from the Burp machine to the configured NightVision API. Access to the target application is needed separately for Repeater testing. |
| Desktop environment | A suitable Windows or Linux desktop capable of running Burp. The extension does not use distribution-specific services. |

The extension uses no Professional-only Scanner features. Loading the supplied JAR does not require Node.js, Jython, Python, Maven, an application server, or a separate database.

A live NightVision tenant and running Burp installation were not available during development. Compilation and offline checks passed; end-to-end compatibility remains to be tested in your environment.

### Rebuild the extension

Rebuilding requires JDK 17 or 21 and either Python 3.8 or later for the included build-and-test script, or Maven for the alternative Maven build. A Java runtime without a compiler is insufficient. The first build needs access to Maven Central for dependencies.

## 3. Install, upgrade, and unload

### Install the prebuilt JAR

1. Extract `nightvision-burp-extension-v0.2.0.zip`.
2. Open Burp Suite and go to **Extensions → Installed → Add**.
3. Choose **Java** as the extension type.
4. Select `nightvision-burp/dist/nightvision-burp-0.2.0.jar` from the extracted package.
5. Click **Next** and inspect the extension's **Output** and **Errors** tabs.
6. Close the installer and open the new **NightVision** tab.

The extension's installed name is **NightVision Finding Validator**.

### Upgrade an existing installation

1. Save analyst notes and export validation results you want as a separate record.
2. Unload the previous NightVision extension in **Extensions → Installed**.
3. Load the updated JAR using the installation steps above.
4. Reconnect to NightVision and reload the scan.

Avoid running two versions simultaneously. Existing annotations can be retrieved when the updated extension uses the same Burp preference store, API origin, and issue ID.

### Unload the extension

Unload or remove it through **Extensions → Installed**. Unloading cancels the active background worker, clears the token field, and drops the connection reference.

Unloading does not delete saved annotations, exports, or existing Repeater requests. An API write already received by NightVision may still complete even if the extension is unloaded while the operation is in progress.

## 4. Quick start

### Explore the interface

1. Open **NightVision** and click **Offline demo**.
2. Inspect the sample finding's four detail tabs.
3. Choose **Needs review**, enter a note, and click **Save local validation**.
4. Confirm that the **Local validation** column changes.

The sample uses `example.invalid` and is not a working test application. The installed extension can open its request in Repeater; it does not simulate a reachable server.

### Review a real finding

1. Enter your NightVision API token and click **Connect / load scans**.
2. Choose a scan and click **Load findings**.
3. Select a finding and click **Fetch full finding** when you need current details.
4. Inspect the request, original response, and evidence.
5. Verify the destination and target credentials, then click **Open in Repeater**.
6. Review and send the request manually from Repeater.
7. Return to **NightVision**, select an assessment, enter notes, and save them.
8. To change the remote finding to false positive, use **Mark false positive in NightVision**.

## 5. Connect to NightVision

### API origin

The default API origin is:

```text
https://api.nightvision.net
```

Enter the HTTPS origin for your actual deployment: scheme, host, and optional port. Do not append `/api/v1`, another path, a query string, or embedded credentials.

| Example | Accepted format? |
| --- | --- |
| `https://api.nightvision.net` | Yes. |
| `https://api.nightvision.net/` | Yes; the root slash is normalized. |
| `https://nightvision-api.example.com:8443` | Yes, if this is your API service. |
| `https://api.nightvision.net/api/v1` | No; omit the API path. |
| `http://api.nightvision.net` | No; platform access requires HTTPS. |

This field identifies NightVision's API service. Your target application's service is configured separately through **Destination URL**.

### API token

Generate a token through your NightVision account's token-management interface and paste it into **API token (memory only)**. The extension accepts a raw token or a token preceded by `Token `, then authenticates as:

```http
Authorization: Token <your-api-token>
```

JWT / `Bearer` login and interactive SSO login are not implemented. The token grants only the account's permitted access. It is separate from the cookies or authorization headers needed to authenticate your target application in Repeater.

### Project UUID (optional)

Enter a project UUID before connecting to limit the scan list. Use a UUID, not a project name. Leave the field blank to request accessible scans without a project filter.

This filter limits the scan picker. A manually entered scan UUID is loaded if the token has access to that scan, independently of the picker filter.

### Connect / load scans

Click **Connect / load scans** to apply the fields and retrieve scans. Success is reported in the status line with the returned scan count.

Editing the origin, token, or project field alone does not reconfigure an existing connection. Click the connection button again to apply changes. Reconnecting clears the previously loaded scan and finding list, so save unsaved notes first.

### Disconnect

Click **Disconnect** to clear the token field, drop the connection, and clear loaded scans, the selected scan UUID, and findings. Saved annotations, exports, and existing Repeater tabs remain.

The extension does not persist connection settings for automatic reconnection. Enter the connection details again after reloading the extension.

## 6. Select scans and load findings

### Scan dropdown

Each entry displays the target name, scan status, creation timestamp supplied by NightVision, and scan UUID. Selecting an entry copies its ID into **Scan UUID**. The extension requests scans ordered by descending creation time.

### Scan UUID

You can paste an accessible scan UUID directly after connecting. Use the scan ID rather than a target ID, schedule ID, project ID, or application URL.

### Load findings

Click **Load findings** to retrieve that scan's issues across the returned API pages. Selecting a different scan does not automatically load its findings.

If loading fails, the previous findings may remain visible. Use the status line to distinguish a successful refresh from an error. The text filter also remains in place when you change scans; clear it if new rows appear to be missing.

### Fetch full finding

Select one row and click **Fetch full finding** to retrieve its current detail record, including remote resolution and evidence fields supplied by NightVision.

The retrieved record replaces the in-memory copy and repopulates the detail controls. Save notes and copy temporary request edits before refreshing. There is no automatic refresh; fetch the record again to see changes another analyst makes in NightVision.

### Background operation state

Network operations run on a background worker. While an operation is active, relevant buttons and editing controls are disabled to avoid changing the selected record during an update. The status line shows progress, and controls are enabled again when the operation finishes or fails.

## 7. Search, sort, and navigate findings

### Table columns

| Column | Contents |
| --- | --- |
| Severity | Severity supplied by NightVision. |
| Finding | Nuclei template name when present, otherwise issue-kind name, otherwise an issue-kind fallback. |
| Method | Reported HTTP method. |
| Host | Reported fully qualified domain name. |
| Path | Reported URL path. |
| NightVision resolution | Remote resolution in the last loaded issue record. |
| Local validation | Saved local assessment, or **Not reviewed** when none exists. |

### Filter findings

Filtering uses a case-insensitive substring match across the displayed columns. Examples include a vulnerability name, `HIGH`, a host, a path fragment, or `Needs review`.

Filtering is local and makes no API request. It does not search analyst notes, evidence, payloads, issue IDs, or full JSON. It is not a regular-expression filter. Clear the field to restore all loaded rows. Updating a displayed status can cause a row to stop matching an active filter.

### Sort and select

Click a column header to sort by its displayed values. Severity is treated as text, not a custom critical-to-informational ranking. Select one row at a time to populate its details and analyst fields.

Drag the divider between the table and detail area to resize those areas. Request, response, JSON, and notes areas support their normal text-view interactions.

### Temporary edits

Unsaved notes, request edits, and destination changes are temporary. Changing selection or repopulating the detail area can discard them. Save annotations and open requests you want to keep in Repeater before switching rows, reconnecting, loading the demo, or refreshing details.

## 8. Review evidence and HTTP traffic

### Finding / evidence

This read-only view displays:

- Finding name, severity, issue UUID, and NightVision resolution.
- Parameter name and type.
- Reported payload.
- Evidence text and evidence details.
- AI explanation, if supplied by NightVision.
- Whether recognizable raw request text was found.

The extension displays an existing explanation. It does not generate a new explanation or make a separate AI request. Missing fields remain blank, and evidence is presented as text.

### Request (editable)

This tab shows the first recognizable original HTTP request in the issue data. Edit it or paste a complete raw request copied from NightVision.

```http
GET /search?q=nv-marker HTTP/1.1
Host: example.invalid
Accept: text/html

```

Begin with a raw HTTP request line. A curl command is not raw HTTP. The extension does not execute shell commands or construct an exploit request from a finding's URL or payload.

Edits affect the next **Open in Repeater** action. They do not update NightVision, change the **Full finding JSON** view, or become part of a saved annotation.

### Original response

This read-only view displays recognized response text from the loaded NightVision record. It shows the scan's original response, not the result of your latest Repeater request.

Inspect replay responses in Repeater. The extension does not automatically capture them or use them to assign a verdict.

### Full finding JSON

This read-only view shows the complete loaded issue object as formatted JSON. Use it to inspect additional fields or investigate an unrecognized traffic format.

The JSON is the last loaded API record. Temporary request-editor changes are not reflected in it.

### Recognized request and response formats

NightVision's public `Issue` schema permits unrestricted content in `extra_info`. Extraction is best effort. These optional fields are recognized in `extra_info` or at the issue's top level:

| Representation | Request fields | Response fields |
| --- | --- | --- |
| Raw string | `raw_request`, `http_request`, or `request` | `raw_response`, `http_response`, or `response` |
| Nested raw string | A `raw` or `raw_request` string inside a `request`, `http_request`, or `raw_request` object | A `raw` or `raw_response` string inside the equivalent response object |
| Header and body strings | `requestHeader` or `request_header`, with `requestBody` or `request_body` | `responseHeader` or `response_header`, with `responseBody` or `response_body` |

Request text must look like a raw HTTP request; response text must begin with `HTTP/`. The first recognized representation is used. There is no selector for multiple captured exchanges in this release.

If extraction fails, fetch the full finding, inspect its JSON, and paste the original raw request from NightVision if needed. No request is fabricated when evidence cannot be recognized.

Structured HAR arrays, encoded traffic, and binary bodies may require a future adapter. A sanitized issue JSON sample can help identify the required adaptation without sharing credentials.

## 9. Open a request in Repeater

### Destination URL

The suggested destination uses the finding's protocol, FQDN, port, and path. If the protocol is missing, HTTPS is suggested. Verify it before opening Repeater.

**Destination URL chooses the connection host, port, and TLS setting. The request line and Host header come from the request editor.** Changing the destination does not rewrite the message's path, query, Host header, or other content.

| Setting | Effect |
| --- | --- |
| Destination `https://test.example.com:8443/other-path` | Chooses connection host `test.example.com`, port `8443`, and TLS. |
| Request line `GET /search?q=marker HTTP/1.1` | Keeps `/search?q=marker` as the request target. |
| Header `Host: app.example.com` | Keeps that Host header until edited. |

For ordinary replay, align the destination, request target, and Host header with the intended application. HTTP and HTTPS destinations are accepted. Embedded credentials and URL fragments are rejected.

### Repeater workflow

1. Review the evidence and affected parameter.
2. Confirm that the destination is authorized for testing. The extension does not enforce Burp's target scope before opening Repeater.
3. Update expired target-application cookies or authorization headers if necessary.
4. Click **Open in Repeater**.
5. Open the resulting tab, captioned with `NV` and the first eight characters of the issue ID.
6. Inspect the service and message, then click Repeater's **Send** when ready.
7. Compare the result with the evidence and an appropriate control request.
8. Return to the extension and record your assessment.

Opening a Repeater tab does not send the request. Clicking the action again creates another tab. Existing Repeater tabs remain independently available after selection changes or disconnection.

Header line endings are normalized to CRLF when preparing the message. Body text is retained without newline normalization. This text workflow is not a byte-for-byte binary replay guarantee; Burp may apply its own message handling when sending.

The NightVision API token is never inserted into target requests. Target authentication belongs in the request itself.

## 10. Save local validation and analyst notes

### Assessment labels

| Label | Suggested analyst meaning | Automatic NightVision update? |
| --- | --- | --- |
| Not reviewed | Review has not been completed. | No. |
| Confirmed | You reproduced and assessed the issue. | No. |
| False positive | Your review concluded the issue is not valid in the tested context. | No. |
| Needs review | More investigation or context is needed. | No. |
| Retest passed | Your retest did not reproduce the original issue under the checked conditions. | No. |

These are manual labels. An HTTP status code, reflected string, expired session, or failed request does not automatically establish a verdict.

### Save an assessment

1. Select a finding.
2. Choose a **Local validation** value.
3. Enter observations in **Analyst notes**.
4. Click **Save local validation**.

The status, notes, and update timestamp are stored in Burp's extension preferences. The table's **Local validation** column updates. No API write occurs.

Notes are saved explicitly, not while typing. For example:

```text
Retested with a current authenticated session. The marker appears as
HTML-encoded text in the results page. Reviewed the surrounding output
context and compared with a control request. No executable context was
observed under these test conditions.
```

### Persistence and identity

Annotations are associated with the API origin and issue UUID. They can survive Burp restarts when the same preference store is retained. They are not scoped by this extension to a Burp project and do not automatically transfer to other machines or analysts.

Different issue UUIDs have separate notes, even when findings have similar titles or paths. Demo records use an `offline-demo` namespace. A different origin representation can also produce a different annotation identity.

Only the latest assessment and notes are kept, not a complete edit history. After a verified remote update, later local saves retain the last `nightvision_sync` metadata. That metadata records a past operation; it is not continuous synchronization and does not prove that no one changed NightVision afterward.

### Size limits and clearing

An annotation is limited to 7,000 characters and 7,000 UTF-8 bytes after JSON serialization, including metadata. Escaping, non-ASCII text, and sync fields consume part of the allowance. Shorten notes when a size error appears.

To clear the visible assessment, choose **Not reviewed**, empty the notes, and save. This saves a new value; it does not delete the underlying preference entry or prior sync metadata. There is no delete-all-annotations control.

## 11. Mark a finding false positive in NightVision

### Use the remote action

1. Connect, load the scan, and select the issue you have reviewed.
2. Enter analyst notes. Save them locally first if desired.
3. Click **Mark false positive in NightVision**.
4. Wait for the status line to report the verified result or an error.

The button means **False positive** regardless of the local dropdown's current value. Selecting **False positive** and clicking **Save local validation** alone does not change NightVision.

The remote action needs a live API connection and update permission. The installed offline demo cannot make a real update. Remote reopen and resolved actions are not implemented.

### Update and verification requests

The extension sends:

```http
PUT /api/v1/issues/{issue_id}/
Authorization: Token <your-api-token>
Content-Type: application/json

{"resolution":1}
```

It then retrieves the same record:

```http
GET /api/v1/issues/{issue_id}/
```

Success is reported only when the retrieved issue ID matches and its resolution is `1`. NightVision's own public source documents `1=false_positive`. The extension also displays `0` as **Open** and `2` as **Resolved**. Other values are shown numerically without an inferred name.

### After verified success

- The refreshed issue replaces the loaded record.
- **NightVision resolution** displays **False positive (1)**.
- The local assessment becomes **False positive**.
- Analyst notes and an update timestamp are saved locally.
- Local `nightvision_sync` fields record the verified resolution and verification timestamp.

The update payload contains only `resolution`. Notes are not uploaded. The extension does not overwrite evidence, extra information, or AI explanations to store notes.

### Failure and uncertainty

| Outcome | What happens | Next step |
| --- | --- | --- |
| Update rejected, such as HTTP 403 | Error shown; no new verified sync recorded. | Check update permissions. |
| Interrupted request or unconfirmed response | The server may still have applied the change. | Fetch the full finding and check its current resolution before retrying. |
| Accepted update but failed or mismatched read-back | The extension does not report verified success. | Refresh and inspect the current state in NightVision. |
| Verified remote update but failed local save | Remote success is reported separately; note text remains in the editor. | Copy the notes before changing selection and resolve the local preference issue. |

The extension does not automatically retry the write or label uncertain results verified.

### Classification scope and reversal

The action addresses one issue UUID. It does not invoke the bulk `set-resolution` endpoint or delete the issue. NightVision controls whether the disposition also affects matching occurrences or later scans; do not assume its effects are limited to the displayed scan.

Reverse a remote classification through NightVision's interface or a separately verified API workflow. Changing a local label back to **Not reviewed** or **Confirmed** does not reverse the remote change.

## 12. Export validation results

Click **Export local validations**, select a destination, and save the JSON file. The default filename is `nightvision-validations.json`. Existing files require confirmation before replacement.

All currently loaded findings are exported, including rows hidden by a filter. Export is not limited to the selected row and does not gather findings from other unloaded scans. Row order follows the loaded collection rather than the table's visual sort order.

### Export fields

| Field | Meaning |
| --- | --- |
| `format` | `nightvision-burp-validations-v1`. |
| `api_origin` | Connection origin, or `offline-demo`. |
| `exported_at` | Export timestamp in UTC ISO 8601 format. |
| `findings` | Array of loaded finding summaries and saved annotations. |
| `issue_id` | Issue UUID. |
| `scan_id` | Scan UUID from the loaded issue. |
| `nightvision_resolution` | Last loaded remote value, serialized as a string. |
| `finding` | Display name. |
| `target` | Suggested URL derived from the finding. |
| `local_validation` | Saved status, notes, update time, and last verified sync metadata when present. An unsaved annotation is an empty object. |

Example after a verified false-positive update:

```json
{
  "format": "nightvision-burp-validations-v1",
  "api_origin": "https://api.nightvision.net",
  "exported_at": "2026-10-22T22:59:00Z",
  "findings": [
    {
      "issue_id": "11111111-1111-4111-8111-111111111111",
      "scan_id": "22222222-2222-4222-8222-222222222222",
      "nightvision_resolution": "1",
      "finding": "Demo: reflected input for manual review",
      "target": "https://example.invalid:443/search?q=nv-marker",
      "local_validation": {
        "status": "False positive",
        "notes": "Reviewed output encoding and the surrounding context.",
        "updated_at": "2026-10-22T22:58:00Z",
        "nightvision_sync": {
          "status": "verified",
          "resolution": 1,
          "verified_at": "2026-10-22T22:58:00Z"
        }
      }
    }
  ]
}
```

Save notes before exporting. Unsaved dropdown changes and note edits are not included.

Exports omit the API token, original raw traffic, temporary request edits, Repeater responses, and temporary destination edits. The exported target is derived from the loaded finding, not the edited destination field. Names and analyst notes can still contain information you entered.

There is no built-in import, scheduled export, CSV export, or report generator. The JSON is a portable record for reading or separate processing, not a built-in restore package.

## 13. Use the offline demo

**Offline demo** disconnects, clears the token field, and loads a bundled synthetic finding containing:

- A LOW-severity reflected-input example.
- A raw request to `example.invalid`.
- A sample original response containing `nv-marker`.
- Evidence explaining that reflection alone does not prove XSS.

Explore detail tabs, filtering, sorting, request editing, Repeater handoff, local annotation, and export. Demo notes use a separate namespace and can remain available when the installed demo is loaded again.

Loading the sample makes no API request. **Fetch full finding** reports that the sample already contains its details. The remote false-positive action reports that a live connection is required.

### Conversation preview versus installed extension

The browser-style preview shown in the conversation is a separate simulation. Its Repeater handoff and response are simulated, and notes last only for that preview session. It is not a working NightVision web client bundled with this release.

The Java extension runs inside Burp, persists annotations in Burp preferences, and can use real Repeater and API operations. A build-generated preview PNG is also a mock-host render, not a running Burp instance.

## 14. Storage and data handling

| Data | Where it is held or saved | Sent to NightVision? |
| --- | --- | --- |
| API token | Process memory and password field while connected. | Yes, in the API Authorization header. |
| Loaded scans and issues | Extension memory. | Retrieved from NightVision. |
| Original request and response | Loaded record and text views. | Not uploaded by the update action. |
| Edited request | Temporary editor state; copied to Repeater when requested. | No. |
| Local status and notes | Burp extension preferences after saving. | No. |
| Last verified sync metadata | Local annotation after successful verification. | No. |
| False-positive resolution | NightVision after the explicit update succeeds. | Yes: `{"resolution":1}`. |
| Validation export | User-selected file path. | No. |

### Credentials and preferences

The extension does not write the API token to its JAR, annotation preferences, or exports. Disconnecting, loading the demo, and unloading clear the field and drop the connection reference. Java does not guarantee immediate erasure of immutable token strings from memory.

Local annotations use Burp's standard extension preferences. This extension adds no separate encryption layer or database. Exact physical preference paths depend on the host implementation. Keep unnecessary secrets out of notes.

### Burp project data

Requests opened in Repeater come under Burp's own data handling and project state. Credentials present in those messages remain part of the messages. Existing Repeater data is not removed by disconnecting the extension.

### HTTPS and redirects

API calls use Java's HTTP client with normal certificate validation. Redirects are disabled. Pagination must remain on the configured HTTPS origin, port, and collection path before the token is attached.

Operational errors are summarized without displaying raw server response bodies. The extension's startup log message contains no credentials. Burp's own logs and project handling are separate.

### Proxy behavior

NightVision API calls do not use Burp's HTTP engine, Proxy interception, or Burp's upstream proxy settings. They use the Java client directly. This release has no extension-level proxy or custom trust-store controls.

Repeater handles target traffic after manual sending. Networks requiring a proxy or custom certificate trust for platform access may require additional configuration or a future transport enhancement. Changing Burp's proxy settings alone does not configure this API client.

## 15. API operations and limits

### API operations by action

| Action | Operation | Purpose |
| --- | --- | --- |
| Connect / load scans | `GET /api/v1/scans/` | Uses `page_size=100`, descending creation order, and an optional project filter. |
| Load findings | `GET /api/v1/issues/` | Uses the selected scan UUID and `page_size=100`. |
| Fetch full finding | `GET /api/v1/issues/{id}/` | Retrieves one current issue record. |
| Mark false positive in NightVision | `PUT`, then `GET`, at `/api/v1/issues/{id}/` | Sets `resolution` to `1`, then verifies the saved ID and value. |
| Save local validation | No API request. | Writes preferences. |
| Filter or sort | No API request. | Changes the table view. |
| Export local validations | No API request. | Writes a local file. |
| Offline demo | No API request. | Loads a bundled sample. |
| Open in Repeater | No platform API or immediate target request. | Creates a tab for manual sending. |

### Built-in limits

| Setting | Value or behavior |
| --- | --- |
| Requested page size | 100 records. |
| Maximum collection pages | 200. |
| Maximum accumulated collection records | 50,000. |
| Maximum API response body | 20 MiB per response. |
| Configured connection timeout | 15 seconds. |
| Configured HTTP request timeout | 45 seconds. |
| Redirects | Disabled. |
| Automatic polling | None. |
| Application-level write retries | None. |
| UI network operations | One background operation at a time. |
| Local annotation size | 7,000 serialized characters and UTF-8 bytes, including metadata. |
| Remote-update note pre-check | Approximately 6,200 serialized UTF-8 bytes for the notes object, reserving room for sync metadata. |

The request timeout is a Java client setting, not a guarantee that every streamed response-body read finishes in 45 seconds.

Pagination loops, collection limits, invalid JSON, and missing result arrays produce errors. A partially fetched new collection is not silently shown as complete. Narrow the scan list with the project filter when needed. Limits are defined in source and are not configurable through the UI.

## 16. Troubleshooting

| Symptom | What to check or do |
| --- | --- |
| Extension fails to load or tab is missing | Select the compiled JAR as Java, inspect extension Output / Errors, and check Java and Montoya compatibility. |
| Unsupported class version | Use a compatible Burp runtime. For rebuilding, use JDK 17 or 21 and verify the selected Java installation. |
| API origin error | Enter the HTTPS API origin without an API path, query, or embedded credentials. |
| ID must be a UUID | Use the appropriate project, scan, or issue UUID rather than a name or URL. |
| HTTP 401 | Check token validity and token authentication format. Bearer JWT login is not supported. |
| HTTP 403 | Check resource and update permissions. A token may be able to read an issue without permission to update it. |
| HTTP 404 | Check the ID, API origin, and access. |
| HTTP 429 | Wait before retrying; there is no automatic rate-limit retry. |
| Redirect or unexpected HTTP status | Verify the API origin and whether a gateway is redirecting to a login page. Redirects are not followed. |
| Network, TLS, or certificate failure | Check network access and Java certificate trust. Burp's upstream proxy settings do not automatically apply. |
| Connection succeeds but no scans appear | Clear an unnecessary project filter, check account access, and reconnect. An accessible collection can be empty. |
| Findings appear empty | Check the load result and clear the text filter. |
| Old scan's findings remain | Click **Load findings** after changing the scan and confirm success. Failed loads can retain the prior table. |
| Request or response is blank | Fetch the full finding, inspect JSON, and paste the original request if needed. The format may require an adapter. |
| Request format error | Paste raw HTTP beginning with a request line, not a curl command. |
| Replay reaches an unexpected host or path | Check destination, Repeater service, request line, and Host header independently. |
| Replay returns a login page, 401, or 403 | Refresh target application credentials. The NightVision API token does not authenticate the target. |
| Local save does not change NightVision | Expected: use the separate remote false-positive action. |
| Update not confirmed or not verified | Fetch the full record and inspect remote state before retrying; the write may already have applied. |
| Remote update succeeded but notes failed to save | Copy the notes before leaving and investigate the local preference failure. |
| Notes too long | Shorten them; serialized metadata and escaping count toward the limit. |
| Notes lost after changing rows | Save before switching selection, reconnecting, or refreshing. |
| Notes missing on another machine or profile | Preferences are local and not transferred automatically. Use an export as a separate record. |
| Notes missing for a similar issue in another scan | The issue UUID may differ. Annotations are not correlated by title or path. |
| Export missing new note text | Save the annotation, then export again. |
| Export has more rows than the visible table | All loaded findings are included, including filtered-out rows. |
| Dependency download fails | Check HTTPS access to Maven Central or use an existing verified dependency cache. |
| Dependency checksum mismatch | Remove the named cached JAR and retry; do not disable checksum verification. |

Most operational messages appear in the status line. Investigate uncertain remote changes using the current remote record or NightVision's interface rather than a local verdict alone.

## 17. Build from source

### Windows

Install JDK 17 or 21 and Python 3.8 or later, with Java and Python available on PATH. Open PowerShell in the extracted `nightvision-burp` project directory:

```powershell
java -version
py -3 --version
py -3 tools/build.py
```

If your installation uses `python` instead of the Windows launcher:

```powershell
python tools/build.py
```

### Linux desktop

With JDK 17 or 21 and Python 3.8 or later, run from the project directory:

```bash
java -version
python3 --version
python3 tools/build.py
```

The same source can be used on a suitable Kali, Ubuntu, or other Linux desktop. Burp needs a graphical desktop for interactive use; the extension has no server-hosting step.

### Build output and behavior

The script creates:

```text
dist/nightvision-burp-0.2.0.jar
```

It performs these steps:

1. Finds Java on PATH.
2. Downloads pinned Montoya and Gson dependencies when not cached.
3. Verifies pinned SHA-256 digests, including cached files.
4. Compiles Java 17-compatible extension classes.
5. Compiles and runs offline regression checks against a mock Montoya host.
6. Packages the extension, demo, Gson classes, and Gson license into the JAR.

Dependencies are cached in `.build/deps/`; compiled classes go to `target/`. These directories can be recreated. Gson is bundled; Montoya classes are supplied by Burp and are not bundled.

The script uses `javac` when available, otherwise attempts Java's compiler module. A compiler must be present. No third-party Python package is required.

### Optional UI image

On Linux:

```bash
python3 tools/build.py --preview /tmp/nightvision-burp-preview.png
```

On Windows:

```powershell
py -3 tools/build.py --preview nightvision-burp-preview.png
```

This writes a Swing mock-host image during offline tests. It does not launch a live NightVision connection or full Burp instance.

### Maven alternative

With Maven and JDK 17 or 21 installed, run:

```bash
mvn clean package
```

Load the shaded output:

```text
target/nightvision-burp-0.2.0.jar
```

Maven includes Gson and treats Montoya as provided. The standalone regression checks are not registered with Maven Surefire. Use `tools/build.py` to run those checks. The Python build was exercised during development; the Maven alternative was not separately executed in that environment.

### Check the supplied JAR hash

The package includes `dist/SHA256SUMS.txt`. On Linux, enter the `dist` directory and run:

```bash
sha256sum -c SHA256SUMS.txt
```

On Windows, from the project directory:

```powershell
Get-FileHash .\dist\nightvision-burp-0.2.0.jar -Algorithm SHA256
Get-Content .\dist\SHA256SUMS.txt
```

Compare the reported hash with the text file. That checksum describes the distributed binary. The build script does not regenerate `SHA256SUMS.txt`. A rebuilt archive may have a different hash, including differences caused by ZIP metadata; calculate a new hash for a rebuilt release.

## 18. Verification and test coverage

Version 0.2.0 passed **61 offline checks**, covering:

- API endpoints, queries, token headers, and update payloads.
- Pagination, loops, malformed collections, and credential boundaries.
- Rejection of pagination links that change origin, port, scheme, or collection path.
- Errors that omit raw response bodies and token values.
- Request-header normalization and body-text newline preservation.
- Finding names, destination adaptation, and raw traffic extraction.
- Issue-specific false-positive writes with only the resolution field.
- Permission failures, wrong read-back resolution, mismatched ID, and failed verification.
- Distinction between an accepted update and a verified saved result.
- Swing tab registration, demo, filtering, notes, and remote-status display.
- Recording verified-sync metadata only after read-back succeeds.

These use a fake API transport and mock Montoya host. They do not prove real-tenant permissions, platform classification side effects, all evidence formats, or compatibility with every Burp version.

### Suggested integration check

1. Load the JAR and inspect Burp's extension errors.
2. Try the installed offline demo and local save/export.
3. Connect and load one accessible scan.
4. Compare one finding's full JSON and extracted traffic with NightVision's evidence.
5. Open its request in Repeater and verify service and application authentication before testing.
6. On a validated finding you intend to reclassify, perform the remote action and confirm the result in NightVision.

## 19. Project files and dependencies

| Path | Purpose |
| --- | --- |
| `README.md` | This feature and operations guide. |
| `dist/nightvision-burp-0.2.0.jar` | Prebuilt extension. |
| `dist/SHA256SUMS.txt` | Distributed JAR hash. |
| `pom.xml` | Maven dependencies and shaded build. |
| `tools/build.py` | Build and offline-check runner. |
| `src/main/java/local/nightvision/NightVisionExtension.java` | Burp entry point, Swing UI, annotations, background actions, remote action, and exports. |
| `src/main/java/local/nightvision/NightVisionClient.java` | API transport, pagination, explicit resolution update, and verification. |
| `src/main/java/local/nightvision/Finding.java` | Field adaptation, resolution labels, traffic extraction, destination validation, and request preparation. |
| `src/main/resources/demo-findings.json` | Synthetic finding. |
| `src/test/java/local/nightvision/SelfTest.java` | Offline regression checks. |
| `THIRD_PARTY_NOTICES.md` | Dependency and license notices. |
| `licenses/GSON-APACHE-2.0.txt` | Gson license. |

| Dependency | Version | Use |
| --- | --- | --- |
| PortSwigger Montoya API | 2026.7 | Compile-time API supplied by Burp at runtime. |
| Google Gson | 2.13.2 | JSON processing; bundled. |
| Maven Compiler Plugin | 3.14.1 | Maven build only. |
| Maven Shade Plugin | 3.6.1 | Maven packaging only. |

Gson's Apache 2.0 license is included in the package and JAR. Review `THIRD_PARTY_NOTICES.md`. This custom extension is not published to the BApp Store.

## 20. Current limitations

- Live Burp/NightVision integration remains untested in the development environment.
- Traffic extraction is best effort; some formats require an adapter or manual paste.
- Binary and encoded traffic, structured HAR arrays, and choosing among multiple exchanges are not fully supported.
- Validation is manual; no automatic verdict or Repeater-response capture is implemented.
- No automatic polling, scan monitoring, scan launching, or active scanning is included.
- False positive is the only remote resolution action; remote reopen and resolve are not included.
- No bulk remote update, finding deletion, or suppression-management controls are included.
- Notes stay local; preferences retain the latest assessment and last verified sync, not full edit history.
- No built-in import, cross-machine annotation synchronization, or purge-all control is included.
- Exports are JSON and cover the loaded collection only.
- No extension-level proxy, custom trust-store, SSO, or Bearer-token controls are included.
- No Burp Site Map issue import, Scanner integration, or automatic association of Repeater responses is implemented.

## 21. Frequently asked questions

### Does Save local validation update NightVision?

No. It saves locally. The remote false-positive action is a separate button and requires update permission.

### Will a local False positive assessment synchronize later?

No. There is no queued or automatic synchronization.

### Can a successful retest mark the issue resolved in NightVision?

You can record **Retest passed** locally. Use NightVision's own interface for a remote resolved change; this extension does not implement it.

### Will analyst notes appear in NightVision?

No. They stay in the saved local annotation and export. The API update sends only the resolution.

### Does Open in Repeater send immediately?

No. You send the request through Repeater's **Send** control.

### Are target credentials updated automatically?

No. Refresh the application's cookies or authorization headers yourself when needed. The API token authenticates the NightVision platform only.

### Is the API token remembered after restarting Burp?

The extension does not persist it. Enter it again after loading or restarting the extension.

### Does Disconnect remove saved assessments?

No. It clears the connection and loaded view. Preferences, exports, and Repeater tabs remain.

### Are annotations attached to a Burp project or shared with my team?

This extension stores preferences by API origin and issue ID, not Burp project. They are not automatically shared with other machines or analysts. Export a separate record when needed.

### Can this run on Ubuntu Desktop or Kali?

The Java extension does not rely on distribution-specific services. It needs a compatible desktop Burp and Java environment. The Linux build workflow is included, but those operating systems were not individually certified during development.

### Does it require Node.js, a web server, or MCP?

No. Load the JAR in Burp. Building uses Java with the Python script or Maven, and the extension uses direct REST calls.

### Can I inspect fields that are not shown in the evidence view?

Yes. **Full finding JSON** shows the entire loaded issue object. Unrecognized traffic may still need adaptation before raw HTTP replay.

## 22. Release history and references

### Release history

| Version | Changes |
| --- | --- |
| 0.1.0 | Initial API connection, scan selection, finding filters, evidence and traffic views, editable requests, Repeater handoff, local assessments and notes, JSON export, and offline demo. |
| 0.2.0 | Added explicit remote false-positive updates, verified resolution mapping, read-back confirmation, remote-resolution display, local sync metadata, and expanded offline checks. |

This expanded README documents version 0.2.0. It does not change the compiled extension's behavior.

### References

- [NightVision REST API reference](https://docs.nightviz.ai/reference/)
- [NightVision public OpenAPI document](https://docs.nightviz.ai/openapi/nightvision-rest-api.yaml)
- [NightVision's resolution mapping in its public source](https://github.com/nvsecurity/nightvision-mcp/blob/main/src/types/index.ts)
- [NightVision scan findings and evidence](https://docs.nightviz.ai/welcome/key-concepts/dast-scans/)
- [PortSwigger: install a custom extension](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install)
- [PortSwigger: Montoya Repeater API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/repeater/Repeater.html)
- [PortSwigger: extension development setup](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/manual-setup)

API behavior and resolution mappings were reviewed on October 22, 2026. The implemented source is the authority for this release's behavior; later platform changes may require an extension update.
