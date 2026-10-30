# NightVision Finding Validator for Burp Suite

**Extension version:** 0.5.8  
**Author:** Kevin Thomas  
**Documentation updated:** October 28, 2026

NightVision Finding Validator brings NightVision scan findings into Burp Suite for manual review. Connect to NightVision, select a scan, examine the evidence, open a finding's HTTP request in Repeater, and record your assessment. Use the separate remote buttons to mark a finding false positive or won't fix in NightVision and verify that the change saved.

The extension is a Java JAR loaded inside Burp Suite. It is not a separate website, monitoring service, or scanner. It connects directly to the NightVision REST API; using MCP is not required. Version 0.5.8 supports browser SSO through the official NightVision CLI, current YAML/JSON CLI configuration, legacy token files, and manual API tokens.

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
| API token (memory only) | Supplies a manually entered token used for API requests. SSO does not fill this field. |
| NightVision CLI / Browse | Sets the official CLI executable; remembers its path in Burp preferences. |
| Saved login file / Browse login file | Optionally selects the saved config used by Use saved login; blank enables auto-detection. The path is remembered without copying credentials. |
| Connection diagnostics | Shows login paths, Java runtime/trust settings, CLI exit code, and classified TLS failures; omits credentials and raw process/exception messages. |
| Additional trusted CA / Browse CA | Adds a selected IT-provided CA certificate file to this extension’s API client trust. |
| Use trusted Windows roots | Adds available native Windows ROOT stores alongside JVM trust; enabled by default on Windows. |
| Sign in with SSO | Runs the official CLI browser login, reads its saved credential after success, verifies the account, and loads scans. |
| Use saved login | Reads the current OS user’s saved CLI credential, verifies it, and loads scans without launching a login process. |
| Cancel sign-in | Stops the pending sign-in/connection attempt and CLI listener. Keeps the browser and saved login. |
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
| Request (editable) | Displays a captured request, reconstructed from structured fields when needed; lets you edit or replace it. |
| Captured request / Captured response | Browse the messages returned in each array independently. Shows source field, count, and parsing or reconstruction status. |
| Original response | Displays recognized response text from the NightVision finding. |
| Attach retest evidence to NightVision… | Burp context-menu action that explicitly saves one selected completed exchange to a chosen loaded finding, without sending traffic or changing its verdict. |
| Retest evidence | Lists local attachments, verifies their message hashes, and shows capture metadata plus request/response previews. Includes folder selection, refresh, and explicit attachment removal. |
| Full finding JSON | Displays the complete loaded issue as formatted, read-only JSON. |
| Destination URL | Sets the HTTP connection service used when opening the request in Repeater. |
| Open in Repeater | Creates a Repeater tab containing the request for manual sending. |
| Local validation | Lets you choose an analyst assessment for the selected finding. |
| Analyst notes | Holds your test observations and reasoning. |
| Save local validation | Replaces the selected issue's previous saved assessment, notes, and timestamp in Burp's extension preferences. |
| Mark false positive in NightVision | Sets resolution 2 for the selected issue, then retrieves it to verify the result. |
| Mark won't fix in NightVision | Sets resolution 4 for the selected issue, then retrieves it to verify the result. |
| Export local validations | Saves loaded finding identifiers and saved local annotations as JSON. |
| Validation report… | Previews and saves scoped CSV/HTML reports with saved verdicts/notes, summary counts, common credential redaction, and optional original evidence in HTML. |
| Offline demo | Loads a synthetic finding without requiring an API token. |
| Status line | Reports progress, record counts, save and sync results, and errors. |
| Adjustable layout | Lets you resize the divider between the findings table and detail area. |

## 2. Requirements and compatibility

### Run the supplied extension

| Requirement | Details |
| --- | --- |
| Burp Suite | A desktop Community or Professional installation with Montoya API support. |
| API dependency | Compiled against Montoya API 2026.7. Evidence capture includes a pre-1.0 adapter for Burp 2022.12.6; the build separately tests the workflow with Montoya 0.10.1. Live integration remains to be verified. |
| Java runtime | Targets Java 17 bytecode. Burp must run on Java 17 or later; a compatible Burp installation's bundled runtime can provide this. |
| NightVision access | A NightVision account with access to the scans and issues, using CLI SSO login or a manual API token. |
| SSO browser login | The current official NightVision CLI installed on the same machine and OS account as Burp, with an available desktop browser. |
| Remote updates | Permission to update issues is also required for the remote resolution actions. |
| Network access | HTTPS access from the Burp machine to the configured NightVision API. Access to the target application is needed separately for Repeater testing. |
| Desktop environment | A suitable Windows or Linux desktop capable of running Burp. The extension does not use distribution-specific services. |

The extension uses no Professional-only Scanner features. Loading the supplied JAR does not require Node.js, Jython, Python, Maven, an application server, or a separate database. SSO browser login requires the official NightVision CLI; manual-token mode and offline demo do not.

A live NightVision tenant and running Burp installation were not available during development. Compilation and offline checks passed; end-to-end compatibility remains to be tested in your environment.

### Rebuild the extension

Rebuilding requires JDK 17 or 21 and either Python 3.8 or later for the included build-and-test script, or Maven for the alternative Maven build. A Java runtime without a compiler is insufficient. The first build needs access to Maven Central for dependencies.

## 3. Install, upgrade, and unload

### Install the prebuilt JAR

1. Extract `nightvision-burp-extension-v0.5.8.zip`.
2. Open Burp Suite and go to **Extensions → Installed → Add**.
3. Choose **Java** as the extension type.
4. Select `nightvision-burp/dist/nightvision-burp-0.5.8.jar` from the extracted package.
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

Unload or remove it through **Extensions → Installed**. Unloading cancels the active background worker, stops an extension-launched CLI login listener, clears the token field, and drops the connection reference. It does not close the browser or remove the CLI’s saved credential.

Unloading does not delete saved annotations, exports, or existing Repeater requests. An API write already received by NightVision may still complete even if the extension is unloaded while the operation is in progress.

## 4. Quick start

### Explore the interface

1. Open **NightVision** and click **Offline demo**.
2. Inspect the sample finding's four detail tabs.
3. Choose **Needs review**, enter a note, and click **Save local validation**.
4. Confirm that the **Local validation** column changes.

The sample uses `example.invalid` and is not a working test application. The installed extension can open its request in Repeater; it does not simulate a reachable server.

### Review a real finding

1. Click **Sign in with SSO** and finish your normal NightVision browser sign-in. Select the installed CLI executable using **Browse** if needed. For later sessions, use **Use saved login**. Alternatively, enter an API token and click **Connect / load scans**.
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

### Sign in with SSO

Install the current official [NightVision CLI](https://docs.nightviz.ai/welcome/tutorials-and-guides/installing-the-cli/) on the same desktop as Burp. Leave **API origin** set to `https://api.nightvision.net`.

1. In **NightVision CLI**, enter the executable path or use **Browse**. `nightvision` works when the executable is on Burp’s inherited PATH. On Windows, select the actual `nightvision.exe` file, without surrounding quotes or command arguments.
2. Click **Sign in with SSO**.
3. In the browser opened by NightVision, choose your organization’s SSO option and complete any normal MFA prompts.
4. When the CLI finishes successfully, the extension reads the credential saved by the CLI, calls `GET /api/v1/user/me/` to verify it, and loads scans. The status line shows the account email when provided.

The extension runs the executable directly, with separate arguments:

```text
nightvision login --api-url https://api.nightvision.net/api/v1/
```

It does not collect your SSO password, implement an identity-provider login page, embed a browser, or ask you to copy an authorization code. Browser login remains owned by NightVision’s official CLI. CLI stdout/stderr are drained together; at most 64 KiB is examined in process memory to classify failures. The extension records only the exit code and fixed explanations, not raw output or credentials. The extension also removes inherited `NIGHTVISION_TOKEN` and `NIGHTVISION_API_URL` variables from this subprocess so they cannot bypass or redirect the requested login.

The extension waits up to five minutes and stops the login process on timeout. It does not pass `--timeout`, so older CLI releases without that option can be used. **Cancel sign-in** cancels the pending connection and stops the CLI process, freeing its login listener. Your browser remains open. A login already completed in the browser or saved by the CLI may remain available; cancellation is not revocation or account logout. The same applies when the extension is unloaded during sign-in.

If the CLI cannot open a browser from Burp, run `nightvision login` in a normal desktop terminal, complete SSO, and click **Use saved login** in Burp. If the CLI fails, inspect **Connection diagnostics** for its exit code and fixed error hint.

### Use saved login

The current CLI stores its platform token in a top-level `token` field in its configuration file. Version 0.3.0 incorrectly assumed the CLI always used a separate plain token file; 0.3.1 corrects that assumption:

| Platform | Saved credential location |
| --- | --- |
| Windows | `%USERPROFILE%\.nightvision\nightvision.yml` |
| Linux/macOS | `~/.nightvision/nightvision.yml` |

Auto-detection checks `nightvision.yml`, `nightvision.yaml`, and `nightvision.json` before the legacy `.nightvision/token` file under the home directory reported by Java and available OS home hints. The extension does not recursively search your filesystem. YAML and JSON must have a top-level text `token`; unrelated, nested, malformed, ambiguous, or incompatible API configuration is not treated as a credential. The parser uses SafeConstructor with bounded input, rejects duplicate keys, and does not instantiate custom YAML tags. Existing config files are never edited.

If detection fails, click **Browse login file** and select the config actually used by your terminal login, then click **Use saved login**. The optional field applies to **Use saved login** only; a new **Sign in with SSO** reads the CLI’s normal saved locations. An explicitly chosen file does not fall back to another credential if it is missing.

**Connection diagnostics** lists checked paths and the loaded file, with credential values omitted. It also shows CLI exit status and fixed failure explanations. Share this diagnostic view for troubleshooting, rather than the contents of your config file.

Click **Use saved login** after restarting Burp to reuse that credential without a new browser login. No CLI executable is launched by this action. The extension still verifies the account and loads scans; it does not treat a file’s presence as proof that the login is valid. A missing or rejected credential produces guidance to sign in again. A service or network failure is not reported as an expired credential.

The API token field stays blank for SSO and saved-login connections. The CLI executable path and any explicit saved-login file path are remembered in Burp preferences, while the extension does not write the credential there. Saved-login reuse is explicit: the extension does not read the token or make an automatic connection on startup.

SSO and saved-login actions connect only to NightVision’s production API at `https://api.nightvision.net`. Other configured origins remain available through manual-token mode. This keeps a production credential from being sent to another origin. Run Burp as the same OS user who completed CLI login; for example, a Windows Burp process does not use a Linux/WSL user’s separate token file.

### API TLS trust and company certificates

Browser sign-in and CLI login can succeed while the Java API connection fails with `SSLHandshakeException`. They use different TLS implementations and may use different trusted-certificate stores. A company TLS-inspection gateway can be one cause, but the exception can also mean an expired certificate, a hostname mismatch, or a protocol problem.

Version 0.5.8 retains Java’s default trusted roots and adds these API-specific settings:

| Control | Behavior |
| --- | --- |
| Use trusted Windows roots | Enabled by default on Windows. Tries `Windows-ROOT` and `Windows-ROOT-LOCALMACHINE` when the running JVM supports them. Unavailable stores are reported in TLS failure diagnostics; default JVM trust remains available. Disabled on other operating systems. |
| Additional trusted CA (optional) | Use **Browse CA** to select your trusted company/issuer CA in PEM or DER form, then reconnect. Accepts 1–32 currently valid CA certificates, up to 2 MiB total; leaf server certificates are rejected. The selected file is read in the background and is never modified. |

After changing either setting, click **Use saved login** or reconnect with a manual API token. Settings do not alter an already-created connection. The CA path and checkbox preference are remembered without copying credentials into preferences.

TLS changes apply only to this extension’s API clients. They do not modify the global Java trust store, Burp’s own network settings, the CLI, your browser, or Repeater. Certificate-chain validation and HTTPS hostname checks remain enabled. An additional CA adds trust; it does not replace the JVM’s trusted roots.

If your workplace uses TLS inspection, select the CA certificate supplied or approved by your IT team. If Windows already trusts that CA and the JVM exposes the native store, the Windows-roots option can be sufficient. Use **Connection diagnostics** after a failure: it distinguishes certificate-chain, hostname, validity-date, and protocol/handshake failures. It includes Java version/home, the configured trust-store path, native store availability, selected CA fingerprints when loaded, and cause class names, while omitting credential values and raw exception messages. These diagnostics do not prove the cause before the connection is tested in your environment.

See **TLS-SETUP.md** for the short recovery workflow.

### API token

Generate a token through your NightVision account's token-management interface and paste it into **API token (memory only)**. The extension accepts a raw token or a token preceded by `Token `, then authenticates as:

```http
Authorization: Token <your-api-token>
```

Direct JWT / `Bearer` entry is not implemented. Browser SSO uses the official CLI credential as described above. The token grants only the account's permitted access. It is separate from the cookies or authorization headers needed to authenticate your target application in Repeater.

### Project UUID (optional)

Enter a project UUID before connecting to limit the scan list. Use a UUID, not a project name. Leave the field blank to request accessible scans without a project filter.

This filter limits the scan picker. A manually entered scan UUID is loaded if the token has access to that scan, independently of the picker filter.

### Connect / load scans

Click **Connect / load scans** to apply the fields and retrieve scans. Success is reported in the status line with the returned scan count.

Editing the origin, token, or project field alone does not reconfigure an existing connection. Click the connection button again to apply changes. Reconnecting clears the previously loaded scan and finding list, so save unsaved notes first.

### Disconnect

Click **Disconnect** to clear the token field, drop the connection, and clear loaded scans, the selected scan UUID, and findings. Saved annotations, exports, and existing Repeater tabs remain.

Disconnect does not delete or revoke the CLI’s saved credential and does not log out the browser. After reloading the extension, use **Use saved login**, or enter a manual API token again. Only non-secret executable, config/CA file paths, and TLS options are remembered by the extension; it does not automatically connect.

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
- Captured request and response counts, and whether replayable request text was found.

The extension displays an existing explanation. It does not generate a new explanation or make a separate AI request. Missing fields remain blank, and evidence is presented as text.

### Request (editable)

This tab shows a captured HTTP request. Use **Captured request** to browse multiple messages; the initial selection prefers the first usable capture. The source field and index appear in the selector. The status label says whether the text is raw or reconstructed from structured fields. Edit it or paste a complete raw request copied from NightVision.

```http
GET /search?q=nv-marker HTTP/1.1
Host: example.invalid
Accept: text/html

```

Begin with a raw HTTP request line. A curl command is not raw HTTP. The extension reads existing captured traffic, including structured captures; it does not create a test payload from the finding summary or execute shell commands. Structured request captures are represented as HTTP/1.1 for editable replay, including captures originally marked HTTP/2. This is not a byte-for-byte representation of the original wire traffic.

Edits affect the next **Open in Repeater** action. They do not update NightVision, change the **Full finding JSON** view, or become part of a saved annotation. Switching captured requests or fetching the finding again discards request edits. Browsing captured responses preserves the current request edits.

### Original response

This read-only view displays captured response text from the loaded NightVision record. Use **Captured response** to browse the returned responses. Structured responses are reconstructed from their recorded status, headers, and body and labeled accordingly. It shows scan evidence rather than the result of your latest Repeater request.

The request and response selectors are independent. Equal array positions do not establish that those two messages belong to the same exchange. Missing or unsupported captures stay visible with a status explanation; the extension does not substitute a different message as evidence.

Inspect replay responses in Repeater. The extension does not automatically capture them or use them to assign a verdict.

### Full finding JSON

This read-only view shows the complete loaded issue object as formatted JSON. Use it to inspect additional fields or investigate an unrecognized traffic format.

The JSON is the last loaded API record. Temporary request-editor changes are not reflected in it.

### Recognized request and response formats

NightVision's public `Issue` schema permits unrestricted content in `extra_info`. NightVision's own public client reads the `http_requests` and `http_responses` arrays. Version 0.2.1 handles those captures as well as the older singular raw formats.

| Representation | Request fields | Response fields |
| --- | --- | --- |
| NightVision capture array | `extra_info.http_requests[]` with `method`, absolute `url`, `headers`, `cookies`, and `postData` | `extra_info.http_responses[]` with `status`, `statusText`, `httpVersion`, `headers`, and `content` |
| Capture array at issue root | `http_requests[]` | `http_responses[]` |
| Raw string | `raw_request`, `http_request`, or `request` | `raw_response`, `http_response`, or `response` |
| Nested raw string | A `raw` or `raw_request` string inside a request object or array item | A `raw` or `raw_response` string inside a response object or array item |
| Header and body strings | `requestHeader` or `request_header`, with `requestBody` or `request_body` | `responseHeader` or `response_header`, with `responseBody` or `response_body` |

Structured headers can be arrays of `{name, value}` objects or objects mapping names to values. Repeated headers and captured body text are retained. Requests use the captured URL's escaped path and query; no URL decoding is applied. An absent Host header is added from that URL. Captured cookies are added only when no Cookie header was recorded. A missing Content-Type can be supplied from `postData.mimeType`.

Bodies can be strings or captured objects with `text`. Explicit base64-encoded UTF-8 text bodies are decoded; unsupported encodings and non-UTF-8 binary bodies produce an explanation. Structured form parameters without a captured text body are not silently converted to an empty request. HTTP/1.1 replay representation, decoded content, inferred Host, and supplied MIME type mean reconstructed text may differ from the original wire message. Verify headers such as Content-Length and Content-Encoding before replaying; Burp may also update framing.

Raw text must start with an HTTP request line or `HTTP/` response status line. Legacy singular formats use the first recognized representation. Capture arrays offer independent message selection and retain unsupported entries for inspection.

If traffic is missing, click **Fetch full finding** and inspect the source fields in **Full finding JSON**. The status label distinguishes absent captures from unsupported captured content. Some findings have no saved HTTP traffic. You can paste an original raw request when one is available; the extension does not generate a replacement response or send a target request to fill the view.

## 9. Open a request in Repeater

### Destination URL

For a structured captured request, the suggested destination uses that capture's URL, including its host, port, and TLS scheme. Switching captured requests updates this suggestion. When no capture URL is available, the finding's protocol, FQDN, port, and path supply the fallback; a missing protocol falls back to HTTPS. Verify the destination before opening Repeater.

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
5. The extension selects the docked Repeater tool when its standard Swing tab is available. Otherwise select **Repeater** yourself. The basic handoff uses Burp's default tab name. If only the named overload is available, the caption is `NV` and the first eight characters of the issue ID.
6. Inspect the service and message, then click Repeater's **Send** when ready.
7. Compare the result with the evidence and an appropriate control request.
8. Return to the extension and record your assessment.

A receipt directly below the button confirms the handoff and naming mode. Version 0.5.8 resolves the installed public Repeater API before invocation, preferring the basic one-request method. It avoids a direct compile-time dependency on the named-tab method. The available overload and actual return type are resolved before a single handoff; there is no fallback retry after a method has been invoked. Invalid inputs are reported there. Burp handoff/API compatibility failures also show an error dialog and a sanitized stage/error type, available API signature, bounded Burp version when readable, and allowlisted missing Montoya member signature under **Extensions → NightVision → Errors**. Other exception text and request contents are not logged. A failed handoff or tab-navigation attempt is never retried automatically. Detached/custom Burp layouts may require selecting Repeater manually.

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
| Won't fix | Your review accepts the finding without planning a fix. | No. |
| Needs review | More investigation or context is needed. | No. |
| Retest passed | Your retest did not reproduce the original issue under the checked conditions. | No. |

These are manual labels. An HTTP status code, reflected string, expired session, or failed request does not automatically establish a verdict.

### Attach manual retest evidence

After manually sending a request in Burp Repeater, right-click its completed request or response and select **Attach retest evidence to NightVision…**. Choose the loaded finding, verify its issue UUID/origin/target, add a label and optional context, and click **Save evidence**. A verified-save receipt confirms the local attachment. This action leaves the local verdict, validation notes, and NightVision unchanged.

The **Retest evidence** tab displays saved attachments for the selected finding and verifies their SHA-256 hashes before showing their messages. It remembers a local evidence folder, initially `<OS user home>/NightVision-Burp/evidence`. Raw selected HTTP bytes are saved separately from preferences and may contain session credentials. Binary bodies are retained in full, with an explicit omission note in text previews. Read [EVIDENCE.md](EVIDENCE.md) for the workflow, ownership/timestamp rules, storage, removal, and limits.

### Save an assessment

1. Select a finding.
2. Choose a **Local validation** value.
3. Enter observations in **Analyst notes**.
4. Click **Save local validation**.

The status, notes, and update timestamp are stored in Burp's extension preferences. The extension reads the written value back before showing **Validation saved and read back from Burp preferences** and updating the table's **Local validation** column. No API write occurs. A failed or unconfirmed write leaves your edits in the editor and shows an error rather than a success message.

Notes are saved explicitly, not while typing. For example:

```text
Retested with a current authenticated session. The marker appears as
HTML-encoded text in the results page. Reviewed the surrounding output
context and compared with a control request. No executable context was
observed under these test conditions.
```

### Persistence and identity

Annotations are associated with the API origin and issue UUID. They can survive Burp restarts when the same preference store is retained. They are not scoped by this extension to a Burp project and do not automatically transfer to other machines or analysts.

Version 0.4.1 fixed an invalid preference-key length in earlier releases: the previous keys were 87 characters, exceeding Java's 80-character key limit. Current keys are 57 characters and retain the full SHA-256 identity. Existing records accepted by older lenient hosts remain readable; a new explicit save writes the supported key. Before unloading an older extension, copy any notes still visible in its editor. Values from rejected saves were never persisted and cannot be recovered automatically.

Different issue UUIDs have separate notes, even when findings have similar titles or paths. Demo records use an `offline-demo` namespace. A different origin representation can also produce a different annotation identity.

Only the latest assessment and notes are kept, not a complete edit history. After a verified remote update, later local saves retain the last `nightvision_sync` metadata. That metadata records a past operation; it is not continuous synchronization and does not prove that no one changed NightVision afterward.

Edit or replace the notes in the editor, then click **Save local validation**. The button replaces the saved status and complete note text for the same API origin and issue UUID, including clearing notes when the editor is empty. Repeat saves confirm **Previous status and notes replaced**. Generate a new report after saving; an existing report file or preview remains a snapshot. HTML shows **Latest saved analyst notes**, and CSV uses the same current saved record. Independent evidence attachment notes remain with their attachments, listed newest first by attachment time.

### Size limits and clearing

An annotation is limited to 7,000 characters and 7,000 UTF-8 bytes after JSON serialization, including metadata. Escaping, non-ASCII text, and sync fields consume part of the allowance. Shorten notes when a size error appears.

To clear the visible assessment, choose **Not reviewed**, empty the notes, and save. This saves a new value; it does not delete the underlying preference entry or prior sync metadata. There is no delete-all-annotations control.

## 11. Mark a finding false positive in NightVision

Version 0.5.7 corrects a reversed resolution mapping in earlier versions. Those versions sent `1` (Resolved) while labeling it False positive. Review any findings changed with the older button in NightVision, then explicitly reclassify them if needed. The upgrade does not automatically change remote findings, saved local verdicts, or historical sync receipts.

### Use the remote action

1. Connect, load the scan, and select the issue you have reviewed.
2. Enter analyst notes. Save them locally first if desired.
3. Click **Mark false positive in NightVision**.
4. Wait for the status line to report the verified result or an error.

The button means **False positive** regardless of the local dropdown's current value. Selecting **False positive** and clicking **Save local validation** alone does not change NightVision.

Both remote actions need a live API connection and update permission. The installed offline demo cannot make a real update. Remote reopen and resolved actions are not implemented.

### Mark won't fix in NightVision

Select the issue and click **Mark won't fix in NightVision** beside the false-positive button. This sends `PUT /api/v1/issues/{issue_id}/` with only `{"resolution":4}` and uses a separate GET to verify the selected UUID and code `4`. Only after successful verification does the extension display **Won't fix (4)**, save the local **Won't fix** assessment and analyst notes, and record a code-4 sync receipt. Notes remain local.

Both buttons use the classification in their own labels, independently of the local dropdown. Choosing **Won't fix** and **Save local validation** saves locally only. Won't fix counts as reviewed in report summaries and reviewed-only scopes. A failed or mismatched read-back leaves the previous saved assessment intact and preserves unsaved notes. Neither action retries the write automatically.

### Update and verification requests

The extension sends:

```http
PUT /api/v1/issues/{issue_id}/
Authorization: Token <your-api-token>
Content-Type: application/json

{"resolution":2}
```

It then retrieves the same record:

```http
GET /api/v1/issues/{issue_id}/
```

Success is reported only when the retrieved issue ID matches and its resolution is `2`. The deployed NightVision web app uses `0=Open`, `1=Resolved`, `2=False positive`, and `4=Won't fix`. Other values are shown numerically without an inferred name. The public MCP type comments have an outdated mapping that reverses `1` and `2`; they are not the authority for this write.

### After verified success

- The refreshed issue replaces the loaded record.
- **NightVision resolution** displays **False positive (2)**.
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

### CSV and HTML validation reports

Click **Validation report…** to choose a title, optional analyst name, format, scope, and content options. You can report on all loaded findings, visible rows in their current sort order, or the selected finding, and restrict any scope to saved reviewed verdicts. Save local validation first: unsaved notes, verdict changes, and request edits are excluded.

HTML includes summary counts by local verdict and severity, finding metadata, and optionally saved notes, scanner evidence text, the selected finding's chosen original HTTP captures, and saved manual retest attachments for findings in scope. Saved retests are initially enabled for HTML and include provenance, context, attachment notes, hashes, and text representations of the messages. CSV includes one row per finding with metadata and optional saved notes; HTTP messages and scanner payloads are excluded. Both show the local verdict separately from the last loaded NightVision resolution and any historical sync receipt.

Reports preview before saving and redact common credential patterns across their fields. HTML escapes external text and has no scripts or external assets. CSV quotes fields and prefixes risky formula starters as text. Redaction cannot detect every secret in prose; review content before sharing. Reports use loaded data without API calls or remote changes. Open saved HTML in a browser to print or save a PDF.

Reports allow 5,000 findings and 16 MiB of output, limit individual fields to 16,000 characters with a truncation marker, and preview at most 50 findings. The exported file covers the full chosen scope. See [REPORTS.md](REPORTS.md) for scope rules, evidence provenance, redaction coverage, and limitations. Synthetic examples are included in `examples/`.

### Existing JSON export

Click **Export local validations (JSON)**, select a destination, and save the JSON file. The default filename is `nightvision-validations.json`. Existing files require confirmation before replacement.

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
      "nightvision_resolution": "2",
      "finding": "Demo: reflected input for manual review",
      "target": "https://example.invalid:443/search?q=nv-marker",
      "local_validation": {
        "status": "False positive",
        "notes": "Reviewed output encoding and the surrounding context.",
        "updated_at": "2026-10-22T22:58:00Z",
        "nightvision_sync": {
          "status": "verified",
          "resolution": 2,
          "verified_at": "2026-10-22T22:58:00Z"
        }
      }
    }
  ]
}
```

Save notes before exporting. Unsaved dropdown changes and note edits are not included.

Exports omit the API token, original raw traffic, temporary request edits, Repeater responses, and temporary destination edits. The exported target is derived from the loaded finding, not the edited destination field. Names and analyst notes can still contain information you entered.

There is no built-in import or scheduled export. The JSON is a portable record for reading or separate processing, not a built-in restore package. Its existing output is separate from the new HTML/CSV report path and does not apply the report redactor.

## 13. Use the offline demo

**Offline demo** disconnects, clears the token field, and loads a bundled synthetic finding containing:

- A LOW-severity reflected-input example.
- A raw request to `example.invalid`.
- A sample original response containing `nv-marker`.
- Evidence explaining that reflection alone does not prove XSS.

Explore detail tabs, filtering, sorting, request editing, Repeater handoff, local annotation, and export. Demo notes use a separate namespace and can remain available when the installed demo is loaded again.

Loading the sample makes no API request. **Fetch full finding** reports that the sample already contains its details. The remote resolution buttons report that a live connection is required.

### Conversation preview versus installed extension

The browser-style preview shown in the conversation is a separate simulation. Its Repeater handoff and response are simulated, and notes last only for that preview session. It is not a working NightVision web client bundled with this release.

The Java extension runs inside Burp, persists annotations in Burp preferences, and can use real Repeater and API operations. A build-generated preview PNG is also a mock-host render, not a running Burp instance.

## 14. Storage and data handling

| Data | Where it is held or saved | Sent to NightVision? |
| --- | --- | --- |
| Manual API token | Process memory and password field while connected. | Yes, in the API Authorization header. |
| SSO/CLI credential | Saved by the official CLI in the OS user’s `.nightvision/nightvision.yml` or a supported legacy/config file; the extension reads it into process memory only after an explicit login action. | Yes, to the production NightVision API in the Authorization header. |
| CLI executable, saved-login and CA file paths, Windows-roots option | Burp extension preferences; contain no credential values. | No. |
| Connection diagnostics | Extension memory: local paths, CLI exit status, Java/TLS settings and failure classification; no credential contents or raw process/exception messages. | No. |
| Loaded scans and issues | Extension memory. | Retrieved from NightVision. |
| Original request and response | Loaded record and text views. | Not uploaded by the update action. |
| Edited request | Temporary editor state; copied to Repeater when requested. | No. |
| Local status and notes | Burp extension preferences after saving. | No. |
| Last verified sync metadata | Local annotation after successful verification. | No. |
| Explicit retest attachments | User-selected local evidence folder: raw message files and metadata, including labels, context, notes, hashes, and attachment time. The folder path alone is remembered in preferences. | No. |
| Remote resolution | NightVision after the selected remote action succeeds. | Yes: `{"resolution":2}` for false positive or `{"resolution":4}` for won't fix. |
| Validation export | User-selected file path. | No. |
| HTML/CSV report | User-selected file path; prepared snapshot and preview in memory. Common credential patterns are redacted; optional original and saved retest evidence appears only in HTML. | No. |

### Credentials and preferences

The sign-in code does not copy the API token into the JAR, annotation preferences, or exports. Explicit retest attachments save the selected raw HTTP messages and may therefore contain authentication headers or cookies present in those messages. Disconnecting, loading the demo, and unloading clear the sign-in field and drop the connection reference; saved local attachments remain. Java does not guarantee immediate erasure of immutable token strings from memory. SSO login delegates credential saving to the official CLI; the extension reads that file but does not create, modify, delete, encrypt, or revoke it. Disconnect and cancel leave this shared credential in place. These credentials can be reused by other NightVision tools running as the same OS user.

Local annotations use Burp's standard extension preferences. This extension adds no separate encryption layer or database. Exact physical preference paths depend on the host implementation. Keep unnecessary secrets out of notes.

### Burp project data

Requests opened in Repeater come under Burp's own data handling and project state. Credentials present in those messages remain part of the messages. Existing Repeater data is not removed by disconnecting the extension.

### HTTPS and redirects

API calls use Java's HTTP client with certificate-chain and HTTPS hostname validation. JVM trust is retained, available Windows roots can be added, and an optional CA file can supply an additional trusted issuer for API connections. Redirects are disabled. Pagination must remain on the configured HTTPS origin, port, and collection path before the token is attached.

Operational errors are summarized without displaying raw server response bodies. The extension's startup log message contains no credentials. Burp's own logs and project handling are separate.

### Proxy behavior

NightVision API calls do not use Burp's HTTP engine, Proxy interception, or Burp's upstream proxy settings. They use the Java client directly. This release offers API-specific Windows-root and additional-CA controls. It has no extension-level proxy controls.

Repeater handles target traffic after manual sending. Networks requiring a proxy for platform access may require additional Java/network configuration or a future transport enhancement. Custom certificate trust can be supplied through the additional-CA setting. Changing Burp's proxy settings alone does not configure this API client.

## 15. API operations and limits

### API operations by action

| Action | Operation | Purpose |
| --- | --- | --- |
| Connect / load scans | `GET /api/v1/scans/` | Uses `page_size=100`, descending creation order, and an optional project filter. |
| Sign in with SSO | Official CLI login, then `GET /api/v1/user/me/` and `GET /api/v1/scans/` | CLI owns the browser login and credential creation; extension verifies identity before loading scans. |
| Use saved login | `GET /api/v1/user/me/`, then `GET /api/v1/scans/` | Reads an existing saved CLI credential and verifies it; does not launch the CLI or browser. |
| Cancel sign-in | No additional API operation. | Cancels the pending connection and stops an extension-launched CLI login process; no logout or token revocation. |
| Load findings | `GET /api/v1/issues/` | Uses the selected scan UUID and `page_size=100`. |
| Fetch full finding | `GET /api/v1/issues/{id}/` | Retrieves one current issue record. |
| Mark false positive / won't fix in NightVision | `PUT`, then `GET`, at `/api/v1/issues/{id}/` | Sets `resolution` to `2` or `4` for the clicked button, then verifies the saved ID and value. |
| Save local validation | No API request. | Writes preferences. |
| Filter or sort | No API request. | Changes the table view. |
| Export local validations | No API request. | Writes a local file. |
| Validation report… | No API request. | Snapshots loaded data, previews, and writes a chosen CSV/HTML file. |
| Attach / view / remove retest evidence | No API or target request. | Saves, verifies, reads, or explicitly removes local attachment files. |
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
| SSO login timeout | Five minutes, enforced by the extension without depending on CLI timeout flags. |
| Saved credential size | Token up to 16 KiB; config file up to 1 MiB. Token must contain nonempty printable ASCII text. |
| CLI diagnostic capture | Drains all output but keeps only the first 64 KiB in memory for classification. Raw output is not displayed or saved. |
| SSO API origin | Production `https://api.nightvision.net` only. |
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
| HTTP 401 | For SSO/saved login, click **Sign in with SSO** again. For manual tokens, check validity and token format. |
| CLI cannot start | Install the current CLI. Use **Browse** to select its executable; GUI-launched Burp may have a different PATH from your terminal. |
| SSO browser does not open or CLI exits | Run `nightvision login` from a normal desktop terminal, complete SSO, then click **Use saved login**. Version 0.3.1 no longer passes the compatibility-sensitive `--timeout` flag. Read **Connection diagnostics** for exit details. |
| No reusable saved login | Click **Use saved login** with auto-detection; if needed, use **Browse login file** to choose `.nightvision/nightvision.yml`. Read **Connection diagnostics** for checked paths. Run terminal login under the same OS environment as Burp. |
| SSO timeout | Retry and finish the browser flow within five minutes; check the desktop browser and local callback availability. |
| SSO refuses API origin | Use `https://api.nightvision.net`; other origins require a manually supplied token. |
| HTTP 403 | Check resource and update permissions. A token may be able to read an issue without permission to update it. |
| HTTP 404 | Check the ID, API origin, and access. |
| HTTP 429 | Wait before retrying; there is no automatic rate-limit retry. |
| Redirect or unexpected HTTP status | Verify the API origin and whether a gateway is redirecting to a login page. Redirects are not followed. |
| SSLHandshakeException / certificate-chain failure | On Windows, leave **Use trusted Windows roots** enabled and reconnect. If needed, select your IT-provided issuer CA using **Browse CA**, then click **Use saved login**. Read **Connection diagnostics** for the actual failure class. |
| Certificate hostname mismatch | Check API origin and the certificate presented by the server/network gateway; adding an issuer CA does not bypass hostname validation. |
| Expired/not-yet-valid certificate | Check the system clock and have the server or inspecting gateway’s certificate validity checked. |
| Invalid additional CA file | Select a currently valid issuer/root CA certificate, in PEM or DER form, rather than a server leaf certificate. |
| Other network or TLS failure | Read **Connection diagnostics**; Burp’s upstream proxy settings do not automatically configure this Java client. |
| Connection succeeds but no scans appear | Clear an unnecessary project filter, check account access, and reconnect. An accessible collection can be empty. |
| Findings appear empty | Check the load result and clear the text filter. |
| Old scan's findings remain | Click **Load findings** after changing the scan and confirm success. Failed loads can retain the prior table. |
| Request or response is blank | Use 0.2.1 or newer, select the finding, and click **Fetch full finding**. Read the label above the editor; inspect `extra_info.http_requests` and `extra_info.http_responses` in JSON. Empty arrays mean no captures were returned. Unsupported bodies need the original text or another adapter. |
| Request format error | Paste raw HTTP beginning with a request line, not a curl command. |
| Attach retest evidence is absent or fails | Check the request/response editor’s Extensions submenu after receiving a response. Version 0.5.8 supports both requestResponse() and the getRequestResponse() accessor in Burp 2022.12.6, plus the early exchange and byte getter names. A remaining API failure keeps a diagnostic action visible; click it and inspect the sanitized error log. No other exchange is substituted. |
| Open in Repeater seems to do nothing | Read the receipt directly below the button. Select Repeater manually if it is undocked. For a handoff failure, check Extensions → NightVision → Errors for the stage/type. Save unsaved notes before replacing the extension. |
| Replay reaches an unexpected host or path | Check destination, Repeater service, request line, and Host header independently. |
| Replay returns a login page, 401, or 403 | Refresh target application credentials. The NightVision API token does not authenticate the target. |
| Local save does not change NightVision | Expected: use the separate remote false-positive or won't-fix button. |
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
dist/nightvision-burp-0.5.8.jar
```

It performs these steps:

1. Finds Java on PATH.
2. Downloads pinned Montoya, Gson, and SnakeYAML dependencies when not cached.
3. Verifies pinned SHA-256 digests, including cached files.
4. Compiles Java 17-compatible extension classes.
5. Compiles and runs offline regression checks against a mock Montoya host.
6. Packages the extension, demo, Gson and SnakeYAML classes, and license texts into the JAR.

Dependencies are cached in `.build/deps/`; compiled classes go to `target/`. These directories can be recreated. Gson and SnakeYAML are bundled; Montoya classes are supplied by Burp and are not bundled.

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
target/nightvision-burp-0.5.8.jar
```

Maven includes Gson and SnakeYAML and treats Montoya as provided. The standalone regression checks are not registered with Maven Surefire. Use `tools/build.py` to run those checks. The Python build was exercised during development; the Maven alternative was not separately executed in that environment.

### Check the supplied JAR hash

The package includes `dist/SHA256SUMS.txt`. On Linux, enter the `dist` directory and run:

```bash
sha256sum -c SHA256SUMS.txt
```

On Windows, from the project directory:

```powershell
Get-FileHash .\dist\nightvision-burp-0.5.8.jar -Algorithm SHA256
Get-Content .\dist\SHA256SUMS.txt
```

Compare the reported hash with the text file. That checksum describes the distributed binary. The build script does not regenerate `SHA256SUMS.txt`. A rebuilt archive may have a different hash, including differences caused by ZIP metadata; calculate a new hash for a rebuilt release.

## 18. Verification and test coverage

Version 0.5.8 passed **464 checks**, without external NightVision API calls, covering:

- API endpoints, queries, token headers, and update payloads.
- Actual won't-fix button clicks: code-4-only writes, separate read-back gating, permission/mismatch failures, no retries, preserved notes, saved receipt/reload, and reviewed HTML/CSV output.
- Repeated actual Save-button clicks against a real Java preference store: one current record per issue, replacement and clearing of notes, fresh-instance reload, regenerated HTML/CSV files and previews, immutable older snapshots, preserved remote-sync receipts, and cleared notes taking precedence over legacy records.
- Pagination, loops, malformed collections, and credential boundaries.
- Rejection of pagination links that change origin, port, scheme, or collection path.
- Errors that omit raw response bodies and token values.
- Request-header normalization and body-text newline preservation.
- Finding names, destination adaptation, and raw traffic extraction.
- Actual Repeater button clicks through Montoya's static service/request factories: edited messages, host/port/TLS overrides, default tab naming/navigation, invalid inputs, runtime/linkage errors, sanitized diagnostics, detached layouts, no duplicate retry/network send, preserved notes, and unload protection.
- Isolated editor API fixtures reproduce the exact previous requestResponse() NoSuchMethodError, then verify Object/Optional return descriptors, null/empty and unsupported values, missing methods, and no substitution of another table selection. Registered menu callback tests cover visible diagnostic actions, deduplicated safe logs, response availability, attachment-time linkage failures, and no storage/network/preference writes on failure.
- Installed Repeater API resolution: basic and named-only interfaces, void/non-void returns, private host implementations accessed through public interfaces, failure unwrapping without retry, missing methods, safe signature extraction, and bounded product-version diagnostics.
- NightVision structured request/response arrays, multiple captures, HAR-style headers, cookies, postData, content, and base64 UTF-8 bodies.
- Escaped paths, duplicate headers, Unicode, body newline preservation, unsupported bodies, and malformed captures.
- Mocked list-to-detail loading that populates both editors, capture selectors, per-request destinations, request edit preservation while browsing responses, and clearing on disconnect.
- Issue-specific false-positive and won't-fix writes with only `resolution: 2` or `resolution: 4`, deployed resolution labels (0/1/2/4), corrected UI/report/sync receipts, and rejection of resolved (1) read-backs.
- Permission failures, wrong read-back resolution, mismatched ID, and failed verification.
- Distinction between an accepted update and a verified saved result.
- Swing tab registration, demo, filtering, notes, and remote-status display.
- Recording verified-sync metadata only after read-back succeeds.
- SSO subprocess arguments, executable paths with spaces, bounded output classification without raw-output logging, and removal of inherited token/API overrides.
- Saved-credential validation, process failure without stale-login fallback, cancellation, timeout, and unload cleanup using real child Java fixtures.
- Saved-login origin boundaries, verified user identity before scan loading, 401/403/service errors, and absence of credentials in Burp preferences.
- Current CLI YAML config from a simulated terminal/browser login, JSON, quoting, comments, BOM, config precedence, selected files, legacy fallback, and wrong-origin rejection.
- Malformed YAML, duplicate and ambiguous keys, custom tags, nested token rejection, and diagnostic errors that omit source lines and credentials.
- A synthetic older CLI that rejects `--timeout`, and noisy failing output larger than the retained capture cap.
- Real loopback HTTPS with a generated test CA: reject untrusted chains before sending Authorization, accept a selected CA, reject a wrong hostname, and retain isolation from global JVM trust.
- A real Swing connection failing on TLS and recovering after a CA is selected; safe diagnostics, invalid CA inputs, and retained uncertainty/no retry for TLS-failed writes.
- Report scope and sorting, saved annotations versus unsaved edits, original capture provenance, optional evidence, common credential redaction, HTML escaping, CSV formula/quote/newline handling, size/preview limits, and staged file replacement.
- A real temporary Java preference store: reproduction of the oversized-key failure, supported compact keys, saved status/notes/time, fresh-extension reload, written HTML/CSV, origin isolation, legacy reads, and truthful failure handling for dropped/throwing writes.
- Pre-1.0 API capture: getRequestResponse(), httpRequest()/httpResponse(), asBytes(), response availability without hasResponse(), and service metadata from the same exchange's request; no alternate table selection or method-body retry.
- Retest evidence: explicit editor/table selection, defensive byte snapshots, request/response bounds, actual registered menu actions, cancellation/busy behavior, chosen finding ownership, preserved notes/verdicts, raw/binary file fidelity, hashes, malformed/transplanted/symlink records, locking, safe removal, limits, fresh-controller reload, stale-load rejection, and HTML provenance/redaction.

These use mocked REST responses, a mock Montoya host, real synthetic CLI subprocesses, a real disposable Java preference node, and a local HTTPS server. TLS fixtures use JDK `keytool` to generate temporary certificates and private keys during tests, then remove them. No generated private key is packaged. They do not prove real-tenant SSO/identity-provider compatibility, native Windows-store behavior on every JVM, company gateway compatibility, permissions, platform classification side effects, all evidence formats, or compatibility with every Burp version. The official Linux CLI’s help and compiled configuration/login routines were inspected; this confirmed current `nightvision.yml` storage and the top-level `token` key. No real account login was performed during development.

The same compiled Repeater runner also passed **52 checks each** with the published Montoya **2023.12.1** and **2024.12** API libraries on its runtime classpath. These checks use a mock Burp host and validate API linkage/workflow, not a live installation of those Burp versions.

The Python build additionally runs **56 pre-1.0 evidence workflow checks** in a separate JVM containing the pinned Montoya **0.10.1** API, with the current SDK absent from that classpath. This exercises the Repeater editor selection, completed-response checks, exact raw/binary bytes, explicit target choice, save, hashes, reload, and written reports through the real early API names. It does not run a live Burp UI or contact a NightVision tenant.

The API classes bundled in the official **Burp Community 2022.12.6** JAR were additionally inspected. The same compiled code passed **56 evidence workflow checks** and **52 Repeater checks** with those exact extracted API classes, with the current SDK absent from the runtime classpath. This validates the older getter names and handoff linkage with a mock host; the Burp application UI was not launched. No Burp/API binaries are redistributed in this package.

### Suggested integration check

1. Load the JAR and inspect Burp's extension errors.
2. Try the installed offline demo and local save/export.
3. Use **Sign in with SSO**, complete your organization’s browser login, and confirm the reported account and scan list. Restart Burp and check **Use saved login**. Manual-token mode remains available.
4. Compare one finding's full JSON and extracted traffic with NightVision's evidence.
5. Open its request in Repeater and verify service and application authentication before testing.
6. On a validated finding you intend to reclassify, perform the remote action and confirm the result in NightVision.

## 19. Project files and dependencies

| Path | Purpose |
| --- | --- |
| `README.md` | This feature and operations guide. |
| `dist/nightvision-burp-0.5.8.jar` | Prebuilt extension. |
| `dist/SHA256SUMS.txt` | Distributed JAR hash. |
| `pom.xml` | Maven dependencies and shaded build. |
| `tools/build.py` | Build and offline-check runner. |
| `src/main/java/local/nightvision/NightVisionExtension.java` | Burp entry point, Swing UI, annotations, background actions, remote action, and exports. |
| `src/main/java/local/nightvision/NightVisionClient.java` | API transport, user verification, pagination, explicit resolution update, and verification. |
| `src/main/java/local/nightvision/NightVisionLogin.java` | Official CLI login lifecycle, saved-credential reading, origin binding, cancel, and timeout. |
| `SSO-SETUP.md` | Short SSO installation and upgrade guide. |
| `TLS-SETUP.md` | API certificate-trust recovery guide. |
| `REPORTS.md` | Report workflow, scope, evidence, redaction, and output limits. |
| `EVIDENCE.md` | Manual retest attachment, viewing, local storage, integrity checks, removal, and report workflow. |
| `src/main/java/local/nightvision/EvidenceStore.java` | Immutable local attachment records, binary message files, metadata, hashes, bounded reads, atomic commits, and safe removal. |
| `src/main/java/local/nightvision/EvidenceCapture.java` | Explicit exchange selection, current/pre-1.0 editor/exchange/byte aliases, and bounded raw-message snapshots. |
| `src/main/java/local/nightvision/EvidenceController.java` | Context-menu action, attachment dialog, evidence tab, and file workers. |
| `src/test/java/local/nightvision/RepeaterSelfTest.java` | Real button/static-factory handoff, API shape compatibility, docked navigation, and safe failure regression checks. |
| `src/main/java/local/nightvision/RepeaterBridge.java` | Public runtime API lookup, basic handoff preference, one invocation, and safe missing-member/version diagnostics. |
| `src/test/java/local/nightvision/EvidenceCompatibilitySelfTest.java` | Isolated runtime editor API descriptors and real registered menu failure-action regression checks. |
| `src/test/java/local/nightvision/EvidenceSelfTest.java` | File-backed capture, context-menu, ownership, binary integrity, reload, and report tests. |
| `examples/sample-validation-report.html` and `.csv` | Synthetic validation report examples. |
| `src/main/java/local/nightvision/ValidationReport.java` | Immutable report model, HTML/CSV rendering, spreadsheet text protection, and staged file writes. |
| `src/main/java/local/nightvision/ReportRedactor.java` | Common credential-pattern redaction for report fields. |
| `src/test/java/local/nightvision/ReportSelfTest.java` | Report generation, scoping, escaping/redaction, and file-write regression checks. |
| `src/test/java/local/nightvision/ResolutionSelfTest.java` | Won't-fix request payloads, actual button verification/failure behavior, saved receipt/reload, and reviewed HTML/CSV reports. |
| `src/test/java/local/nightvision/PersistenceSelfTest.java` | Real Java preference limits, save/read-back, reload-to-report, legacy compatibility, and failed-write regression checks. |
| `src/main/java/local/nightvision/TlsSupport.java` | API-scoped trust, Windows roots, additional CA loading, hostname-preserving trust delegation, and safe TLS diagnostics. |
| `src/test/java/local/nightvision/TlsSelfTest.java` | Real local HTTPS trust, hostname, isolation, and UI recovery tests. |
| `src/main/java/local/nightvision/SavedLogin.java` | Bounded current-config/legacy-credential parsing and configured API checks. |
| `src/main/java/local/nightvision/Finding.java` | Field adaptation, resolution labels, capture access, destination validation, and request preparation. |
| `src/main/java/local/nightvision/Traffic.java` | NightVision capture arrays, raw formats, structured HTTP reconstruction, and unsupported-content diagnostics. |
| `src/test/resources/nightvision-structured-traffic.json` | Synthetic live-format traffic fixture; contains no tenant data. |
| `src/main/resources/demo-findings.json` | Synthetic finding. |
| `src/test/java/local/nightvision/SelfTest.java` | Offline regression checks. |
| `src/test/java/local/nightvision/LoginSelfTest.java` | SSO process, saved credential, cancellation, and UI regression tests. |
| `src/test/java/local/nightvision/LoginProcessFixture.java` | Synthetic child process used by tests; never opens a browser or calls NightVision. |
| `THIRD_PARTY_NOTICES.md` | Dependency and license notices. |
| `licenses/GSON-APACHE-2.0.txt` | Gson license. |
| `licenses/SNAKEYAML-APACHE-2.0.txt` | SnakeYAML license. |

| Dependency | Version | Use |
| --- | --- | --- |
| PortSwigger Montoya API | 2026.7 | Compile-time API supplied by Burp at runtime. |
| PortSwigger Montoya API | 0.10.1 | Python build legacy workflow test only; absent from compile/runtime packaging. |
| Google Gson | 2.13.2 | JSON processing; bundled. |
| SnakeYAML | 2.5 | CLI configuration parsing with SafeConstructor; bundled. |
| Maven Compiler Plugin | 3.14.1 | Maven build only. |
| Maven Shade Plugin | 3.6.1 | Maven packaging only. |

Apache 2.0 license texts for Gson and SnakeYAML are included in the package and JAR. Review `THIRD_PARTY_NOTICES.md`. This custom extension is not published to the BApp Store.

## 20. Current limitations

- Live Burp/NightVision integration remains untested in the development environment.
- Traffic extraction is best effort; some formats require an adapter or manual paste.
- The text editor does not support byte-exact binary replay. Base64 UTF-8 text is supported; binary or unknown encodings need another workflow.
- Original scanner capture selectors are independent; matching positions are not treated as a pairing. A retest attachment stores one exchange explicitly selected in Burp.
- Validation is manual. Evidence is attached through an explicit context-menu action; no automatic interception, correlation, or vulnerability verdict is performed.
- No automatic polling, scan monitoring, scan launching, or active scanning is included.
- Remote false-positive (2) and won't-fix (4) actions are included; remote reopen and resolve are not included.
- No bulk remote update, finding deletion, or suppression-management controls are included.
- Notes stay local; preferences retain the latest assessment and last verified sync, not full edit history.
- No built-in import, cross-machine annotation synchronization, or purge-all control is included.
- JSON exports and HTML/CSV reports cover loaded data only. No multi-scan comparison or automatic refresh is included.
- Report redaction covers common patterns, not all secrets/personal data. HTML can include loaded scanner text, the selected finding's chosen original captures, and explicitly saved retest attachments from the configured local folder. CSV and JSON exports omit retest HTTP messages.
- Retest evidence permits 1 MiB requests, 2 MiB responses, and 50 attachments per finding. HTML evidence enrichment is limited to 100 attachments and 32 MiB of source messages. Binary bodies are stored exactly but omitted from text previews/reports.
- SSO depends on the official current CLI and a usable desktop browser; it is limited to the production API origin.
- API trust can use JVM roots, available native Windows roots, and an additional CA certificate file. Importing password-protected trust stores and configuring client TLS private keys are not implemented.
- No extension-level proxy or direct Bearer-token controls are included.
- The extension does not auto-connect, revoke credentials, log out the browser, or manage identity-provider policies.
- No Burp Site Map issue import, Scanner integration, or automatic association of Repeater responses is implemented.

## 21. Frequently asked questions

### Does Save local validation update NightVision?

No. It saves locally. The remote false-positive and won't-fix actions use separate buttons and require update permission.

### Will a local False positive or Won't fix assessment synchronize later?

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

A manually entered API token is not persisted by the extension. For SSO, the official CLI saves its credential separately; click **Use saved login** after restarting Burp to verify and reuse it.

### Do I have to reinstall the extension every time?

Burp can reload it on startup: enable **Settings → Extensions → Core extension settings → Automatically reload extensions on startup**, keep the extension’s **Loaded** checkbox selected, and keep the JAR at a permanent path. This is separate from authentication; click **Use saved login** to reconnect after Burp starts.

### Does Disconnect remove saved assessments?

No. It clears the connection and loaded view. Preferences, exports, and Repeater tabs remain. The saved CLI credential and browser session also remain.

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
| 0.2.1 | Fixed empty request/response tabs for NightVision's structured capture arrays; added multiple-message selectors, per-capture destinations, reconstruction labels, missing-content diagnostics, and regression coverage. |
| 0.3.0 | Added SSO through the official CLI, saved-login reuse, CLI executable selection, user verification, cancel/timeout handling, and credential/process regression checks. |
| 0.3.1 | Fixed current CLI YAML/JSON credential loading, added saved-file selection and safe connection diagnostics, and removed dependency on the CLI `--timeout` flag. |
| 0.3.2 | Added API-scoped trusted Windows roots, an additional CA file option, classified TLS diagnostics, and real loopback TLS/hostname regression tests. |
| 0.4.0 | Added scoped HTML/CSV validation reports, saved-note and optional evidence controls, redacted previews, summary counts, staged writes, synthetic examples, and report regression checks. |
| 0.4.1 | Fixed oversized validation preference keys, added save read-back confirmation and legacy-key reads, and verified persistence through fresh controllers and written reports using a real Java preference store. |
| 0.5.0 | Added explicit Burp retest evidence attachment, chosen finding ownership, file-backed raw/binary storage with hashes, a viewer/removal tab, and HTML report integration with provenance and redaction. |
| 0.5.1 | Added direct Repeater action feedback, docked tool navigation, visible/sanitized API failure diagnostics, and actual button/factory regression checks. |
| 0.5.2 | Replaced the direct named-tab Repeater call with runtime public-API lookup and a basic handoff preference; added return/overload compatibility checks and useful sanitized missing-member/version diagnostics. |
| 0.5.3 | Fixed the evidence editor accessor linkage failure with public runtime lookup; retained a visible diagnostic action for unreadable exchanges, guarded availability/snapshot linkage failures, and deduplicated safe API warnings. |
| 0.5.4 | Added pre-1.0 evidence API aliases for Burp 2022.12.6, including editor/exchange/byte access and service/response availability fallbacks; added an isolated early-API workflow test to every Python build. |
| 0.5.5 | Made local-validation replacement explicit in the UI and save receipt, labeled reports with the latest saved notes, explained report regeneration, and verified repeated saves, clearing, reload, and written reports with real preferences. |
| 0.5.6 | Added Kevin Thomas author credit in the extension interface, source entry point, README, JAR/Maven metadata, and HTML report footer. |
| 0.5.7 | Corrected resolved/false-positive codes in writes, read-back checks, and labels; added won't-fix display and regression checks for resolved read-backs. |
| 0.5.8 | Added a separate verified won't-fix (4) button, local validation label, saved sync receipt, reviewed report support, and actual-button/transport regression checks. |

This README documents version 0.5.8.

### References

- [NightVision CLI installation and browser login](https://docs.nightviz.ai/welcome/tutorials-and-guides/installing-the-cli/)
- [NightVision saved-login credential behavior](https://docs.nightviz.ai/integrations/mcp-server/)
- [NightVision public CLI login integration source](https://github.com/nvsecurity/nightvision-mcp/blob/main/src/services/auth-service.ts)
- [Java native Windows certificate-store provider](https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html)
- [Java extended trust manager and endpoint checks](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/net/ssl/X509ExtendedTrustManager.html)
- [NightVision REST API reference](https://docs.nightviz.ai/reference/)
- [NightVision public OpenAPI document](https://docs.nightviz.ai/openapi/nightvision-rest-api.yaml)
- [NightVision web application (deployed resolution mapping)](https://app.nightvision.net/)
- [NightVision MCP type comments (outdated resolution labels)](https://github.com/nvsecurity/nightvision-mcp/blob/main/src/types/index.ts)
- [NightVision structured evidence handling in its own client](https://github.com/nvsecurity/nightvision-mcp/blob/main/src/services/issue-service.ts)
- [NightVision scan findings and evidence](https://docs.nightviz.ai/welcome/key-concepts/dast-scans/)
- [PortSwigger: install a custom extension](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install)
- [PortSwigger: Montoya Repeater API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/repeater/Repeater.html)
- [PortSwigger: extension development setup](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/manual-setup)

API endpoints were initially reviewed on October 22, 2026. Resolution values were corrected on October 28, 2026 using the deployed NightVision web app and the public OpenAPI enum; see the false-positive upgrade note above. Structured capture handling was checked against NightVision's public client on October 26, 2026. The implemented source is the authority for this release's behavior; later platform changes may require an extension update.
