# Manual retest evidence — version 0.5.8

Attach a completed HTTP exchange selected in Burp to a loaded NightVision
finding. The extension saves the request and response locally, verifies their
SHA-256 hashes, and can include the attachment in an HTML validation report.
It does not send the selected request, infer a verdict, or update NightVision.

## Attach a retest

1. Connect to NightVision and load the scan's findings. You can also use the
   offline demo with synthetic traffic for an initial check.
2. Open the request in Repeater, verify its destination and authentication,
   and perform your manual test by clicking **Send** in Repeater.
3. Right-click the completed request or response and choose
   **Attach retest evidence to NightVision…**. A single selected completed
   exchange is required; a request without a response cannot be attached.
4. Choose the finding in **Attach to finding**. Confirm its issue UUID, scan,
   API origin, and target. The current NightVision table selection is only a
   suggested choice; the finding you explicitly choose owns the attachment.
5. Set a label and optional context, such as the tested application role.
   You can add separate attachment notes, up to 4,000 characters.
6. Optionally provide the actual test time as an ISO UTC timestamp, for example
   `2026-10-26T16:30:00Z`. Leave it blank when the test time is unknown.
7. Review the selected request/response and local folder, then click
   **Save evidence**. Wait for the saved-and-hash-verified receipt.

Burp may group the action under **Extensions → NightVision Finding Validator** in the editor’s right-click menu. For a selected request without a response, the action is disabled and its tooltip explains to send the request first.

Version 0.5.8 supports the early API used by Burp Community 2022.12.6: `getRequestResponse()`, `httpRequest()` / `httpResponse()`, and `asBytes()`, alongside their current API equivalents. When the early exchange interface has no `hasResponse()` or service accessor, response availability comes from that exchange's response and its own request supplies the HTTP service. The build runs the complete evidence workflow against the pinned pre-1.0 Montoya 0.10.1 API in a separate JVM. The compiled workflow was also checked against the API classes bundled with the official Burp Community 2022.12.6 release; a live Burp UI was not launched. If an exchange still cannot be read, the same menu label remains as a diagnostic-only action. Clicking it shows the failure; it never substitutes a different selected exchange or saves evidence. Repeated identical compatibility warnings are deduplicated in the extension error log.

The attachment time is recorded automatically in UTC. It is not represented
as the time the original request was sent. Test time, when supplied, is an
analyst-entered value. The source Burp tool and HTTP service are also recorded.

The selected message bytes are snapshotted before the dialog. Later edits
cannot change that pending snapshot. Attaching evidence leaves the saved local
verdict, validation notes, and any unsaved note edits untouched. Use
**Save local validation** separately to save your assessment.

## Review or remove evidence

Select a finding and open the **Retest evidence** tab. Its attachment selector
lists saved retests newest first. Selecting an entry verifies its hashes and
displays its metadata, request, and response.

The tab shows the evidence folder and supports **Browse folder**, **Refresh**,
and **Remove attachment**. Editing the folder clears the previous display;
click Refresh to load from the new location. Removing an attachment requires
confirmation and changes only that local evidence entry.

Views show up to 65,536 characters per message with a truncation marker.
Binary/non-UTF-8 bodies are explicitly omitted from text display while their
complete bytes remain saved. These are the message bytes exposed by Burp's
API, not a claim of original network-packet or HTTP/2 frame fidelity.

## Include retests in reports

Choose **Validation report… → HTML report** and keep **Include saved manual
retest attachments for findings in scope (HTML)** checked. It is initially
enabled for HTML. Each finding includes its saved attachments from the current
evidence folder, not just whichever attachment is selected in the viewer.

The report labels original NightVision captures separately from manually
attached Burp retests. Retests include the attachment label/context/notes,
source tool, attached and optional tested-at times, HTTP service and response
status, raw byte counts, fingerprints, and text representations of the request
and response. Known credential patterns are redacted and HTML is escaped.
The original evidence files are not changed by report generation.

CSV and the existing JSON validation export retain their previous metadata/
annotation scope and do not include raw retest traffic. The HTML report is a
readable record, not a byte-exact evidence backup. The `examples/` folder has
a synthetic report with retest evidence.

## Local storage and limits

The initial location is `<OS user home>/NightVision-Burp/evidence`, as reported
by the Java runtime. The **Retest evidence** tab shows the actual configured
path. A selected path is remembered in Burp preferences; raw HTTP messages
are stored in separate files, so they do not use the annotation preference
size allowance. Nothing is created merely by loading the extension or viewing
a finding with no saved evidence.

The folder groups attachments by a SHA-256 of API origin plus issue UUID. Each
attachment has its own UUID directory containing `metadata.json`, `request.bin`,
and `response.bin`. Files are staged, read back and hashed, and committed by
an atomic directory rename. A per-finding lock prevents competing writes.
Current local filesystems must support atomic moves. Owner-only permissions
are set where POSIX permissions are supported; Windows/existing folder access
is governed by the filesystem. No additional encryption layer is provided.

Raw messages may contain cookies, authentication headers, and application
data. They are saved only through the explicit attachment action and are not
uploaded to NightVision. Report redaction covers recognizable patterns and
cannot identify every secret in arbitrary content. Review reports before
sharing. Keep the evidence folder if you want the raw attachments to survive
an extension upgrade or move; changing the folder does not migrate its files.

| Limit | Value |
| --- | --- |
| Request | 1 MiB per attachment |
| Response | 2 MiB per attachment |
| Attachments | 50 per API origin and finding |
| Label / context / attachment notes | 160 / 500 / 4,000 characters |
| Retests in one HTML report | 100 attachments and 32 MiB of source messages |
| Existing report limits | 5,000 findings, 16 MiB output, 16,000 characters per text field, first 50 findings in the preview |

Files with changed hashes, mismatched ownership, missing data, or substituted
symlinks are rejected. An evidence-read error stops report preparation rather
than silently including an unverified record. Choose a narrower scope or omit
retest attachments when report limits are reached.
