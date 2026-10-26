# Validation reports — version 0.4.1

The extension creates HTML reports for review and printing, and CSV files for
spreadsheet analysis. Reports use the findings already loaded in Burp and the
local annotations you have saved. Creating a report makes no API request and
does not change a finding in NightVision.

## Upgrade when validations did not save

Version 0.4.1 fixes the earlier validation keys exceeding Java's preference-key
limit. Copy any notes still visible before unloading the older extension, then
load `dist/nightvision-burp-0.4.1.jar`. Re-enter any lost verdict/notes and click
**Save local validation**. Confirm the status says **Validation saved and read
back from Burp preferences** before creating the report.

Records previously accepted by a lenient host remain readable. Rejected writes
were never stored and cannot be recovered automatically. Failed saves now keep
your edits visible and show an error. HTML/CSV reports read their validation
fields from saved records, with **Include saved analyst notes** enabled for note text.

## Create a report

1. Load a scan and review its findings. Use **Save local validation** after
   changing a verdict or notes. Unsaved edits are excluded from reports.
2. For original HTTP evidence, select the finding and choose its captured
   request and response in the existing traffic selectors.
3. Click **Validation report…** beside the findings filter.
4. Enter a report title and, optionally, an analyst name. Choose **HTML report**
   or **CSV spreadsheet**.
5. Choose the scope and whether to include only reviewed findings.
6. Select the content options and click **OK** to preview the report.
7. Choose **Save report…**, select the destination, and confirm replacement if
   the file already exists. Closing the preview writes no report.

Open the saved HTML file in a browser to read it or use the browser's print
command to save a PDF. HTML reports contain their own styling and require no
internet access, JavaScript, or external assets. The `examples/` folder contains
synthetic HTML and CSV examples.

## Scope and saved state

| Choice | Included findings |
| --- | --- |
| All loaded findings | The loaded collection, including filtered-out rows, in loaded order. |
| Visible (filtered) findings | Rows currently visible, in the table's displayed sort order. |
| Selected finding | One selected table row. A selection is required. |
| Reviewed findings only | Further restricts the chosen scope to saved Confirmed, False positive, Needs review, or Retest passed verdicts. |

An unreviewed finding remains **Not reviewed** even if you changed the verdict
dropdown without saving. **Needs review** counts as reviewed because an analyst
has saved an assessment; it does not mean the issue has been resolved.

The report keeps **local verdict**, **last loaded NightVision resolution**, and
the **last remote-sync receipt** separate. A previous verified sync receipt is
historical metadata, not a new API check. The report does not infer that an
HTTP 200, a scanner result, or an analyst note proves remediation.

Metadata includes report title, analyst if supplied, generation time in UTC,
API origin or `offline-demo`, scope, issue and scan UUIDs, method and target,
severity, saved local verdict/time, and remote resolution/sync metadata.
The scan field uses loaded data, not a newly edited Scan UUID input.

## Content options

| Option | Default | Behavior |
| --- | --- | --- |
| Saved analyst notes | Included | Uses saved preference values; excludes temporary editor changes. |
| Scanner payload and evidence text | Excluded | HTML only. Adds payload, evidence, and evidence details present in the loaded records. Fetch full finding first when needed. |
| Selected finding's current capture choices | Excluded | HTML only. Adds the selected original request/response entries for that finding, if it is in the report scope. Other findings' traffic is excluded. |

HTTP entries retain their source field and reconstruction/unsupported-content
note. They are labeled **original captured HTTP evidence**. Matching positions
are not treated as a request/response pairing. Edited Request tab text,
temporary destination edits, and Repeater responses are excluded. Retest evidence
capture has not been added in this release.

CSV contains one row per finding and repeats metadata for independent filtering.
It includes notes only when selected; it never includes scanner payloads or HTTP
messages. Its UTF-8 byte-order mark helps spreadsheet applications display
Unicode. Quote and newline characters are escaped for CSV, and values starting
with common formula/control characters receive an apostrophe text prefix.
Spreadsheet applications vary, and editing/re-saving a CSV can change how it is
interpreted. The existing JSON export remains available for separate processing.

## Redaction and limits

The HTML/CSV report path redacts recognized Authorization, Proxy-Authorization,
Cookie, Set-Cookie, common API-key/CSRF headers, token/password/secret/session
key-value fields, sensitive URL query parameters, HTTP URL user information,
and recognizable Basic/Bearer/JWT credentials. Redaction also applies to notes
and report metadata. The source data and saved notes are not modified.

Pattern matching cannot identify every secret or personal detail in free-form
content. Review the preview and saved report before sharing. The legacy JSON
export keeps its existing behavior and does not use the new report redactor.

Reports support up to **5,000 findings** and **16 MiB** of UTF-8 output.
Individual text fields are limited to **16,000 characters**, with a visible
truncation marker. The in-app preview shows the first **50 findings** when the
scope is larger; summaries and the saved file still cover the complete chosen
scope. A large/empty report gives guidance to change the scope or omit evidence.

File writing is staged in the destination directory before replacement. Reports
are not automatically opened, uploaded, emailed, or synchronized.
