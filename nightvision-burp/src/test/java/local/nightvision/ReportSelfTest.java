package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static local.nightvision.SelfTest.*;

/** Report regression checks use synthetic evidence, an offline Burp host, and temporary files. */
final class ReportSelfTest {
    private static final Instant TIME = Instant.parse("2026-10-26T16:00:00Z");
    private static final ValidationReport.Options FULL = new ValidationReport.Options("Synthetic validation report", "Example analyst", true, true, true);

    /** Covers output escaping, credential patterns, spreadsheet cells, scoping, and file replacement. */
    static void run() throws Exception {
        for (String[] pair : List.of(
            new String[]{"Authorization: Bearer header-secret\r\n continued-secret\r\nHost: example.invalid", "header-secret"},
            new String[]{"Cookie: session=cookie-secret; preference=dark\nSet-Cookie: auth=setter-secret; Secure", "cookie-secret"},
            new String[]{"https://app.invalid/?access%5Ftoken=query-secret&view=normal", "query-secret"},
            new String[]{"{\"url\":\"https://app.invalid/?token=nested-query-secret\"}", "nested-query-secret"},
            new String[]{"{\"password\":\"quoted-secret\\\"escaped\",\"client_secret\":\"client-secret\"}", "quoted-secret"},
            new String[]{"refresh_token=form-secret&normal=value", "form-secret"},
            new String[]{"Basic YWxwaGE6YmV0YQ==", "YWxwaGE6YmV0YQ=="},
            new String[]{"https://user:password-secret@app.invalid/path", "password-secret"},
            new String[]{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.signature", "eyJhbGci"})) {
            String redacted = ReportRedactor.redact(pair[0]);
            check(!redacted.contains(pair[1]) && redacted.contains("[REDACTED]"), "Redact a recognizable credential without logging source text");
        }
        check(!ReportRedactor.redact("Authorization: value\r\n continued-secret\r\nHost: app.invalid").contains("continued-secret"), "Redact folded credential header continuations");
        check(ReportRedactor.redact("GET /?view=normal HTTP/1.1\nHost: app.invalid\n\nmarker=café").contains("view=normal"), "Retain noncredential parameters and Unicode evidence");
        check(ReportRedactor.redact("Cookie: session=synthetic-cookie").equals(ReportRedactor.redact(ReportRedactor.redact("Cookie: session=synthetic-cookie"))), "Report credential redaction is stable on already-redacted fields");
        check(!ReportRedactor.redact("{\"password\":\"" + "secret".repeat(20000) + "\"}").contains("secret"), "Handle long quoted credentials without regex recursion or partial leakage");
        check(!ReportRedactor.redact("{\"password\":\"" + "escaped\\\"secret".repeat(5000) + "\"}").contains("secret"), "Handle heavily escaped credential values without regex stack growth");
        check(!ReportRedactor.redact("Authorization: token\r\n" + " folded-secret\r\n".repeat(5000) + "Host: app.invalid").contains("folded-secret"), "Handle many folded header lines while retaining complete redaction");

        ValidationReport.Row unsafe = row(ISSUE, "<script>alert('finding')</script>", "Confirmed", "Saved café notes, \"quoted\"\npassword=note-secret");
        ValidationReport.Snapshot snapshot = snapshot(FULL, List.of(unsafe, row(SCAN, "Second finding", "Not reviewed", "Unreviewed saved note")));
        ValidationReport.Document html = ValidationReport.render(snapshot, ValidationReport.Format.HTML);
        check(!html.content().contains("<script>") && html.content().contains("&lt;script&gt;"), "Render hostile finding text as escaped text rather than executable HTML");
        check(html.content().contains("default-src 'none'") && !html.content().contains("<script ") && !html.content().contains("<img ") && !html.content().contains("href="), "Standalone HTML includes a restrictive policy and no external resources or links");
        check(html.content().contains("2 findings") && html.content().contains("1 reviewed") && html.content().contains("1 unreviewed"), "Summary counts derive from the chosen rows and explicit local verdicts");
        check(html.content().contains("NightVision resolution (last loaded)") && html.content().contains("Local verdict") && html.content().contains("Open (0)"), "Keep local confirmation separate from last loaded remote state");
        check(html.content().contains("not a Repeater retest") && html.content().contains("independent captures"), "Label optional HTTP evidence provenance without implying pairing or retest verification");
        check(!html.content().contains("note-secret") && !html.content().contains("capture-secret") && !html.content().contains("query-secret"), "Redact credentials consistently in notes, captures, and target URLs");
        check(html.content().contains("Saved café notes") && html.content().contains("2026-10-26T16:00:00Z"), "Include saved notes and explicit UTC report time");
        ValidationReport.Options minimal = new ValidationReport.Options("", "", false, false, false);
        ValidationReport.Document without = ValidationReport.render(snapshot(minimal, List.of(unsafe)), ValidationReport.Format.HTML);
        check(!without.content().contains("Saved café notes") && !without.content().contains("scanner-only-marker") && !without.content().contains("capture-only-marker"), "Notes, scanner evidence, and HTTP captures are opt-in/controlled fields");

        ValidationReport.Document csv = ValidationReport.render(snapshot, ValidationReport.Format.CSV);
        check(csv.content().startsWith("\ufeff\"Report title\"") && csv.content().contains("Saved café notes, \"\"quoted\"\"\npassword=[REDACTED]"), "UTF-8 CSV quotes commas, quotes, and multiline redacted notes");
        check(!csv.content().contains("scanner-only-marker") && !csv.content().contains("capture-only-marker"), "CSV omits scanner payloads and captured HTTP traffic");
        check(!csv.previewHtml().contains("scanner-only-marker") && !csv.previewHtml().contains("capture-only-marker"), "CSV preview omits evidence that the CSV file cannot contain");
        for (String formula : List.of("=1+1", "+cmd", "-1+1", "@SUM(A1)", " \t=1", "\ufeff=1", "＝1+1", "＋1", "－1", "＠SUM(A1)", "\r\n=1"))
            check(ValidationReport.csvCell(formula).startsWith("\"'"), "Prefix dangerous spreadsheet formula starters, including whitespace and full-width variants");
        check(ValidationReport.csvCell("normal,\"quoted\"\nnext").equals("\"normal,\"\"quoted\"\"\nnext\""), "Ordinary CSV values remain quoted text with preserved line breaks");

        List<ValidationReport.Row> many = new ArrayList<>();
        for (int i = 0; i < 51; i++) many.add(row("row-" + i, "Finding " + i, "Not reviewed", ""));
        ValidationReport.Document limited = ValidationReport.render(snapshot(minimal, many), ValidationReport.Format.HTML);
        check(limited.content().contains("Finding 50") && !limited.previewHtml().contains("Finding 50") && limited.previewHtml().contains("first 50 of 51"), "Limit only the preview while preserving the full export scope");
        ValidationReport.Row longRow = row(ISSUE, "Long notes", "Needs review", "x".repeat(17000));
        check(ValidationReport.render(snapshot(FULL, List.of(longRow)), ValidationReport.Format.HTML).content().contains("[Truncated after 16,000 characters]"), "Mark field truncation explicitly rather than silently omitting text");
        rejects(() -> ValidationReport.render(snapshot(minimal, List.of()), ValidationReport.Format.HTML), "Empty report cannot be exported as a misleading success");
        rejects(() -> ValidationReport.render(snapshot(minimal, Collections.nCopies(5001, unsafe)), ValidationReport.Format.HTML), "Apply the report row bound before rendering");
        ValidationReport.Row large = row(ISSUE, "Large report", "Confirmed", "x".repeat(16000));
        rejects(() -> ValidationReport.render(snapshot(FULL, Collections.nCopies(1200, large)), ValidationReport.Format.CSV), "Apply the report byte bound while building a large document");
        ValidationReport.Row unicode = row(ISSUE, "Unicode", "Confirmed", "x".repeat(15999) + "😀tail");
        String unicodeText = ValidationReport.render(snapshot(FULL, List.of(unicode)), ValidationReport.Format.HTML).content();
        check(!unicodeText.contains("\ud83d") && unicodeText.contains("[Truncated"), "Avoid splitting a Unicode surrogate pair at the field truncation boundary");

        Path folder = Files.createTempDirectory("nightvision-report-tests-");
        try {
            Path target = folder.resolve("report.html");
            ValidationReport.write(target, html, false);
            check(Files.readString(target).equals(html.content()), "Write the reviewed snapshot as UTF-8 without changing its contents");
            try { ValidationReport.write(target, without, false); throw new AssertionError("Existing report requires overwrite approval"); }
            catch (FileAlreadyExistsException e) { check(Files.readString(target).equals(html.content()), "Refuse an unapproved overwrite and preserve the previous file"); }
            ValidationReport.write(target, without, true);
            check(Files.readString(target).equals(without.content()), "Approved replacement writes the new report");
            try (var paths = Files.list(folder)) { check(paths.count() == 1, "Clean temporary staging files after success and failure"); }
        } finally {
            try (var files = Files.walk(folder)) { for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(file); }
        }
        testScopes();
    }

    /** Controlled fixture includes both a local verdict and independently open remote resolution. */
    private static ValidationReport.Row row(String id, String title, String verdict, String notes) {
        return new ValidationReport.Row(id, SCAN, title, "HIGH", "GET", "https://app.invalid/path?token=query-secret&view=normal", "Open (0)", verdict,
            TIME.toString(), notes, "", "", "scanner-only-marker", "Original scanner evidence", "Capture is not proof of exploitation.",
            List.of(new ValidationReport.Capture("request", "extra_info.http_requests[0]", "Captured raw HTTP text", "https://app.invalid/",
                "GET / HTTP/1.1\r\nHost: app.invalid\r\nAuthorization: Bearer capture-secret\r\n\r\ncapture-only-marker")));
    }
    private static ValidationReport.Snapshot snapshot(ValidationReport.Options options, List<ValidationReport.Row> rows) {
        return new ValidationReport.Snapshot(options, "offline-demo", SCAN, "All loaded findings", TIME, rows);
    }

    /** Exercises report snapshotting against sorted/filtered Swing state and unsaved editor changes. */
    private static void testScopes() throws Exception {
        Map<String, String> prefs = new HashMap<>();
        NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) mock(MontoyaApi.class, prefs, new AtomicReference<Component>()));
        SwingUtilities.invokeAndWait(() -> {
            invoke(extension, "demo");
            ((JTextArea) field(extension, "notes")).setText("saved report note");
            ((JComboBox<?>) field(extension, "verdict")).setSelectedItem("Needs review"); invoke(extension, "saveValidation");
            int saved = prefs.size();
            ((JTextArea) field(extension, "notes")).setText("unsaved-note-excluded");
            ((JTextArea) field(extension, "request")).setText("edited-request-excluded");
            ((JTextField) field(extension, "scanId")).setText("edited-scan-excluded");
            ValidationReport.Snapshot report = extension.reportSnapshot(NightVisionExtension.ReportScope.SELECTED, true, FULL);
            check(report.rows().size() == 1 && report.rows().get(0).notes().equals("saved report note"), "Reports use saved annotations rather than unsaved note edits");
            check(report.rows().get(0).scanId().equals(SCAN) && !report.scanId().equals("edited-scan-excluded"), "Do not treat an edited Scan UUID input as the provenance of loaded findings");
            String html = ValidationReport.render(report, ValidationReport.Format.HTML).content();
            check(!html.contains("edited-request-excluded") && html.contains("GET /search"), "Optional HTTP evidence uses original selected captures, not editable request text");
            check(prefs.size() == saved && ((JTextArea) field(extension, "notes")).getText().equals("unsaved-note-excluded"), "Reporting leaves preferences and unsaved editor state unchanged");
            try {
                var method = NightVisionExtension.class.getDeclaredMethod("setFindings", List.class); method.setAccessible(true);
                JsonObject first = json("{\"id\":\"" + ISSUE + "\",\"scan_id\":\"" + SCAN + "\",\"kind\":{\"name\":\"Alpha\"}}");
                JsonObject second = json("{\"id\":\"" + SCAN + "\",\"scan_id\":\"" + SCAN + "\",\"kind\":{\"name\":\"Beta\"}}");
                method.invoke(extension, List.of(first, second));
            } catch (Exception e) { throw new RuntimeException(e); }
            JTable table = (JTable) field(extension, "table");
            table.getRowSorter().toggleSortOrder(1); table.getRowSorter().toggleSortOrder(1);
            check(extension.reportSnapshot(NightVisionExtension.ReportScope.VISIBLE, false, FULL).rows().get(0).title().equals("Beta"), "Visible report scope preserves the table's displayed sort order");
            ((JTextField) field(extension, "search")).setText("Beta"); table.setRowSelectionInterval(0, 0);
            check(extension.reportSnapshot(NightVisionExtension.ReportScope.VISIBLE, false, FULL).rows().size() == 1, "Visible scope excludes rows hidden by the table filter");
            check(extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, false, FULL).rows().size() == 2, "All-loaded scope includes rows hidden by the filter");
            check(extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, true, FULL).rows().size() == 1, "Reviewed-only scope uses saved recognized verdicts and excludes unreviewed rows");
            table.clearSelection();
            try { extension.reportSnapshot(NightVisionExtension.ReportScope.SELECTED, false, FULL); throw new AssertionError("Selected scope needs a selection"); }
            catch (IllegalArgumentException e) { check(true, "Report selected scope rejects a missing selection"); }
            ((JTextField) field(extension, "search")).setText("does-not-match");
            try { extension.reportSnapshot(NightVisionExtension.ReportScope.VISIBLE, false, FULL); throw new AssertionError("No visible findings"); }
            catch (IllegalArgumentException e) { check(true, "Report empty visible scope gives useful guidance"); }
        });
    }
}
