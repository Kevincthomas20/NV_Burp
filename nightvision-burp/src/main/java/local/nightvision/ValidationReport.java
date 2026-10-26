package local.nightvision;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/**
 * Pure report generation from an immutable snapshot of already-loaded findings and
 * saved annotations. It never calls NightVision, changes verdicts, or infers that
 * a successful HTTP response proves remediation. Rendering and file I/O run off the EDT.
 */
final class ValidationReport {
    static final int MAX_ROWS = 5000, MAX_FIELD = 16000, MAX_BYTES = 16 * 1024 * 1024, PREVIEW_ROWS = 50;
    private ValidationReport() {}
    enum Format {
        HTML("HTML report", "html"), CSV("CSV spreadsheet", "csv");
        final String label, extension;
        Format(String label, String extension) { this.label = label; this.extension = extension; }
        @Override public String toString() { return label; }
    }
    record Options(String title, String analyst, boolean notes, boolean scannerEvidence, boolean httpEvidence) {
        Options {
            title = title == null || title.isBlank() ? "NightVision validation report" : title.trim();
            analyst = Objects.toString(analyst, "").trim();
        }
    }
    /** Only the explicitly selected original captures are attached, never unsaved request edits. */
    record Capture(String direction, String source, String note, String destination, String text) {}
    record Row(String issueId, String scanId, String title, String severity, String method, String target,
               String remoteResolution, String verdict, String updatedAt, String notes, String syncStatus,
               String verifiedAt, String payload, String evidence, String evidenceDetails, List<Capture> captures) {
        Row { captures = List.copyOf(captures); }
        boolean reviewed() { return Set.of("Confirmed", "False positive", "Needs review", "Retest passed").contains(verdict); }
    }
    record Snapshot(Options options, String origin, String scanId, String scope, Instant generatedAt, List<Row> rows) {
        Snapshot { rows = List.copyOf(rows); }
    }
    record Document(Format format, String content, String previewHtml, int count) {}

    /** Uses one snapshot for both the preview and exported bytes, so later edits cannot alter it. */
    static Document render(Snapshot snapshot, Format format) {
        if (snapshot.rows().isEmpty()) throw new IllegalArgumentException("No findings match the report options.");
        if (snapshot.rows().size() > MAX_ROWS) throw new IllegalArgumentException("Reports support up to 5,000 findings. Filter the table or select a smaller scope.");
        if (format == Format.CSV) {
            // CSV has no evidence columns; its preview must not show evidence absent from the file.
            Options options = snapshot.options();
            snapshot = new Snapshot(new Options(options.title(), options.analyst(), options.notes(), false, false),
                snapshot.origin(), snapshot.scanId(), snapshot.scope(), snapshot.generatedAt(), snapshot.rows());
        }
        String content = format == Format.HTML ? html(snapshot, snapshot.rows().size(), false) : csv(snapshot);
        if (content.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
            throw new IllegalArgumentException("Report exceeds 16 MiB. Reduce the scope or omit evidence.");
        // The full exported report remains complete; only the in-app preview is limited to 50 rows.
        String preview = html(snapshot, Math.min(PREVIEW_ROWS, snapshot.rows().size()), true);
        return new Document(format, content, preview, snapshot.rows().size());
    }

    /** Escapes all external text; the standalone document has no scripts, links, or remote assets. */
    private static String html(Snapshot snapshot, int limit, boolean preview) {
        Options options = snapshot.options();
        StringBuilder out = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            + "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            + "<meta name=\"referrer\" content=\"no-referrer\"><title>");
        out.append(escape(text(options.title()))).append("</title><style>")
            .append("body{font:15px/1.55 system-ui,sans-serif;color:#172b4d;background:#f3f6fa;margin:0}main{max-width:1120px;margin:auto;padding:36px 26px}"
                + "h1{font-size:30px;line-height:1.2;margin:6px 0 20px}h2{font-size:21px;margin-top:28px}h3{font-size:18px}"
                + ".eyebrow{color:#285ea8;font-weight:700;letter-spacing:.08em;font-size:12px}.muted{color:#52647b}.notice{background:#e9f0fa;padding:14px;border-left:4px solid #3974bd}"
                + "table{border-collapse:collapse;width:100%;background:white;margin:16px 0}th,td{text-align:left;vertical-align:top;padding:10px 12px;border:1px solid #dbe3ee;overflow-wrap:anywhere}th{background:#eaf0f7}"
                + ".finding{background:white;border:1px solid #dbe3ee;border-radius:8px;padding:20px;margin:20px 0;break-inside:avoid}"
                + "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6fa;padding:14px;border:1px solid #dbe3ee;font:12px/1.5 ui-monospace,monospace}"
                + "@media print{body{background:white}main{max-width:none;padding:0}.finding{border-radius:0}pre{white-space:pre-wrap}thead{display:table-header-group}}")
            .append("</style></head><body><main><div class=\"eyebrow\">NIGHTVISION / MANUAL VALIDATION</div><h1>")
            .append(escape(text(options.title()))).append("</h1><table><tbody>");
        field(out, "Generated (UTC)", snapshot.generatedAt().toString());
        field(out, "Analyst", options.analyst().isBlank() ? "Not supplied" : options.analyst());
        field(out, "API origin", snapshot.origin()); field(out, "Loaded scan UUID", blank(snapshot.scanId()));
        field(out, "Scope", snapshot.scope());
        out.append("</tbody></table><p class=\"notice\">Saved local assessments and the last loaded NightVision state are shown separately. "
            + "Reports do not refresh findings or verify remediation. Common credential patterns are redacted; review remaining content before sharing.</p>");
        if (preview && limit < snapshot.rows().size()) out.append("<p><b>Preview shows the first ").append(limit)
            .append(" of ").append(snapshot.rows().size()).append(" findings. The saved file contains the full chosen scope.</b></p>");
        long reviewed = snapshot.rows().stream().filter(Row::reviewed).count();
        out.append("<h2>Summary</h2><p><b>").append(snapshot.rows().size()).append(" findings</b> &nbsp; / &nbsp; ")
            .append(reviewed).append(" reviewed &nbsp; / &nbsp; ").append(snapshot.rows().size() - reviewed).append(" unreviewed</p>");
        counts(out, "Local verdict", snapshot.rows().stream().map(Row::verdict).toList());
        counts(out, "Severity", snapshot.rows().stream().map(Row::severity).toList());
        for (int i = 0; i < limit; i++) {
            Row row = snapshot.rows().get(i);
            out.append("<section class=\"finding\"><h3>").append(i + 1).append(". ").append(escape(text(row.title()))).append("</h3><table><tbody>");
            field(out, "Severity", row.severity()); field(out, "Local verdict", row.verdict());
            field(out, "NightVision resolution (last loaded)", row.remoteResolution()); field(out, "Method / target", row.method() + " " + row.target());
            field(out, "Issue UUID", row.issueId()); field(out, "Scan UUID", blank(row.scanId()));
            field(out, "Local validation saved (UTC)", blank(row.updatedAt()));
            field(out, "Last remote sync receipt", blank(row.syncStatus()));
            if (!row.verifiedAt().isBlank()) field(out, "Remote sync verified (UTC)", row.verifiedAt());
            out.append("</tbody></table>");
            if (options.notes()) block(out, "Saved analyst notes", row.notes().isBlank() ? "No saved notes." : row.notes());
            if (options.scannerEvidence()) {
                block(out, "Scanner payload", row.payload()); block(out, "Scanner evidence", row.evidence()); block(out, "Scanner evidence details", row.evidenceDetails());
            }
            if (options.httpEvidence() && !row.captures().isEmpty()) {
                out.append("<h4>Original captured HTTP evidence</h4><p class=\"muted\">Captured by NightVision; not a Repeater retest. Request and response entries are independent captures.</p>");
                for (Capture capture : row.captures()) {
                    block(out, "Captured " + capture.direction() + " / " + capture.source(), capture.text().isEmpty() ? "No usable captured text. " + capture.note() : capture.text());
                    out.append("<p class=\"muted\">").append(escape(text(capture.note() + (capture.destination().isBlank() ? "" : " | Capture URL: " + capture.destination())))).append("</p>");
                }
            }
            out.append("</section>"); checkSize(out);
        }
        out.append("<footer class=\"muted\">NightVision Finding Validator 0.4.1. Unsaved notes, request edits, and Repeater results are excluded. "
            + "Individual fields are limited to 16,000 characters with a truncation marker. Print this HTML file from your browser to save a PDF.</footer></main></body></html>");
        return out.toString();
    }

    /** One quoted row per finding; metadata repeats so filtered spreadsheet rows retain provenance. */
    private static String csv(Snapshot snapshot) {
        StringBuilder out = new StringBuilder("\ufeff"); // UTF-8 BOM helps spreadsheet applications display Unicode.
        csvRow(out, List.of("Report title", "Analyst", "Generated UTC", "API origin", "Scope", "Issue UUID", "Scan UUID", "Finding", "Severity", "Method", "Target",
            "NightVision resolution (last loaded)", "Local verdict", "Local validation saved UTC", "Last remote sync receipt", "Remote sync verified UTC", "Saved analyst notes"));
        for (Row row : snapshot.rows()) {
            csvRow(out, List.of(snapshot.options().title(), snapshot.options().analyst(), snapshot.generatedAt().toString(), snapshot.origin(), snapshot.scope(),
                row.issueId(), row.scanId(), row.title(), row.severity(), row.method(), row.target(), row.remoteResolution(), row.verdict(),
                row.updatedAt(), row.syncStatus(), row.verifiedAt(), snapshot.options().notes() ? row.notes() : ""));
            checkSize(out);
        }
        return out.toString();
    }

    /** Redacts before truncation so cutting a long field cannot leave part of a recognized secret. */
    private static String text(String value) {
        String safe = ReportRedactor.redact(value).replace("\0", "");
        if (safe.length() <= MAX_FIELD) return safe;
        int end = Character.isHighSurrogate(safe.charAt(MAX_FIELD - 1)) ? MAX_FIELD - 1 : MAX_FIELD;
        return safe.substring(0, end) + "\n[Truncated after 16,000 characters]";
    }
    static String escape(String value) { return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
    private static String blank(String value) { return value.isBlank() ? "Not supplied" : value; }
    private static void field(StringBuilder out, String label, String value) { out.append("<tr><th>").append(escape(label)).append("</th><td>").append(escape(text(value)).replace("\n", "<br>")).append("</td></tr>"); }
    private static void block(StringBuilder out, String label, String value) { if (!value.isBlank()) out.append("<h4>").append(escape(text(label))).append("</h4><pre>").append(escape(text(value))).append("</pre>"); }
    private static void counts(StringBuilder out, String label, List<String> values) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String value : values) counts.merge(value.isBlank() ? "Unknown" : text(value), 1, Integer::sum);
        out.append("<table><thead><tr><th>").append(escape(label)).append("</th><th>Findings</th></tr></thead><tbody>");
        counts.forEach((key, count) -> out.append("<tr><td>").append(escape(key)).append("</td><td>").append(count).append("</td></tr>"));
        out.append("</tbody></table>");
    }
    private static void csvRow(StringBuilder out, List<String> cells) {
        for (int i = 0; i < cells.size(); i++) { if (i > 0) out.append(','); out.append(csvCell(cells.get(i))); }
        out.append("\r\n");
    }
    /** Quote delimiters/newlines and prefix risky formula starters so initial spreadsheet imports treat them as text. */
    static String csvCell(String value) {
        String cell = text(value);
        String leading = cell.replaceFirst("^[\\s\\p{Z}\\p{Cf}]*", "");
        if ((!leading.isEmpty() && "=+-@＝＋－＠".indexOf(leading.charAt(0)) >= 0)
            || (!cell.isEmpty() && "\t\r\n".indexOf(cell.charAt(0)) >= 0)) cell = "'" + cell;
        return "\"" + cell.replace("\"", "\"\"") + "\"";
    }
    private static void checkSize(StringBuilder out) {
        if (out.length() > MAX_BYTES) throw new IllegalArgumentException("Report exceeds 16 MiB. Reduce the scope or omit evidence.");
    }

    /** Writes via a temporary sibling, preserving an existing destination if staging fails. */
    static void write(Path destination, Document report, boolean replace) throws IOException {
        Path target = destination.toAbsolutePath();
        Path staged = Files.createTempFile(target.getParent(), ".nightvision-report-", ".tmp");
        try {
            Files.writeString(staged, report.content(), StandardCharsets.UTF_8);
            // Without overwrite approval, a newly appeared destination must cause failure rather than replacement.
            if (!replace) Files.move(staged, target);
            else try { Files.move(staged, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException e) { Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(staged); }
    }
}
