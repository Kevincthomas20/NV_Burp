package local.nightvision;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.*;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.*;
import com.google.gson.*;
import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.BiFunction;
import static local.nightvision.SelfTest.*;

/** Exercises byte fidelity, real evidence files, actual registered menu actions, reloads, and report provenance. */
final class EvidenceSelfTest {
    private static final byte[] REQUEST = "GET /test?token=query-secret HTTP/1.1\r\nHost: app.example.invalid\r\nAuthorization: Bearer capture-secret\r\n\r\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE = "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-secret\r\n\r\nRetest café result".getBytes(StandardCharsets.UTF_8);
    private static final EvidenceStore.Target TARGET = new EvidenceStore.Target("offline-demo", ISSUE, SCAN, "Synthetic finding", "https://app.example.invalid/test");
    private static final EvidenceStore.Labels LABELS = new EvidenceStore.Labels("Explicit retest", "Test role: standard user", "2026-10-26T16:00:00Z", "Evidence attachment notes");

    /** The build also starts this compiled workflow in a separate JVM containing only the early API. */
    public static void main(String[] args) throws Exception {
        check(MessageEditorHttpRequestResponse.class.getMethod("getRequestResponse") != null, "Legacy test runtime exposes the actual pre-1.0 editor accessor");
        check(HttpRequestResponse.class.getMethod("httpRequest") != null && HttpRequestResponse.class.getMethod("httpResponse") != null, "Legacy runtime exposes the pre-1.0 exchange getter names");
        check(HttpRequest.class.getMethod("asBytes") != null && HttpResponse.class.getMethod("asBytes") != null, "Legacy runtime exposes the pre-1.0 raw-message byte accessor");
        try { MessageEditorHttpRequestResponse.class.getMethod("requestResponse"); throw new AssertionError("Do not mix the current API into the legacy test classpath"); }
        catch (NoSuchMethodException expected) { check(true, "Legacy workflow runs without a current editor accessor on its classpath"); }
        run(); System.out.println("PASS: " + checks + " pre-1.0 evidence selection, capture, save, reload, and report checks.");
    }

    static void run() throws Exception {
        testSelection();
        Path folder = Files.createTempDirectory("nightvision-evidence-tests-");
        try { testStore(folder.resolve("store")); testUi(folder.resolve("ui")); }
        finally { try (var files = Files.walk(folder)) { for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path); } }
    }

    /** Selection must use one explicit editor/table exchange and allocate bytes only within the limits. */
    private static void testSelection() throws Exception {
        HttpRequestResponse message = exchange(REQUEST.clone(), RESPONSE.clone(), false);
        check(EvidenceCapture.selected(event(List.of(message), null)).orElseThrow() == message, "Select exactly one table request/response for evidence");
        check(EvidenceCapture.selected(event(List.of(message, message), null)).isEmpty(), "Do not guess among multiple selected exchanges");
        HttpRequestResponse other = exchange(REQUEST.clone(), RESPONSE.clone(), false);
        check(EvidenceCapture.selected(event(List.of(message), other)).orElseThrow() == other, "Prefer the specific message editor over an unrelated table selection");
        byte[] source = REQUEST.clone(); var captured = EvidenceCapture.snapshot(exchange(source, RESPONSE.clone(), false), "REPEATER"); source[0] = 'X';
        byte[] returned = captured.request(); returned[0] = 'Y';
        check(Arrays.equals(captured.request(), REQUEST), "Snapshot bytes cannot be changed by the source editor or a returned byte array");
        check(captured.status() == 200 && captured.host().equals("app.example.invalid") && captured.port() == 443 && captured.tls(), "Capture actual response and HTTP service metadata");
        rejects(() -> EvidenceCapture.snapshot(exchange(REQUEST, null, false), "REPEATER"), "A response is required before evidence can be attached");
        rejects(() -> EvidenceCapture.snapshot(exchange(REQUEST, RESPONSE, true), "REPEATER"), "Reject oversized messages before requesting a byte-array copy");
        rejects(() -> EvidenceCapture.snapshot(exchange(REQUEST, new byte[EvidenceStore.MAX_RESPONSE + 1], false), "REPEATER"), "Bound the response size independently of the request size");
        rejects(() -> new EvidenceStore.Labels("Retest", "", "yesterday", ""), "Do not invent or accept an ambiguous actual test timestamp");
        rejects(() -> new EvidenceStore.Labels("Retest", "", "", "x".repeat(4001)), "Bound attachment note size");
        rejects(() -> EvidenceController.parseFolder("  "), "An empty evidence path must not silently become Burp's working directory");
    }

    /** The filesystem tests verify atomic, bounded records and refuse tampered/cross-finding content. */
    private static void testStore(Path folder) throws Exception {
        EvidenceStore store = new EvidenceStore(folder);
        check(store.list(TARGET).isEmpty() && !Files.exists(folder), "Read-only selection does not create an evidence folder");
        var captured = EvidenceCapture.snapshot(exchange(REQUEST.clone(), RESPONSE.clone(), false), "REPEATER");
        var saved = store.save(TARGET, captured, LABELS);
        var entry = new EvidenceStore(folder).read(TARGET, saved.id());
        check(Arrays.equals(entry.request(), REQUEST) && Arrays.equals(entry.response(), RESPONSE), "Save and reload the exact request/response bytes supplied by Burp");
        check(saved.requestSha256().equals(EvidenceStore.sha(REQUEST)) && saved.responseSha256().equals(EvidenceStore.sha(RESPONSE)), "Stored fingerprints cover complete raw messages");
        check(!saved.attachedAt().isBlank() && saved.labels().testedAt().equals("2026-10-26T16:00:00Z"), "Keep automatic attachment time separate from the analyst-supplied test time");
        var noTime = store.save(TARGET, captured, new EvidenceStore.Labels("No asserted test time", "", "", ""));
        check(noTime.labels().testedAt().isEmpty(), "Attaching a message does not fabricate its original test timestamp");
        byte[] binary = concat("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".getBytes(StandardCharsets.UTF_8), new byte[]{0, (byte) 255, 1, 2});
        var binarySaved = store.save(TARGET, EvidenceCapture.snapshot(exchange(REQUEST.clone(), binary, false), "PROXY"), new EvidenceStore.Labels("Binary retest", "", "", ""));
        check(Arrays.equals(store.read(TARGET, binarySaved.id()).response(), binary), "Preserve binary bodies rather than converting them to lossy text");
        check(EvidenceStore.messageText(binary).contains("Binary or non-UTF-8 body omitted") && EvidenceStore.messageText(binary).startsWith("HTTP/1.1 200"), "Binary previews retain headers and explain omitted body text");
        Path record = record(folder, TARGET, saved.id()), raw = record.resolve("request.bin");
        if (Files.getFileStore(record).supportsFileAttributeView("posix")) check(Files.getPosixFilePermissions(raw).equals(PosixFilePermissions.fromString("rw-------")), "Raw evidence files use owner-only POSIX permissions when supported");
        byte[] changed = REQUEST.clone(); changed[0] = 'X'; Files.write(raw, changed);
        rejects(() -> store.read(TARGET, saved.id()), "Reject a same-length message changed after capture");
        Files.write(raw, REQUEST);
        byte[] metadata = Files.readAllBytes(record.resolve("metadata.json"));
        Files.writeString(record.resolve("metadata.json"), "{\"schema\":1,\"secret\":\"synthetic-metadata-secret\"}");
        try { store.read(TARGET, saved.id()); throw new AssertionError("Incomplete metadata must not load"); }
        catch (IllegalStateException e) { check(!e.getMessage().contains("synthetic-metadata-secret"), "Malformed evidence errors do not echo metadata contents"); }
        Files.write(record.resolve("metadata.json"), metadata);
        EvidenceStore.Target other = new EvidenceStore.Target("https://other.example.invalid", ISSUE, SCAN, "Other origin", "https://other.example.invalid");
        Path copied = record(folder, other, saved.id()); Files.createDirectories(copied);
        for (String file : List.of("metadata.json", "request.bin", "response.bin")) Files.copy(record.resolve(file), copied.resolve(file));
        rejects(() -> store.read(other, saved.id()), "Refuse metadata transplanted into another origin's evidence folder");
        rejects(() -> store.read(TARGET, "../outside"), "An evidence identifier cannot traverse outside its finding directory");
        Path outsider = folder.resolve("outside.bin"); Files.write(outsider, REQUEST);
        try {
            Files.delete(raw); Files.createSymbolicLink(raw, outsider);
            rejects(() -> store.read(TARGET, saved.id()), "Do not follow a substituted raw-message symlink");
            check(Arrays.equals(Files.readAllBytes(outsider), REQUEST), "Evidence verification never mutates a substituted external file");
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException e) { /* Symlink creation may be restricted on Windows. */ }
        finally { Files.deleteIfExists(raw); Files.write(raw, REQUEST); }
        try (FileChannel channel = FileChannel.open(record.getParent().resolve(".lock"), StandardOpenOption.WRITE); FileLock lock = channel.lock()) {
            rejects(() -> store.save(TARGET, captured, LABELS), "A busy evidence store cannot accept a concurrent partial write");
        }
        int before = store.list(TARGET).size(); Files.writeString(record.resolve("unrelated.txt"), "leave this file alone");
        rejects(() -> store.remove(TARGET, saved.id()), "Removal refuses a record containing unexpected files");
        check(Files.readString(record.resolve("unrelated.txt")).equals("leave this file alone"), "Removal does not recursively delete unexpected user files");
        Files.delete(record.resolve("unrelated.txt"));
        check(store.remove(TARGET, saved.id()) && store.list(TARGET).size() == before - 1, "Explicit removal deletes only the chosen local attachment");
        check(store.read(TARGET, binarySaved.id()).metadata().id().equals(binarySaved.id()), "Removing one attachment preserves the other attachments");
        while (store.list(TARGET).size() < EvidenceStore.MAX_RECORDS) store.save(TARGET, captured, new EvidenceStore.Labels("Bounded attachment", "", "", ""));
        rejects(() -> store.save(TARGET, captured, LABELS), "Apply the per-finding attachment limit without dropping existing evidence");
        check(store.list(TARGET).size() == EvidenceStore.MAX_RECORDS, "A rejected extra save leaves all 50 existing attachments readable");
    }

    /** Drive the registered menu, then a fresh controller and written report, using an explicit target choice. */
    private static void testUi(Path folder) throws Exception {
        Map<String, String> preferences = new HashMap<>(); AtomicReference<ContextMenuItemsProvider> provider = new AtomicReference<>();
        NightVisionExtension extension = new NightVisionExtension(); extension.initialize((MontoyaApi) host(MontoyaApi.class, preferences, provider));
        List<String> notices = new ArrayList<>(); AtomicInteger prompts = new AtomicInteger();
        AtomicReference<EvidenceStore.Target> chosen = new AtomicReference<>();
        AtomicReference<String> savedAnnotation = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            invoke(extension, "demo");
            try {
                JsonObject first = json("{\"id\":\"" + ISSUE + "\",\"scan_id\":\"" + SCAN + "\",\"kind\":{\"name\":\"First finding\"}}");
                JsonObject second = json("{\"id\":\"" + SCAN + "\",\"scan_id\":\"" + SCAN + "\",\"kind\":{\"name\":\"Second finding\"}}");
                Method method = NightVisionExtension.class.getDeclaredMethod("setFindings", List.class); method.setAccessible(true); method.invoke(extension, List.of(first, second));
            } catch (Exception e) { throw new RuntimeException(e); }
            JTable table = (JTable) field(extension, "table"); table.setRowSelectionInterval(0, 0);
            ((JComboBox<?>) field(extension, "verdict")).setSelectedItem("Needs review"); ((JTextArea) field(extension, "notes")).setText("Saved analyst assessment"); invoke(extension, "saveValidation");
            savedAnnotation.set(preferences.values().iterator().next());
            ((JTextArea) field(extension, "notes")).setText("Unsaved editor note stays visible");
            EvidenceController controller = (EvidenceController) field(extension, "evidence"); controller.notice = notices::add;
            ((JTextField) field(controller, "folder")).setText(folder.toString());
            check(!menu(provider.get(), exchange(REQUEST, null, false)).isEnabled(), "The context menu explains that an exchange needs a response before capture");
            controller.prompt = (captured, targets, selected, root) -> { prompts.incrementAndGet(); return null; };
            menu(provider.get(), exchange(REQUEST.clone(), RESPONSE.clone(), false)).doClick();
            check(!Files.exists(folder) && preferences.size() == 1, "Canceling attachment creates no files or preference settings");
            controller.prompt = (captured, targets, selected, root) -> {
                prompts.incrementAndGet(); chosen.set(targets.get(1));
                return new EvidenceController.Choice(targets.get(1), LABELS, folder);
            };
            menu(provider.get(), exchange(REQUEST.clone(), RESPONSE.clone(), false)).doClick();
        });
        EvidenceController controller = (EvidenceController) field(extension, "evidence"); waitEvidence(controller);
        EvidenceStore store = new EvidenceStore(folder);
        check(store.list(chosen.get()).size() == 1 && store.list(TARGET).isEmpty(), "The chosen finding owns the capture even when another finding is selected in the table");
        SwingUtilities.invokeAndWait(() -> {
            check(((JTextArea) field(extension, "notes")).getText().equals("Unsaved editor note stays visible"), "Attaching evidence does not overwrite unsaved analyst notes");
            check(preferences.values().contains(savedAnnotation.get()), "Attaching evidence does not alter the saved verdict, notes, or remote-sync metadata");
            check(notices.stream().anyMatch(message -> message.contains("saved locally and SHA-256 verified")), "The context-menu action confirms only a verified local evidence save");
            check(((JTextField) field(controller, "folder")).getText().equals(preferences.get("nightvision.evidence.folder")), "Remember the evidence folder path without copying raw messages into preferences");
            controller.prompt = (capture, targets, selected, root) -> { throw new AssertionError("Busy actions must not open an attachment dialog"); };
            setField(extension, "worker", new SwingWorker<Void, Void>() { protected Void doInBackground() { return null; } });
            menu(provider.get(), exchange(REQUEST.clone(), RESPONSE.clone(), false)).doClick(); setField(extension, "worker", null);
            check(prompts.get() == 2, "Busy API work prevents a competing attachment action");
        });
        // Re-initialize with the same preference folder and reconstruct the loaded finding.
        controller.close();
        NightVisionExtension reloaded = new NightVisionExtension(); reloaded.initialize((MontoyaApi) host(MontoyaApi.class, preferences, new AtomicReference<>()));
        AtomicReference<ValidationReport.Snapshot> snapshot = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            invoke(reloaded, "demo");
            try {
                Method method = NightVisionExtension.class.getDeclaredMethod("setFindings", List.class); method.setAccessible(true);
                method.invoke(reloaded, List.of(json("{\"id\":\"" + SCAN + "\",\"scan_id\":\"" + SCAN + "\",\"kind\":{\"name\":\"Second finding\"}}")));
            } catch (Exception e) { throw new RuntimeException(e); }
            ((JTable) field(reloaded, "table")).setRowSelectionInterval(0, 0);
            snapshot.set(reloaded.reportSnapshot(NightVisionExtension.ReportScope.ALL, false, new ValidationReport.Options("Retest report", "Analyst", true, false, false, true)));
        });
        EvidenceController newController = (EvidenceController) field(reloaded, "evidence"); waitEvidence(newController);
        SwingUtilities.invokeAndWait(() -> check(((JComboBox<?>) field(newController, "entries")).getItemCount() == 1 && ((JTextArea) field(newController, "response")).getText().contains("Retest café result"), "A fresh extension instance lists and verifies its saved evidence files"));
        var enriched = ValidationReport.attachRetests(snapshot.get(), store);
        var report = ValidationReport.render(enriched, ValidationReport.Format.HTML);
        check(report.content().contains("Saved manual retest evidence") && report.content().contains(LABELS.label()) && report.content().contains(LABELS.context()), "Reports include explicitly attached retest evidence with its label and context");
        check(report.content().contains("Attached (UTC)") && report.content().contains("Tested at (analyst supplied)") && report.content().contains("Request bytes / SHA-256"), "Reports retain provenance, separate timestamps, and complete-message fingerprints");
        var row = snapshot.get().rows().get(0); String laterScan = "33333333-3333-4333-8333-333333333333";
        var laterRow = new ValidationReport.Row(row.issueId(), laterScan, row.title(), row.severity(), row.method(), row.target(), row.remoteResolution(), row.verdict(), row.updatedAt(), row.notes(), row.syncStatus(), row.verifiedAt(), row.payload(), row.evidence(), row.evidenceDetails(), row.captures());
        var later = new ValidationReport.Snapshot(snapshot.get().options(), snapshot.get().origin(), laterScan, snapshot.get().scope(), Instant.now(), List.of(laterRow));
        String laterHtml = ValidationReport.render(ValidationReport.attachRetests(later, store), ValidationReport.Format.HTML).content();
        check(laterHtml.contains(laterScan) && laterHtml.contains("Finding scan UUID at attachment</th><td>" + SCAN), "An old attachment keeps its own scan provenance when the issue is loaded from a later scan");
        check(!report.content().contains("capture-secret") && !report.content().contains("response-secret") && !report.content().contains("query-secret"), "Redact recognized credentials from saved retest evidence in reports");
        check(enriched.rows().get(0).verdict().equals("Not reviewed") && enriched.rows().get(0).retests().size() == 1, "Evidence attachment does not infer or change a vulnerability verdict");
        Path html = folder.resolve("retest-report.html"); ValidationReport.write(html, report, false);
        check(Files.readString(html).contains("Retest café result"), "Written HTML contains the saved retest response, not just an in-memory preview");
        var stored = store.list(chosen.get()).get(0);
        Path rawResponse = record(folder, chosen.get(), stored.id()).resolve("response.bin");
        byte[] tampered = RESPONSE.clone(); tampered[tampered.length - 1] ^= 1; Files.write(rawResponse, tampered);
        rejects(() -> ValidationReport.attachRetests(snapshot.get(), store), "Report preparation rejects changed stored evidence rather than silently exporting it");
        Files.write(rawResponse, RESPONSE);
        var csv = ValidationReport.render(enriched, ValidationReport.Format.CSV);
        check(!csv.content().contains("Retest café result") && !csv.previewHtml().contains(LABELS.label()), "CSV and its preview continue to omit HTTP evidence");
        SwingUtilities.invokeAndWait(() -> {
            newController.selectionChanged();
            ((JTextField) field(newController, "folder")).setText(folder.resolve("another-folder").toString());
            check(((JComboBox<?>) field(newController, "entries")).getItemCount() == 0 && ((JTextArea) field(newController, "response")).getText().isEmpty(), "Editing the folder immediately clears stale displayed evidence");
        });
        Thread.sleep(100); SwingUtilities.invokeAndWait(() -> {
            check(((JComboBox<?>) field(newController, "entries")).getItemCount() == 0 && ((JTextArea) field(newController, "response")).getText().isEmpty(), "A late load callback cannot restore evidence from the previous folder");
            newController.close();
            check(newController.provideMenuItems(event(List.of(exchange(REQUEST, RESPONSE, false)), null)).isEmpty(), "An unloaded evidence controller offers no new capture action");
        });
    }

    /** Drive the editor path used in Repeater; separate selection tests cover table-row contexts. */
    private static JMenuItem menu(ContextMenuItemsProvider provider, HttpRequestResponse exchange) { return (JMenuItem) provider.provideMenuItems(event(List.of(), exchange)).get(0); }
    private static Path record(Path root, EvidenceStore.Target target, String id) { return root.resolve(EvidenceStore.sha((target.origin() + "\n" + target.issueId()).getBytes(StandardCharsets.UTF_8))).resolve(id); }
    private static byte[] concat(byte[] first, byte[] second) { byte[] out = Arrays.copyOf(first, first.length + second.length); System.arraycopy(second, 0, out, first.length, second.length); return out; }
    private static void waitEvidence(EvidenceController controller) throws Exception {
        for (int i = 0; i < 300; i++) {
            AtomicBoolean finished = new AtomicBoolean();
            SwingUtilities.invokeAndWait(() -> finished.set(field(controller, "saveWorker") == null && field(controller, "loadWorker") == null));
            if (finished.get()) return; Thread.sleep(20);
        }
        throw new AssertionError("Evidence workers did not finish");
    }

    /** Mock only Montoya's object interfaces; actual capture storage and reports use real code/files. */
    private static HttpRequestResponse exchange(byte[] request, byte[] response, boolean oversized) {
        ByteArray req = proxy(ByteArray.class, (method, args) -> switch (method.getName()) {
            case "length" -> oversized ? EvidenceStore.MAX_REQUEST + 1 : request.length;
            case "getBytes" -> { if (oversized) throw new AssertionError("Oversized bytes must not be copied"); yield request; }
            default -> null;
        });
        ByteArray res = proxy(ByteArray.class, (method, args) -> method.getName().equals("length") ? (response == null ? 0 : response.length) : method.getName().equals("getBytes") ? response : null);
        HttpService service = proxy(HttpService.class, (method, args) -> switch (method.getName()) { case "host" -> "app.example.invalid"; case "port" -> 443; case "secure" -> true; default -> null; });
        HttpRequest reqMessage = proxy(HttpRequest.class, (method, args) -> switch (method.getName()) {
            case "toByteArray", "asBytes" -> req; case "url" -> "https://app.example.invalid/test?token=query-secret"; case "httpService" -> service; default -> null;
        });
        HttpResponse resMessage = proxy(HttpResponse.class, (method, args) -> switch (method.getName()) { case "toByteArray", "asBytes" -> res; case "statusCode" -> (short) 200; default -> null; });
        return proxy(HttpRequestResponse.class, (method, args) -> switch (method.getName()) {
            case "hasResponse" -> response != null; case "request", "httpRequest" -> reqMessage; case "response", "httpResponse" -> response == null ? null : resMessage; case "httpService" -> service;
            case "url", "statusCode" -> throw new AssertionError("Use the current message APIs rather than deprecated exchange accessors"); default -> null;
        });
    }
    private static ContextMenuEvent event(List<HttpRequestResponse> rows, HttpRequestResponse editor) {
        return proxy(ContextMenuEvent.class, (method, args) -> switch (method.getName()) {
            case "messageEditorRequestResponse" -> editor == null ? Optional.empty() : Optional.of(proxy(MessageEditorHttpRequestResponse.class, (m, a) -> m.getName().equals("requestResponse") || m.getName().equals("getRequestResponse") ? editor : null));
            case "selectedRequestResponses" -> rows; case "toolType" -> ToolType.REPEATER; default -> null;
        });
    }
    private static <T> T proxy(Class<T> type, BiFunction<Method, Object[], Object> body) { return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> body.apply(method, args))); }
    private static Object host(Class<?> type, Map<String, String> preferences, AtomicReference<ContextMenuItemsProvider> provider) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> {
            if (method.getName().equals("sendRequest") || method.getName().equals("sendToRepeater")) throw new AssertionError("Evidence capture must not send or replay any request");
            if (method.getName().equals("registerContextMenuItemsProvider")) { provider.set((ContextMenuItemsProvider) args[0]); return null; }
            if (method.getName().equals("getString")) return preferences.get((String) args[0]);
            if (method.getName().equals("setString")) { preferences.put((String) args[0], (String) args[1]); return null; }
            if (method.getReturnType().isInterface()) return host(method.getReturnType(), preferences, provider);
            return null;
        });
    }
}
