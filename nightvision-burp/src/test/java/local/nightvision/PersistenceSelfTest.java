package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.prefs.Preferences;
import static local.nightvision.SelfTest.*;

/** Uses a disposable real Java preference node to exercise constraints absent from a map mock. */
final class PersistenceSelfTest {
    private static final String NOTES = "Saved review: café and output context.\nA second line of analyst notes.";
    private static final ValidationReport.Options OPTIONS = new ValidationReport.Options("Persistence regression", "Synthetic analyst", true, false, false);
    private enum Mode { NORMAL, DROP_WRITE, THROW }

    /** Reproduces the old failure and checks save, reload, reports, failure messages, and compatibility. */
    static void run() throws Exception {
        Preferences store = Preferences.userRoot().node("nightvision-validation-test-" + UUID.randomUUID());
        AtomicReference<Mode> mode = new AtomicReference<>(Mode.NORMAL);
        try {
            String legacyKey = legacyKey("offline-demo", ISSUE);
            check(legacyKey.length() == 87 && legacyKey.length() > Preferences.MAX_KEY_LENGTH, "Reproduce the previous validation key exceeding Java's real preference limit");
            try { store.put(legacyKey, "synthetic-value"); throw new AssertionError("The previous key must fail in the real Java preference store"); }
            catch (IllegalArgumentException e) { check(true, "Real Java preferences reject the old oversized save key"); }

            NightVisionExtension extension = extension(store, mode);
            AtomicReference<ValidationReport.Snapshot> report = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                invoke(extension, "demo"); edit(extension, "Confirmed", NOTES); invoke(extension, "saveValidation");
                check(status(extension).contains("saved and read back"), "A successful save is acknowledged only after preference read-back");
                check(((JTable) field(extension, "table")).getModel().getValueAt(0, 6).equals("Confirmed"), "Successful persistence updates the displayed local verdict");
                edit(extension, "Not reviewed", "unsaved replacement"); invoke(extension, "showSelected");
                check(notes(extension).equals(NOTES) && verdict(extension).equals("Confirmed"), "Selection refresh restores the actually saved verdict and multiline notes");
                report.set(extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, true, OPTIONS));
            });
            store.flush();
            String[] keys = store.keys();
            check(keys.length == 1 && keys[0].length() == 57 && keys[0].length() <= Preferences.MAX_KEY_LENGTH, "Store the complete validation under a supported 57-character preference key");
            check(Base64.getUrlDecoder().decode(keys[0].substring("nv.validation.".length())).length == 32, "Compact keys retain the full SHA-256 digest instead of truncating identity");
            JsonObject persisted = json(store.get(keys[0], "{}"));
            check(Finding.s(persisted, "notes").equals(NOTES) && Finding.s(persisted, "status").equals("Confirmed") && !Finding.s(persisted, "updated_at").isBlank(), "Read actual saved status, notes, and timestamp from the Java store");
            check(report.get().rows().size() == 1 && report.get().rows().get(0).notes().equals(NOTES), "Report snapshot includes the record persisted by the actual Save action");
            testReportFiles(report.get());

            // A new controller uses the same backing node, with no shared annotation cache or editor state.
            NightVisionExtension reloaded = extension(store, mode);
            SwingUtilities.invokeAndWait(() -> {
                invoke(extension, "disconnect"); invoke(reloaded, "demo");
                check(notes(reloaded).equals(NOTES) && verdict(reloaded).equals("Confirmed"), "A fresh extension instance reloads saved validation from the real preference store");
                check(reloaded.reportSnapshot(NightVisionExtension.ReportScope.SELECTED, true, OPTIONS).rows().get(0).notes().equals(NOTES), "Reloaded saved validation transfers into the report without being re-entered");
                setField(reloaded, "namespace", "https://other.example.invalid"); invoke(reloaded, "showSelected");
                check(notes(reloaded).isEmpty() && verdict(reloaded).equals("Not reviewed"), "Compact keys keep the same issue ID isolated across API origins");
                setField(reloaded, "namespace", "offline-demo"); invoke(reloaded, "showSelected");
                check(notes(reloaded).equals(NOTES), "Returning to the original namespace retrieves its saved notes");
            });
            testWriteFailures(reloaded, mode);
            mode.set(Mode.NORMAL);
            SwingUtilities.invokeAndWait(() -> {
                JsonObject issue = json("{\"id\":\"" + ISSUE + "\",\"resolution\":1}");
                try {
                    Method method = NightVisionExtension.class.getDeclaredMethod("recordRemoteUpdate", String.class, JsonObject.class, String.class);
                    method.setAccessible(true); method.invoke(reloaded, ISSUE, issue, "Verified remote receipt notes");
                } catch (Exception e) { throw new RuntimeException(e); }
                ValidationReport.Row row = reloaded.reportSnapshot(NightVisionExtension.ReportScope.SELECTED, true, OPTIONS).rows().get(0);
                check(row.verdict().equals("False positive") && row.notes().equals("Verified remote receipt notes") && row.syncStatus().equals("verified"), "Verified remote updates use the same compatible checked save path and appear in reports");
            });
            check(store.keys().length == 1, "Manual and remote-sync validation share one preference record rather than duplicate keys");
            testLegacyCompatibility();
        } finally { store.removeNode(); Preferences.userRoot().flush(); }
    }

    /** Checks the actual written HTML/CSV, not just an in-memory row or the status message. */
    private static void testReportFiles(ValidationReport.Snapshot snapshot) throws Exception {
        Path folder = Files.createTempDirectory("nightvision-persisted-report-");
        try {
            for (ValidationReport.Format format : ValidationReport.Format.values()) {
                ValidationReport.Document report = ValidationReport.render(snapshot, format);
                Path path = folder.resolve("saved-validation." + format.extension);
                ValidationReport.write(path, report, false);
                String contents = Files.readString(path);
                check(contents.contains("Confirmed") && contents.contains(NOTES) && !contents.contains("unsaved replacement"), "Written " + format + " contains the persisted verdict and complete saved notes");
            }
        } finally {
            try (var files = Files.walk(folder)) { for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path); }
        }
    }

    /** A dropped or throwing preference write must retain editor contents and the previous saved record. */
    private static void testWriteFailures(NightVisionExtension extension, AtomicReference<Mode> mode) throws Exception {
        for (Mode failure : List.of(Mode.DROP_WRITE, Mode.THROW)) {
            mode.set(failure);
            SwingUtilities.invokeAndWait(() -> {
                edit(extension, "Retest passed", "new unsaved notes"); invoke(extension, "saveValidation");
                check(status(extension).contains("not confirmed") && !status(extension).contains("provider-secret"), "Failed preference writes cannot claim success or echo provider exception text");
                check(notes(extension).equals("new unsaved notes") && verdict(extension).equals("Retest passed"), "Failed save retains the user's current notes and selected verdict in the editor");
                ValidationReport.Row row = extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, true, OPTIONS).rows().get(0);
                check(row.notes().equals(NOTES) && row.verdict().equals("Confirmed"), "Reports continue to use the previous confirmed saved record after a failed new save");
            });
        }
    }

    /** Reads records accepted by older lenient hosts, then prefers a new compact-key save. */
    private static void testLegacyCompatibility() throws Exception {
        Map<String, String> saved = new HashMap<>();
        String oldKey = legacyKey("offline-demo", ISSUE);
        saved.put(oldKey, "{\"status\":\"Needs review\",\"notes\":\"legacy saved note\"}");
        NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) mock(MontoyaApi.class, saved, new AtomicReference<Component>()));
        SwingUtilities.invokeAndWait(() -> {
            invoke(extension, "demo");
            check(notes(extension).equals("legacy saved note") && verdict(extension).equals("Needs review"), "Existing records from lenient older hosts remain readable after the key fix");
            edit(extension, "Confirmed", "updated compact-key note"); invoke(extension, "saveValidation");
            check(saved.containsKey(oldKey) && saved.size() == 2, "A new save retains the legacy record while writing a compatible current record");
            invoke(extension, "showSelected");
            ValidationReport.Row row = extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, true, OPTIONS).rows().get(0);
            check(row.notes().equals("updated compact-key note") && row.verdict().equals("Confirmed"), "Current saved values take precedence over stale legacy records in the UI and report");
        });
    }

    private static String legacyKey(String origin, String id) throws Exception {
        return "nightvision.validation." + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((origin + "\n" + id).getBytes(StandardCharsets.UTF_8)));
    }
    private static void edit(NightVisionExtension extension, String verdict, String notes) {
        ((JComboBox<?>) field(extension, "verdict")).setSelectedItem(verdict);
        ((JTextArea) field(extension, "notes")).setText(notes);
    }
    private static String notes(NightVisionExtension extension) { return ((JTextArea) field(extension, "notes")).getText(); }
    private static String verdict(NightVisionExtension extension) { return Objects.toString(((JComboBox<?>) field(extension, "verdict")).getSelectedItem()); }
    private static String status(NightVisionExtension extension) { return ((JLabel) field(extension, "status")).getText(); }
    private static NightVisionExtension extension(Preferences store, AtomicReference<Mode> mode) {
        NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) host(MontoyaApi.class, store, mode));
        return extension;
    }

    /** Montoya test host delegates preference calls to a real Java store, including its key/value limits. */
    private static Object host(Class<?> type, Preferences store, AtomicReference<Mode> mode) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            if (method.getName().equals("getString")) return store.get((String) args[0], null);
            if (method.getName().equals("setString")) {
                if (mode.get() == Mode.THROW) throw new IllegalStateException("provider-secret");
                if (mode.get() != Mode.DROP_WRITE) { store.put((String) args[0], (String) args[1]); store.flush(); }
                return null;
            }
            if (method.getReturnType().isInterface()) return host(method.getReturnType(), store, mode);
            return null;
        });
    }
}
