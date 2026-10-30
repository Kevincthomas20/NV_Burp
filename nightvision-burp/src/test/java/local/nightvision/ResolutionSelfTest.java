package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonObject;
import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.net.http.HttpRequest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static local.nightvision.SelfTest.*;

/** Verifies code 4 through the transport, real button, saved receipt, reload, and report workflow. */
final class ResolutionSelfTest {
    static void run() throws Exception { testApi(); testButton(); }

    private static void testApi() throws Exception {
        List<HttpRequest> calls = new ArrayList<>();
        NightVisionClient client = new NightVisionClient("https://api.example.test", "test-token", request -> {
            calls.add(request); return reply(ISSUE, 4);
        });
        JsonObject saved = client.markWontFix(ISSUE);
        check(Finding.s(saved, "resolution").equals("4") && new Finding(saved).resolutionDisplay().equals("Won't fix (4)"), "Won't-fix action returns a verified code 4 with its own display label");
        check(calls.size() == 2 && calls.get(0).method().equals("PUT") && calls.get(1).method().equals("GET"), "Won't-fix action makes exactly one update and one separate verification read");
        check(calls.stream().allMatch(r -> r.uri().getPath().equals("/api/v1/issues/" + ISSUE + "/")), "Won't-fix updates only the selected issue endpoint");
        check(body(calls.get(0)).equals("{\"resolution\":4}"), "Won't-fix payload contains only resolution 4, without analyst notes or other issue fields");
        check(calls.get(0).headers().firstValue("Authorization").orElseThrow().equals("Token test-token"), "Won't-fix update preserves API authentication");
        calls.clear();
        rejects(() -> client.markWontFix("../other"), "Invalid won't-fix issue IDs are rejected before transport");
        check(calls.isEmpty(), "Invalid IDs cause no won't-fix network request");
        for (int other : List.of(0, 1, 2)) {
            List<HttpRequest> mismatch = new ArrayList<>();
            NightVisionClient wrongResolution = new NightVisionClient("https://api.example.test", "test", request -> {
                mismatch.add(request); return reply(ISSUE, request.method().equals("PUT") ? 4 : other);
            });
            rejects(() -> wrongResolution.markWontFix(ISSUE), "Open, resolved, and false-positive read-backs cannot verify a won't-fix update");
            check(mismatch.size() == 2, "Mismatched won't-fix verification does not retry or fall back to another code");
        }
        NightVisionClient wrongIssue = new NightVisionClient("https://api.example.test", "test", request -> reply(SCAN, 4));
        rejects(() -> wrongIssue.markWontFix(ISSUE), "Correct code on the wrong issue cannot verify won't fix");
        List<HttpRequest> deniedCalls = new ArrayList<>();
        NightVisionClient denied = new NightVisionClient("https://api.example.test", "private-token", request -> {
            deniedCalls.add(request); return new NightVisionClient.Reply(403, "private-token response-secret");
        });
        try { denied.markWontFix(ISSUE); throw new AssertionError("Denied won't-fix write cannot succeed"); }
        catch (IllegalStateException e) { check(e.getMessage().contains("403") && !e.getMessage().contains("private-token") && !e.getMessage().contains("response-secret"), "Won't-fix permission errors expose only controlled status guidance"); }
        check(deniedCalls.size() == 1, "Denied won't-fix writes are never retried or followed by a success verification");
    }

    /** Holding GET open proves the UI cannot report success from PUT acceptance alone. */
    private static void testButton() throws Exception {
        Map<String, String> preferences = new HashMap<>();
        AtomicReference<Component> registered = new AtomicReference<>();
        NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) mock(MontoyaApi.class, preferences, registered));
        CountDownLatch verifying = new CountDownLatch(1), allowVerification = new CountDownLatch(1);
        List<HttpRequest> calls = new ArrayList<>();
        NightVisionClient client = new NightVisionClient("https://api.example.test", "test-token", request -> {
            calls.add(request);
            if (request.method().equals("GET")) {
                verifying.countDown();
                if (!allowVerification.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Test verification timed out");
            }
            return reply(ISSUE, 4);
        });
        Map<String, String> before = new HashMap<>();
        String note = "Won't fix: accepted risk for the synthetic test application.";
        SwingUtilities.invokeAndWait(() -> {
            invoke(extension, "demo");
            JButton button = button(registered.get(), "Mark won't fix in NightVision");
            check(button != null, "The extension renders a dedicated won't-fix button");
            button.doClick(0);
            check(status(extension).contains("Connect to NightVision") && preferences.isEmpty(), "Offline won't-fix clicks cannot update NightVision or create a verified local receipt");
            setField(extension, "client", client); setField(extension, "namespace", client.origin());
            ((JComboBox<?>) field(extension, "verdict")).setSelectedItem("Confirmed");
            ((JTextArea) field(extension, "notes")).setText("Original saved assessment"); invoke(extension, "saveValidation");
            before.putAll(preferences);
            ((JTextArea) field(extension, "notes")).setText(note); button.doClick(0);
        });
        try {
            check(verifying.await(5, TimeUnit.SECONDS), "The actual won't-fix button reaches separate read-back verification");
            SwingUtilities.invokeAndWait(() -> {
                check(preferences.equals(before) && ((JTable) field(extension, "table")).getValueAt(0, 6).equals("Confirmed"), "Won't-fix acceptance alone leaves saved assessment and receipt unchanged");
                check(!button(registered.get(), "Mark won't fix in NightVision").isEnabled() && !button(registered.get(), "Mark false positive in NightVision").isEnabled(), "Both remote update buttons are disabled during verification");
            });
        } finally { allowVerification.countDown(); }
        waitWorker(extension);
        check(calls.size() == 2 && body(calls.get(0)).equals("{\"resolution\":4}"), "The rendered button uses the code 4 transport path without extra writes");
        SwingUtilities.invokeAndWait(() -> {
            JTable table = (JTable) field(extension, "table");
            check(table.getValueAt(0, 5).equals("Won't fix (4)") && table.getValueAt(0, 6).equals("Won't fix"), "Verified won't fix updates both remote resolution and local validation columns");
            check(Objects.equals(((JComboBox<?>) field(extension, "verdict")).getSelectedItem(), "Won't fix") && ((JTextArea) field(extension, "notes")).getText().equals(note), "The local dropdown and saved analyst notes retain the won't-fix assessment");
            check(status(extension).contains("Won't fix and read-back verified"), "Successful won't-fix feedback names the verified classification");
            var snapshot = extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, true,
                new ValidationReport.Options("Won't-fix review", "Test analyst", true, false, false));
            check(snapshot.rows().size() == 1 && snapshot.rows().get(0).reviewed() && snapshot.rows().get(0).verdict().equals("Won't fix"), "Reviewed-only reports include the saved won't-fix assessment");
            check(snapshot.rows().get(0).remoteResolution().equals("Won't fix (4)") && snapshot.rows().get(0).notes().equals(note), "Reports retain the verified remote label and saved won't-fix notes");
            check(ValidationReport.render(snapshot, ValidationReport.Format.CSV).content().contains("Won't fix (4)")
                && ValidationReport.render(snapshot, ValidationReport.Format.HTML).content().contains("Won&#39;t fix (4)"), "HTML and CSV render the won't-fix classification correctly");
            check(preferences.values().stream().filter(v -> v.startsWith("{")).map(SelfTest::json)
                .anyMatch(v -> "Won't fix".equals(Finding.s(v, "status")) && "4".equals(Finding.s(Finding.object(v, "nightvision_sync"), "resolution"))), "The saved sync receipt contains resolution 4 independently of false-positive code 2");
        });
        // A new controller must recognize the saved label; it does not refresh remote state automatically.
        NightVisionExtension reloaded = new NightVisionExtension();
        reloaded.initialize((MontoyaApi) mock(MontoyaApi.class, preferences, new AtomicReference<Component>()));
        SwingUtilities.invokeAndWait(() -> {
            invoke(reloaded, "demo"); setField(reloaded, "namespace", client.origin()); invoke(reloaded, "showSelected");
            check(Objects.equals(((JComboBox<?>) field(reloaded, "verdict")).getSelectedItem(), "Won't fix")
                && ((JTextArea) field(reloaded, "notes")).getText().equals(note), "A fresh extension instance restores the saved won't-fix assessment and notes");
        });
        // A later failed verification must leave the current confirmed record intact.
        Map<String, String> confirmed = new HashMap<>(preferences);
        NightVisionClient mismatch = new NightVisionClient("https://api.example.test", "test-token", request -> reply(ISSUE, request.method().equals("PUT") ? 4 : 2));
        SwingUtilities.invokeAndWait(() -> {
            setField(extension, "client", mismatch);
            ((JTextArea) field(extension, "notes")).setText("Unverified replacement notes");
            button(registered.get(), "Mark won't fix in NightVision").doClick(0);
        });
        waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            check(status(extension).contains("could not be verified") && preferences.equals(confirmed), "A wrong code 2 read-back cannot overwrite saved won't-fix notes or claim a new verified receipt");
            check(((JTextArea) field(extension, "notes")).getText().equals("Unverified replacement notes"), "Failed won't-fix verification keeps unsaved analyst notes available");
            ((JTable) field(extension, "table")).clearSelection();
            button(registered.get(), "Mark won't fix in NightVision").doClick(0);
            check(status(extension).contains("Select a finding first"), "Won't-fix actions require an explicitly selected issue");
        });
        ((EvidenceController) field(extension, "evidence")).close();
        ((EvidenceController) field(reloaded, "evidence")).close();
    }

    private static NightVisionClient.Reply reply(String id, int resolution) {
        return new NightVisionClient.Reply(200, "{\"id\":\"" + id + "\",\"resolution\":" + resolution + "}");
    }
    private static String status(NightVisionExtension extension) { return ((JLabel) field(extension, "status")).getText(); }
    private static JButton button(Component component, String label) {
        if (component instanceof JButton button && button.getText().equals(label)) return button;
        if (component instanceof Container parent) for (Component child : parent.getComponents()) {
            JButton button = button(child, label); if (button != null) return button;
        }
        return null;
    }
}
