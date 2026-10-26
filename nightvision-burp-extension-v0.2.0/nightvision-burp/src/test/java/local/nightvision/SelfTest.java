package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.*;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.*;

/** Offline regression checks with fake API transport and a mock Montoya host. */
public class SelfTest {
    static int checks;
    static final String SCAN = "22222222-2222-4222-8222-222222222222";
    static final String ISSUE = "11111111-1111-4111-8111-111111111111";
    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
    static void rejects(Throwing action, String reason) throws Exception {
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException e) { checks++; return; }
        throw new AssertionError(reason);
    }
    interface Throwing { void run() throws Exception; }
    static JsonObject json(String text) { return JsonParser.parseString(text).getAsJsonObject(); }
    public static void main(String[] args) throws Exception {
        List<HttpRequest> calls = new ArrayList<>();
        NightVisionClient c = new NightVisionClient("https://api.example.test/", "Token test-token", req -> {
            calls.add(req);
            return new NightVisionClient.Reply(200, calls.size() == 1
                ? "{\"results\":[{\"id\":\"a\"}],\"next\":\"?page=2&scan=" + SCAN + "\"}"
                : "{\"results\":[{\"id\":\"b\"}],\"next\":null}");
        });
        check(c.issues(SCAN).size() == 2, "Follow relative pagination");
        check(calls.size() == 2 && calls.get(0).method().equals("GET"), "Read-only requests");
        check(calls.get(0).uri().getPath().equals("/api/v1/issues/") && calls.get(0).uri().getQuery().contains("scan=" + SCAN), "Documented endpoint and scan filter");
        check(calls.get(1).headers().firstValue("Authorization").orElseThrow().equals("Token test-token"), "Token prefix normalized");
        calls.clear();
        NightVisionClient badNext = new NightVisionClient("https://api.example.test", "test", req -> {
            calls.add(req); return new NightVisionClient.Reply(200, "{\"results\":[],\"next\":\"https://evil.example/api/v1/issues/\"}");
        });
        rejects(() -> badNext.issues(SCAN), "Cross-origin pagination must fail");
        check(calls.size() == 1, "Never transmit credentials to pagination destination");
        for (String next : List.of("http://api.example.test/api/v1/issues/", "https://api.example.test:444/api/v1/issues/", "https://api.example.test/api/v1/scans/", "https://user@api.example.test/api/v1/issues/"))
            rejects(() -> c.validatePage(URI.create(next), "/api/v1/issues/"), "Reject changed scheme/port/path or userinfo");
        rejects(() -> new NightVisionClient("http://api.example.test", "test"), "No plaintext token traffic");
        rejects(() -> new NightVisionClient("https://api.example.test/api", "test"), "No base path ambiguity");
        rejects(() -> new NightVisionClient("https://api.example.test", "x\u0000secret"), "Reject control chars before building auth header");
        rejects(() -> new NightVisionClient("https://api.example.test", "Bearer test"), "Do not guess Bearer auth");
        rejects(() -> c.issues("../secrets"), "Reject path injection");
        NightVisionClient loop = new NightVisionClient("https://api.example.test", "test", req -> new NightVisionClient.Reply(200, "{\"results\":[],\"next\":\"" + req.uri() + "\"}"));
        rejects(() -> loop.issues(SCAN), "Detect pagination loops");
        NightVisionClient malformed = new NightVisionClient("https://api.example.test", "test", req -> new NightVisionClient.Reply(200, "<html>login</html>"));
        rejects(() -> malformed.issues(SCAN), "Reject login HTML");
        NightVisionClient missingRows = new NightVisionClient("https://api.example.test", "test", req -> new NightVisionClient.Reply(200, "{}"));
        rejects(() -> missingRows.issues(SCAN), "Do not treat invalid response as no findings");
        for (int code : List.of(301, 401, 403, 404, 429, 500)) {
            NightVisionClient error = new NightVisionClient("https://api.example.test", "secret-token", req -> new NightVisionClient.Reply(code, "secret-token server error"));
            try { error.issues(SCAN); throw new AssertionError("HTTP failure must fail"); }
            catch (IllegalStateException e) { check(!e.getMessage().contains("secret-token"), "No response/token disclosure on error"); }
        }
        List<HttpRequest> updateCalls = new ArrayList<>();
        NightVisionClient writable = new NightVisionClient("https://api.example.test", "test-token", req -> {
            updateCalls.add(req);
            return new NightVisionClient.Reply(200, "{\"id\":\"" + ISSUE + "\",\"resolution\":1}");
        });
        JsonObject verified = writable.markFalsePositive(ISSUE);
        check(Finding.s(verified, "resolution").equals("1"), "Return read-back verified false-positive resolution");
        check(updateCalls.size() == 2 && updateCalls.get(0).method().equals("PUT") && updateCalls.get(1).method().equals("GET"), "Explicit write followed by verification, with no automatic retry");
        check(updateCalls.stream().allMatch(r -> r.uri().getPath().equals("/api/v1/issues/" + ISSUE + "/")), "Update only the selected issue endpoint");
        String writeBody = body(updateCalls.get(0));
        check(writeBody.equals("{\"resolution\":1}"), "Only send the documented false-positive field; no notes or evidence overwrite");
        check(updateCalls.get(0).headers().firstValue("Content-Type").orElseThrow().equals("application/json"), "JSON write content type");
        check(updateCalls.get(0).headers().firstValue("Authorization").orElseThrow().equals("Token test-token") && !writeBody.contains("test-token"), "Token only in API authorization header");
        updateCalls.clear();
        rejects(() -> writable.markFalsePositive("../other"), "Reject invalid issue ID before writing");
        check(updateCalls.isEmpty(), "No call for invalid issue ID");
        NightVisionClient denied = new NightVisionClient("https://api.example.test", "secret-token", req -> {
            updateCalls.add(req); return new NightVisionClient.Reply(403, "secret-token");
        });
        try { denied.markFalsePositive(ISSUE); throw new AssertionError("Denied update cannot succeed"); }
        catch (IllegalStateException e) { check(e.getMessage().contains("403") && !e.getMessage().contains("secret-token"), "Expose write permission error without secrets"); }
        check(updateCalls.size() == 1, "Do not retry denied writes or label them verified");
        NightVisionClient mismatched = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(200, "{\"id\":\"" + ISSUE + "\",\"resolution\":" + (req.method().equals("PUT") ? 1 : 0) + "}"));
        rejects(() -> mismatched.markFalsePositive(ISSUE), "Do not report success if read-back has another resolution");
        NightVisionClient wrongIssue = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(200, "{\"id\":\"" + SCAN + "\",\"resolution\":1}"));
        rejects(() -> wrongIssue.markFalsePositive(ISSUE), "Reject wrong issue ID in read-back");
        NightVisionClient unverified = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(req.method().equals("PUT") ? 200 : 500, "{\"id\":\"" + ISSUE + "\",\"resolution\":1}"));
        try { unverified.markFalsePositive(ISSUE); throw new AssertionError("Read-back failure cannot be verified"); }
        catch (IllegalStateException e) { check(e.getMessage().contains("accepted") && e.getMessage().contains("could not be verified"), "Distinguish accepted update from failed verification"); }
        check(new Finding(verified).resolutionDisplay().equals("False positive (1)"), "Display verified remote status");
        String raw = "POST /test HTTP/1.1\nHost: example.test\nContent-Type: text/plain\n\nline1\nline2\r\nend";
        String prepared = Finding.prepareRequest(raw);
        check(prepared.startsWith("POST /test HTTP/1.1\r\nHost:"), "Normalize headers");
        check(prepared.endsWith("line1\nline2\r\nend"), "Preserve body newlines exactly");
        rejects(() -> Finding.prepareRequest("curl https://example.test"), "Do not execute or interpret shell commands");
        rejects(() -> Finding.destination("https://user:pass@example.test/"), "Reject embedded credentials");
        rejects(() -> Finding.destination("file:///tmp/test"), "Only HTTP(S) target service");
        check(Finding.destination("https://example.test:8443/path").getPort() == 8443, "Custom port");
        Finding f = new Finding(json("{\"fqdn\":\"example.test\",\"protocol\":\"https\",\"port\":8443,\"url_path\":\"/x?a=1\",\"kind\":{\"name\":\"Kind\"},\"extra_info\":{\"request\":{\"raw\":\"GET /x HTTP/1.1\\r\\nHost: example.test\\r\\n\\r\\n\"}}}"));
        check(f.title().equals("Kind") && f.targetUrl().equals("https://example.test:8443/x?a=1"), "Schema fields");
        check(f.request().startsWith("GET /x HTTP/1.1"), "Nested raw request");
        Finding empty = new Finding(json("{\"extra_info\":{\"request\":\"please run curl\"}}"));
        check(empty.request().isEmpty(), "Do not fabricate a request");

        Map<String, String> preferences = new HashMap<>();
        AtomicReference<Component> tab = new AtomicReference<>();
        MontoyaApi api = (MontoyaApi) mock(MontoyaApi.class, preferences, tab);
        NightVisionExtension extension = new NightVisionExtension(); extension.initialize(api);
        SwingUtilities.invokeAndWait(() -> {});
        check(tab.get() != null, "Registers a suite tab");
        SwingUtilities.invokeAndWait(() -> {
            invoke(extension, "demo");
            JTable table = (JTable) field(extension, "table");
            check(table.getRowCount() == 1 && table.getSelectedRow() == 0, "Demo renders and selects finding");
            check(((JTextArea) field(extension, "request")).getText().contains("Host: example.invalid"), "Demo request displayed");
            ((JTextArea) field(extension, "notes")).setText("Reviewed output encoding");
            ((JComboBox<?>) field(extension, "verdict")).setSelectedItem("Needs review");
            invoke(extension, "saveValidation");
            check(preferences.size() == 1 && preferences.values().iterator().next().contains("Reviewed output encoding"), "Save analyst validation locally");
            invoke(extension, "showSelected");
            check(((JTextArea) field(extension, "notes")).getText().equals("Reviewed output encoding"), "Reload saved analyst notes");
            invoke(extension, "markFalsePositive");
            check(((JLabel) field(extension, "status")).getText().contains("offline demo cannot change"), "Offline demo cannot write to NightVision");
            ((JTextField) field(extension, "search")).setText("no-match");
            check(table.getRowCount() == 0, "Filtering hides unmatched finding");
            ((JTextField) field(extension, "search")).setText("");
            check(table.getRowCount() == 1, "Clearing filter restores finding");
            if (args.length > 0) {
                Component panel = tab.get(); panel.setSize(1500, 980); layout(panel);
                BufferedImage image = new BufferedImage(1500, 980, BufferedImage.TYPE_INT_RGB);
                Graphics2D g = image.createGraphics(); panel.printAll(g); g.dispose();
                try { javax.imageio.ImageIO.write(image, "png", Path.of(args[0]).toFile()); }
                catch (Exception e) { throw new RuntimeException(e); }
            }
        });
        CountDownLatch verifying = new CountDownLatch(1), allowVerification = new CountDownLatch(1);
        String sample;
        try (var in = SelfTest.class.getResourceAsStream("/demo-findings.json")) {
            sample = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        JsonObject sampleIssue = JsonParser.parseString(sample).getAsJsonArray().get(0).getAsJsonObject();
        sampleIssue.addProperty("resolution", 1);
        NightVisionClient delayed = new NightVisionClient("https://api.example.test", "test-token", req -> {
            if (req.method().equals("GET")) { verifying.countDown(); if (!allowVerification.await(3, TimeUnit.SECONDS)) throw new IllegalStateException("Test timed out"); }
            return new NightVisionClient.Reply(200, sampleIssue.toString());
        });
        int annotationsBefore = preferences.size();
        SwingUtilities.invokeAndWait(() -> {
            JTable table = (JTable) field(extension, "table"); table.setRowSelectionInterval(0, 0);
            setField(extension, "client", delayed); setField(extension, "namespace", delayed.origin());
            ((JTextArea) field(extension, "notes")).setText("False positive: reviewed output encoding");
            invoke(extension, "markFalsePositive");
        });
        check(verifying.await(3, TimeUnit.SECONDS), "UI action reaches read-back verification");
        SwingUtilities.invokeAndWait(() -> check(preferences.size() == annotationsBefore, "Do not save a verified sync result before read-back succeeds"));
        allowVerification.countDown(); waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            JTable table = (JTable) field(extension, "table");
            check(table.getModel().getValueAt(0, 5).equals("False positive (1)"), "Update displayed NightVision status after verification");
            check(table.getModel().getValueAt(0, 6).equals("False positive"), "Update local verdict after verified remote change");
            check(preferences.values().stream().anyMatch(v -> v.contains("nightvision_sync") && v.contains("False positive: reviewed output encoding")), "Save sync timestamp and analyst notes locally");
            check(((JLabel) field(extension, "status")).getText().contains("read-back verified"), "Show verified sync success");
        });
        System.out.println("PASS: " + checks + " offline checks (REST contract, pagination, credential boundaries, traffic preservation, explicit updates, read-back verification, and Swing workflow).");
    }
    static String body(HttpRequest request) throws Exception {
        CompletableFuture<byte[]> bytes = new CompletableFuture<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer item) { byte[] chunk = new byte[item.remaining()]; item.get(chunk); out.writeBytes(chunk); }
            public void onError(Throwable error) { bytes.completeExceptionally(error); }
            public void onComplete() { bytes.complete(out.toByteArray()); }
        });
        return new String(bytes.get(3, TimeUnit.SECONDS), java.nio.charset.StandardCharsets.UTF_8);
    }
    static void waitWorker(Object extension) throws Exception {
        for (int i = 0; i < 150; i++) {
            AtomicReference<Object> worker = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> worker.set(field(extension, "worker")));
            if (worker.get() == null) return;
            Thread.sleep(20);
        }
        throw new AssertionError("Worker did not finish");
    }
    static void setField(Object o, String name, Object value) {
        try { Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); f.set(o, value); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static Object field(Object o, String name) {
        try { Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(o); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static void invoke(Object o, String name) {
        try { Method m = o.getClass().getDeclaredMethod(name); m.setAccessible(true); m.invoke(o); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static void layout(Component c) {
        if (c instanceof Container container) { container.doLayout(); for (Component child : container.getComponents()) layout(child); }
    }
    static Object mock(Class<?> type, Map<String, String> prefs, AtomicReference<Component> tab) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> {
            if (method.getName().equals("registerSuiteTab")) { tab.set((Component) args[1]); return null; }
            if (method.getName().equals("getString")) return prefs.get((String) args[0]);
            if (method.getName().equals("setString")) { prefs.put((String) args[0], (String) args[1]); return null; }
            if (method.getReturnType().equals(void.class)) return null;
            if (method.getReturnType().isInterface()) return mock(method.getReturnType(), prefs, tab);
            if (method.getName().equals("toString")) return "mock";
            return null;
        });
    }
}
