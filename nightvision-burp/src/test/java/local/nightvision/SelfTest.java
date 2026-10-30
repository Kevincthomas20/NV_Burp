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

/**
 * Build-time regression runner: exercises API rules, captured traffic, and Swing
 * behavior using synthetic data and a mock Burp host. Delegates process tests to
 * LoginSelfTest and real local HTTPS checks to TlsSelfTest; no live account is used.
 */
public class SelfTest {
    // Shared assertion count and synthetic identifiers used across the test classes.
    static int checks;
    static final String SCAN = "22222222-2222-4222-8222-222222222222";
    static final String ISSUE = "11111111-1111-4111-8111-111111111111";
    /** Fails the build at the first unmet expectation and counts successful checks. */
    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
    /** Requires an expected validation/application rejection rather than an unrelated exception. */
    static void rejects(Throwing action, String reason) throws Exception {
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException e) { checks++; return; }
        throw new AssertionError(reason);
    }
    interface Throwing { void run() throws Exception; }
    static JsonObject json(String text) { return JsonParser.parseString(text).getAsJsonObject(); }
    /** Runs the suites in order; an optional argument writes a mock-host UI preview PNG. */
    public static void main(String[] args) throws Exception {
        // API reads: follow allowed pagination and normalize Token authentication.
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
        // Credential boundaries: hostile next links must fail before any second request is sent.
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
        // Response failures: loops, malformed bodies, and HTTP errors must not look like empty results.
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
        // Remote writes: assert the exact issue, minimal payload, and separate read-back verification.
        List<HttpRequest> updateCalls = new ArrayList<>();
        NightVisionClient writable = new NightVisionClient("https://api.example.test", "test-token", req -> {
            updateCalls.add(req);
            return new NightVisionClient.Reply(200, "{\"id\":\"" + ISSUE + "\",\"resolution\":2}");
        });
        JsonObject verified = writable.markFalsePositive(ISSUE);
        check(Finding.s(verified, "resolution").equals("2"), "Return read-back verified false-positive resolution");
        check(updateCalls.size() == 2 && updateCalls.get(0).method().equals("PUT") && updateCalls.get(1).method().equals("GET"), "Explicit write followed by verification, with no automatic retry");
        check(updateCalls.stream().allMatch(r -> r.uri().getPath().equals("/api/v1/issues/" + ISSUE + "/")), "Update only the selected issue endpoint");
        String writeBody = body(updateCalls.get(0));
        check(writeBody.equals("{\"resolution\":2}"), "Send false positive code 2 rather than resolved code 1, without notes or evidence overwrite");
        check(updateCalls.get(0).headers().firstValue("Content-Type").orElseThrow().equals("application/json"), "JSON write content type");
        check(updateCalls.get(0).headers().firstValue("Authorization").orElseThrow().equals("Token test-token") && !writeBody.contains("test-token"), "Token only in API authorization header");
        updateCalls.clear();
        rejects(() -> writable.markFalsePositive("../other"), "Reject invalid issue ID before writing");
        check(updateCalls.isEmpty(), "No call for invalid issue ID");
        // A denied/uncertain write must not retry or save a false verification result.
        NightVisionClient denied = new NightVisionClient("https://api.example.test", "secret-token", req -> {
            updateCalls.add(req); return new NightVisionClient.Reply(403, "secret-token");
        });
        try { denied.markFalsePositive(ISSUE); throw new AssertionError("Denied update cannot succeed"); }
        catch (IllegalStateException e) { check(e.getMessage().contains("403") && !e.getMessage().contains("secret-token"), "Expose write permission error without secrets"); }
        check(updateCalls.size() == 1, "Do not retry denied writes or label them verified");
        NightVisionClient mismatched = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(200, "{\"id\":\"" + ISSUE + "\",\"resolution\":" + (req.method().equals("PUT") ? 2 : 0) + "}"));
        rejects(() -> mismatched.markFalsePositive(ISSUE), "Do not report success if read-back has another resolution");
        NightVisionClient wrongIssue = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(200, "{\"id\":\"" + SCAN + "\",\"resolution\":2}"));
        rejects(() -> wrongIssue.markFalsePositive(ISSUE), "Reject wrong issue ID in read-back");
        NightVisionClient unverified = new NightVisionClient("https://api.example.test", "test", req ->
            new NightVisionClient.Reply(req.method().equals("PUT") ? 200 : 500, "{\"id\":\"" + ISSUE + "\",\"resolution\":2}"));
        try { unverified.markFalsePositive(ISSUE); throw new AssertionError("Read-back failure cannot be verified"); }
        catch (IllegalStateException e) { check(e.getMessage().contains("accepted") && e.getMessage().contains("could not be verified"), "Distinguish accepted update from failed verification"); }
        check(new Finding(verified).resolutionDisplay().equals("False positive (2)"), "Display verified remote status");
        // Independent numeric fixtures reproduce the live mapping rather than deriving it from the write constant.
        for (var expected : Map.of(0, "Open (0)", 1, "Resolved (1)", 2, "False positive (2)", 4, "Won't fix (4)", 3, "API value 3").entrySet()) {
            JsonObject issue = json("{\"resolution\":" + expected.getKey() + "}");
            check(new Finding(issue).resolutionDisplay().equals(expected.getValue()), "Use the deployed web app's resolution labels and retain unknown codes");
        }
        List<HttpRequest> resolvedCalls = new ArrayList<>();
        NightVisionClient stillResolved = new NightVisionClient("https://api.example.test", "test", req -> {
            resolvedCalls.add(req);
            return new NightVisionClient.Reply(200, "{\"id\":\"" + ISSUE + "\",\"resolution\":" + (req.method().equals("PUT") ? 2 : 1) + "}");
        });
        rejects(() -> stillResolved.markFalsePositive(ISSUE), "A resolved (1) read-back must never verify a false-positive action");
        check(resolvedCalls.size() == 2 && body(resolvedCalls.get(0)).equals("{\"resolution\":2}"), "A mismatched resolved read-back never retries the write or substitutes the old value");
        // Request preparation: validate destinations and normalize headers while preserving body text.
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

        // Structured captures: preserve URL escapes, duplicate headers, cookies, Unicode, and bodies.
        JsonObject structured;
        try (var in = SelfTest.class.getResourceAsStream("/nightvision-structured-traffic.json")) {
            structured = json(new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        }
        Finding captured = new Finding(structured);
        check(captured.requests().size() == 2 && captured.responses().size() == 2, "Read documented plural NightVision capture arrays");
        String post = captured.requests().get(0).text();
        check(post.startsWith("POST /api/search?q=a%2Fb&n=1 HTTP/1.1\r\nHost: app.example.invalid:8443\r\n"), "Preserve escaped path/query and derive Host including port");
        check(post.contains("X-Test: first\r\nX-Test: second\r\n"), "Preserve duplicate headers and order");
        check(post.contains("Content-Type: application/json\r\n") && post.contains("Cookie: session=synthetic-cookie\r\n"), "Read postData MIME type and captured cookies");
        check(post.endsWith("{\"marker\":\"café\"}\nsecond line\r\nlast"), "Preserve structured request body text, Unicode, and mixed newlines");
        check(captured.requests().get(0).destination().equals("https://app.example.invalid:8443/api/search?q=a%2Fb&n=1"), "Use selected capture URL for service destination");
        check(captured.requests().get(1).text().contains("Host: recorded.example.invalid\r\n") && !captured.requests().get(1).text().contains("Host: other.example.invalid"), "Keep captured Host even when URL differs");
        check(captured.requests().get(1).text().startsWith("GET /next?x=%252F HTTP/1.1"), "Do not decode or double-encode query");
        check(captured.requests().get(1).text().contains("Accept: text/plain\r\nAccept: application/json\r\n"), "Read header maps with repeated values");
        check(captured.response().startsWith("HTTP/2 302 Found\r\n") && captured.response().endsWith("redirect\nbody"), "Render recorded status and content text");
        check(captured.response().contains("Set-Cookie: a=1; Secure\r\nSet-Cookie: b=2; Secure\r\n"), "Preserve response Set-Cookie headers independently");
        check(captured.responses().get(1).text().endsWith("café\n"), "Decode explicit base64 UTF-8 content");
        // Unsupported evidence must remain diagnosable instead of being silently altered for replay.
        Finding malformedCapture = new Finding(json("{\"extra_info\":{\"http_requests\":[null,{},\"GET /raw HTTP/1.1\\r\\nHost: raw.invalid\\r\\n\\r\\n\"]}}"));
        check(malformedCapture.requests().size() == 3 && malformedCapture.requests().get(0).text().isEmpty(), "Keep unsupported array entries without crashing");
        check(malformedCapture.request().startsWith("GET /raw"), "Usable raw array capture remains accessible after unsupported entries");
        Finding missingBody = new Finding(json("{\"extra_info\":{\"http_requests\":[{\"method\":\"POST\",\"url\":\"https://example.invalid\",\"postData\":{\"params\":[{\"name\":\"x\",\"value\":\"1\"}]}}]}}"));
        check(missingBody.request().isEmpty() && missingBody.requests().get(0).note().contains("body text is missing"), "Do not silently replay an empty body when only structured parameters were captured");
        Finding binary = new Finding(json("{\"extra_info\":{\"http_responses\":[{\"status\":200,\"content\":{\"text\":\"/w==\",\"encoding\":\"base64\"}}]}}"));
        check(binary.response().isEmpty() && binary.responses().get(0).note().contains("binary"), "Explain binary bodies instead of corrupting them in the text view");
        Finding badHeader = new Finding(json("{\"extra_info\":{\"http_requests\":[{\"method\":\"GET\",\"url\":\"https://example.invalid\",\"headers\":[{\"name\":\"X-Test\",\"value\":\"one\\r\\nInjected: two\"}]}]}}"));
        check(badHeader.request().isEmpty(), "Do not introduce line breaks while reconstructing structured headers");
        Finding unpaired = new Finding(json("{\"extra_info\":{\"http_requests\":[\"GET /a HTTP/1.1\\r\\nHost: example.invalid\\r\\n\\r\\n\",\"GET /b HTTP/1.1\\r\\nHost: example.invalid\\r\\n\\r\\n\"],\"http_responses\":[]}}"));
        check(unpaired.requests().size() == 2 && unpaired.responses().isEmpty(), "Do not invent or borrow responses when arrays differ");
        Finding topLevel = new Finding(json("{\"http_requests\":[{\"method\":\"GET\",\"url\":\"https://example.invalid\"}],\"responseHeader\":\"HTTP/1.1 200 OK\\r\\nServer: synthetic\",\"responseBody\":\"original\"}"));
        check(topLevel.request().startsWith("GET / HTTP/1.1") && topLevel.response().endsWith("\r\n\r\noriginal"), "Keep top-level arrays and legacy header/body support");

        // Mock-host UI workflow: startup, demo, local notes, filtering, and blocked offline writes.
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
        // Hold the verification GET open to prove the UI does not record success after PUT alone.
        CountDownLatch verifying = new CountDownLatch(1), allowVerification = new CountDownLatch(1);
        String sample;
        try (var in = SelfTest.class.getResourceAsStream("/demo-findings.json")) {
            sample = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        JsonObject sampleIssue = JsonParser.parseString(sample).getAsJsonArray().get(0).getAsJsonObject();
        sampleIssue.addProperty("resolution", 2);
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
            check(table.getModel().getValueAt(0, 5).equals("False positive (2)"), "Update displayed NightVision status after verification");
            var reported = extension.reportSnapshot(NightVisionExtension.ReportScope.ALL, false,
                new ValidationReport.Options("Resolution regression", "Test analyst", true, false, false));
            check(reported.rows().get(0).remoteResolution().equals("False positive (2)")
                && ValidationReport.render(reported, ValidationReport.Format.HTML).content().contains("False positive (2)"), "Reports use the corrected remote label after a verified false-positive update");
            check(preferences.values().stream().filter(v -> v.startsWith("{")).map(SelfTest::json)
                .anyMatch(v -> "2".equals(Finding.s(Finding.object(v, "nightvision_sync"), "resolution"))), "Saved sync receipts record false-positive code 2, matching the verified API value");
            check(table.getModel().getValueAt(0, 6).equals("False positive"), "Update local verdict after verified remote change");
            check(preferences.values().stream().anyMatch(v -> v.contains("nightvision_sync") && v.contains("False positive: reviewed output encoding")), "Save sync timestamp and analyst notes locally");
            check(((JLabel) field(extension, "status")).getText().contains("read-back verified"), "Show verified sync success");
        });
        // Reproduce list responses with no traffic, followed by full detail containing multiple captures.
        List<HttpRequest> evidenceCalls = new ArrayList<>();
        NightVisionClient evidenceClient = new NightVisionClient("https://api.example.test", "test-token", req -> {
            evidenceCalls.add(req);
            return new NightVisionClient.Reply(200, req.uri().getPath().endsWith("/issues/")
                ? "{\"results\":[{\"id\":\"" + ISSUE + "\",\"fqdn\":\"summary.example.invalid\"}],\"next\":null}" : structured.toString());
        });
        SwingUtilities.invokeAndWait(() -> {
            setField(extension, "client", evidenceClient);
            ((JTextField) field(extension, "scanId")).setText(SCAN);
            invoke(extension, "loadFindings");
        });
        waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            JTable table = (JTable) field(extension, "table"); table.setRowSelectionInterval(0, 0);
            check(((JLabel) field(extension, "requestInfo")).getText().contains("Fetch full finding"), "Summary without traffic explains how to fetch detail");
            invoke(extension, "fetchDetail");
        });
        waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            JComboBox<?> requests = (JComboBox<?>) field(extension, "capturedRequests");
            JComboBox<?> responses = (JComboBox<?>) field(extension, "capturedResponses");
            check(requests.getItemCount() == 2 && responses.getItemCount() == 2, "Fetch detail populates both captured-message selectors");
            check(((JTextArea) field(extension, "request")).getText().equals(post), "Live-style fetched request appears in Request tab");
            check(((JTextArea) field(extension, "response")).getText().equals(captured.response()), "Live-style fetched response appears in Original response tab");
            requests.setSelectedIndex(1);
            check(((JTextField) field(extension, "destination")).getText().equals("http://other.example.invalid/next?x=%252F"), "Switching capture updates destination from that capture URL");
            check(((JTextArea) field(extension, "request")).getText().startsWith("GET /next?x=%252F"), "Switching capture updates request editor");
            ((JTextArea) field(extension, "request")).append("edited"); responses.setSelectedIndex(1);
            check(((JTextArea) field(extension, "request")).getText().endsWith("edited"), "Browsing responses preserves current request edits");
            check(((JTextArea) field(extension, "response")).getText().endsWith("café\n"), "Response selector shows selected decoded content");
            check(((JLabel) field(extension, "requestInfo")).getText().contains("Reconstructed"), "Show reconstruction status separately from replayable HTTP text");
            check(((JTextArea) field(extension, "raw")).getText().contains("http_requests"), "Keep unmodified structured evidence available in Full finding JSON");
            if (args.length > 0) {
                requests.setSelectedIndex(0);
                Component panel = tab.get();
                findTabs(panel).setSelectedIndex(1);
                panel.setSize(1500, 980); layout(panel);
                BufferedImage image = new BufferedImage(1500, 980, BufferedImage.TYPE_INT_RGB);
                Graphics2D g = image.createGraphics(); panel.printAll(g); g.dispose();
                try { javax.imageio.ImageIO.write(image, "png", Path.of(args[0]).toFile()); }
                catch (Exception e) { throw new RuntimeException(e); }
            }
            invoke(extension, "disconnect");
            check(requests.getItemCount() == 0 && responses.getItemCount() == 0 && ((JTextArea) field(extension, "request")).getText().isEmpty(), "Disconnect clears captured messages and text");
        });
        check(evidenceCalls.size() == 2 && evidenceCalls.stream().allMatch(r -> r.method().equals("GET") && r.uri().getHost().equals("api.example.test")), "Loading and browsing evidence makes only the two expected NightVision API reads");
        // These suites add real child-process and local HTTPS behavior to the mock API coverage.
        LoginSelfTest.run();
        TlsSelfTest.run();
        ReportSelfTest.run();
        PersistenceSelfTest.run();
        ResolutionSelfTest.run();
        EvidenceSelfTest.run();
        EvidenceCompatibilitySelfTest.run();
        RepeaterSelfTest.run();
        System.out.println("PASS: " + checks + " checks (REST, SSO, TLS, traffic, reports, real preferences, evidence files/context menu, and Swing workflow).");
    }
    /** Collects a Java HTTP BodyPublisher so tests can inspect the exact outgoing JSON payload. */
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
    /** Waits for the EDT completion callback, with a deadline so stalled work fails the build. */
    static void waitWorker(Object extension) throws Exception {
        for (int i = 0; i < 150; i++) {
            AtomicReference<Object> worker = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> worker.set(field(extension, "worker")));
            if (worker.get() == null) return;
            Thread.sleep(20);
        }
        throw new AssertionError("Worker did not finish");
    }
    /** Test-only reflection avoids adding production setters just to arrange a UI scenario. */
    static void setField(Object o, String name, Object value) {
        try { Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); f.set(o, value); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    /** Reads private controller state for an assertion; Swing state is read on the EDT by callers. */
    static Object field(Object o, String name) {
        try { Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(o); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    /** Invokes a button action directly; UI callers schedule this on Swing's event thread. */
    static void invoke(Object o, String name) {
        try { Method m = o.getClass().getDeclaredMethod(name); m.setAccessible(true); m.invoke(o); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    /** Lays out a headless component tree before drawing an optional preview image. */
    static void layout(Component c) {
        if (c instanceof Container container) { container.doLayout(); for (Component child : container.getComponents()) layout(child); }
    }
    /** Finds the detail tabs so the preview can show captured request text. */
    static JTabbedPane findTabs(Component c) {
        if (c instanceof JTabbedPane tabs) return tabs;
        if (c instanceof Container container) for (Component child : container.getComponents()) {
            JTabbedPane tabs = findTabs(child); if (tabs != null) return tabs;
        }
        return null;
    }
    /** Minimal recursive Montoya proxy capturing the registered tab and preference reads/writes. */
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
