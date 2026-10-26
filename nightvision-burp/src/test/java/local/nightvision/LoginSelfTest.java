package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.*;
import java.net.http.HttpRequest;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import static local.nightvision.SelfTest.*;

/** Tests use only temporary synthetic credentials, mock HTTP, and a child Java fixture. */
final class LoginSelfTest {
    private static final String TOKEN = "synthetic-sso-credential";
    static void run() throws Exception {
        Path folder = Files.createTempDirectory("nightvision sso tests ");
        try {
            Path tokenFile = folder.resolve("saved-token");
            AtomicReference<ProcessBuilder> command = new AtomicReference<>();
            AtomicReference<Process> child = new AtomicReference<>();
            NightVisionLogin.requireProductionOrigin("https://API.NIGHTVISION.NET:443/");
            check(true, "SSO accepts only the production HTTPS origin, including its default port");
            for (String base : List.of("http://api.nightvision.net", "https://api.nightvision.net.evil.invalid", "https://api.nightvision.net:444", "https://api.nightvision.net/?x=y", "https://user@api.nightvision.net", "https://other.example.invalid"))
                rejects(() -> NightVisionLogin.requireProductionOrigin(base), "Reject redirecting saved credentials to another origin");
            NightVisionLogin success = login(tokenFile, "success", Duration.ofSeconds(5), command, child);
            check(success.signIn("C:\\Program Files\\Nightvision\\nightvision.exe").equals(TOKEN), "Read the credential produced by a successful login process");
            check(command.get().command().equals(List.of("C:\\Program Files\\Nightvision\\nightvision.exe", "login", "--api-url", "https://api.nightvision.net/api/v1/")), "Pass paths with spaces directly and support CLIs without --timeout");
            check(!command.get().environment().containsKey("NIGHTVISION_TOKEN") && !command.get().environment().containsKey("NIGHTVISION_API_URL"), "Inherited tokens and alternate API environment cannot override browser login");
            check(command.get().redirectErrorStream() && !success.diagnostics().contains("synthetic-output-secret") && !success.diagnostics().contains(TOKEN), "Drain merged CLI output while keeping raw output and credentials out of diagnostics");
            check(success.savedToken().equals(TOKEN), "A saved login can be reused without executing the CLI");
            try { login(tokenFile, "failure", Duration.ofSeconds(5), command, child).signIn("nightvision"); throw new AssertionError("Failed CLI cannot reuse stale credential"); }
            catch (IllegalStateException e) { check(e.getMessage().contains("exit 7") && !e.getMessage().contains("synthetic-output-secret") && !e.getMessage().contains(TOKEN), "CLI failure includes exit code without output or saved secrets"); }
            check(Files.readString(tokenFile).trim().equals(TOKEN), "Failed login does not delete an existing CLI credential");
            Files.delete(tokenFile);
            rejects(() -> login(tokenFile, "missing", Duration.ofSeconds(5), command, child).signIn("nightvision"), "Zero exit without a saved credential cannot connect");
            rejects(() -> new NightVisionLogin(tokenFile, Duration.ofSeconds(5), pb -> { throw new IOException("sensitive-system-error"); }).signIn("nightvision"), "Missing executable produces safe installation guidance");
            rejects(() -> success.signIn("nightvision\n--token secret"), "Reject a multiline executable field");
            for (String text : List.of("", "not a token", "line1\nline2", "x".repeat(NightVisionLogin.MAX_TOKEN_BYTES + 1))) {
                Files.writeString(tokenFile, text);
                rejects(() -> success.savedToken(), "Reject empty, malformed, and oversized saved credentials");
            }
            NightVisionLogin stopped = login(tokenFile, "success", Duration.ofSeconds(5), command, child);
            stopped.cancel();
            try { stopped.signIn("nightvision"); throw new AssertionError("Canceled login cannot start"); }
            catch (CancellationException e) { check(true, "Cancellation before launch prevents login"); }
            Files.writeString(tokenFile, TOKEN);
            NightVisionLogin timeout = login(tokenFile, "wait", Duration.ofMillis(200), command, child);
            rejects(() -> timeout.signIn("nightvision"), "Timed-out login cannot reuse a prior credential");
            check(child.get().waitFor(2, TimeUnit.SECONDS), "Timeout stops the login listener process");
            NightVisionLogin cancel = login(tokenFile, "wait", Duration.ofSeconds(10), command, child);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                child.set(null);
                Future<String> result = executor.submit(() -> cancel.signIn("nightvision"));
                awaitChild(child); cancel.cancel();
                try { result.get(2, TimeUnit.SECONDS); throw new AssertionError("Canceled login cannot complete"); }
                catch (ExecutionException e) { check(e.getCause() instanceof CancellationException, "Cancellation propagates without accepting the old credential"); }
                check(child.get().waitFor(2, TimeUnit.SECONDS), "Cancel stops the CLI process");
            } finally { executor.shutdownNow(); }
            testConfigFormats(folder, command, child);
            testUi(tokenFile);
        } finally {
            try (var files = Files.walk(folder)) { for (Path p : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p); }
        }
    }
    static NightVisionLogin login(Path token, String mode, Duration timeout, AtomicReference<ProcessBuilder> command, AtomicReference<Process> child) {
        return new NightVisionLogin(token, timeout, builder -> {
            command.set(builder);
            String java = Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win") ? "java.exe" : "java").toString();
            List<String> args = new ArrayList<>(List.of(java, "-cp", System.getProperty("java.class.path"), LoginProcessFixture.class.getName(), mode, token.toString()));
            args.addAll(builder.command().subList(1, builder.command().size()));
            ProcessBuilder fixture = new ProcessBuilder(args);
            fixture.environment().clear(); fixture.environment().putAll(builder.environment());
            fixture.redirectOutput(builder.redirectOutput()).redirectError(builder.redirectError()).redirectErrorStream(builder.redirectErrorStream());
            Process process = fixture.start(); child.set(process); return process;
        });
    }
    static void testConfigFormats(Path folder, AtomicReference<ProcessBuilder> command, AtomicReference<Process> child) throws Exception {
        Path dir = Files.createDirectory(folder.resolve("current-cli")); Path legacy = dir.resolve("token"); Path config = dir.resolve("nightvision.yml");
        NightVisionLogin current = login(legacy, "old-cli", Duration.ofSeconds(5), command, child);
        check(current.signIn("nightvision").equals(TOKEN), "Reproduce an older CLI that rejects --timeout and writes current YAML config");
        String before = Files.readString(config);
        check(current.savedToken().equals(TOKEN) && Files.readString(config).equals(before), "Reuse a terminal login saved in nightvision.yml without modifying it");
        check(current.diagnostics().contains("nightvision.yml") && !current.diagnostics().contains(TOKEN), "Diagnose the loaded source file without disclosing its credential");
        Files.writeString(legacy, "stale-legacy-token");
        check(current.savedToken().equals(TOKEN), "Prefer current CLI YAML over a stale legacy token file");
        for (String value : List.of("token: '" + TOKEN + "' # comment\n", "token: \"" + TOKEN + "\"\n", "{\"token\":\"" + TOKEN + "\",\"api-url\":\"https://api.nightvision.net/api/v1/\"}", "\ufefftoken: " + TOKEN + "\n")) {
            Files.writeString(config, value); check(current.savedToken().equals(TOKEN), "Read quoted YAML, comments, JSON, and UTF-8 BOM without including syntax in the token");
        }
        Files.delete(legacy);
        for (String invalid : List.of("token: [" + TOKEN, "token: " + TOKEN + "\ntoken: duplicate-secret\n", "token: !!java.net.URL ['https://example.invalid']", "token: {secret: '" + TOKEN + "'}", "token: '" + TOKEN + "'\napi-url: https://other.example.invalid/api/v1/", "nested:\n  token: " + TOKEN + "\n", "token: '" + TOKEN + "'\nTOKEN: second-secret\n")) {
            Files.writeString(config, invalid);
            try { current.savedToken(); throw new AssertionError("Unsupported or ambiguous config cannot authenticate"); }
            catch (IllegalStateException e) { check(!e.getMessage().contains(TOKEN) && !e.getMessage().contains("duplicate-secret") && !e.getMessage().contains("second-secret"), "Reject malformed config, unsafe tags, wrong origin, nested/ambiguous tokens without leaking YAML source"); }
        }
        Path selected = folder.resolve("explicit-login.yaml"); Files.writeString(selected, "token: " + TOKEN + "\n");
        check(current.savedToken(selected.toString()).equals(TOKEN), "Use an explicitly chosen login config when OS home directories differ");
        rejects(() -> current.savedToken(folder.resolve("missing-config.yml").toString()), "An explicit missing file must not fall back to another account's credential");
        Files.delete(config); Files.writeString(legacy, TOKEN);
        check(current.savedToken().equals(TOKEN), "Preserve support for legacy plain token files");
        Path json = dir.resolve("nightvision.json"); Files.writeString(json, "{\"token\":\"" + TOKEN + "\"}");
        check(current.savedToken().equals(TOKEN), "Auto-detect a JSON CLI config");
        Files.delete(json);
        NightVisionLogin noisy = login(legacy, "noisy-failure", Duration.ofSeconds(5), command, child);
        try { noisy.signIn("nightvision"); throw new AssertionError("Noisy failure must fail"); }
        catch (IllegalStateException e) { check(!e.getMessage().contains("synthetic-secret") && !noisy.diagnostics().contains("synthetic-secret"), "Drain output exceeding the capture cap without deadlock or credential leakage"); }
        for (String raw : List.of("unknown flag: --timeout token=" + TOKEN, "listen: address already in use " + TOKEN, "permission denied " + TOKEN, "xdg-open not found " + TOKEN))
            check(!NightVisionLogin.failureHint(raw).contains(TOKEN), "Whitelist failure explanations rather than echoing CLI errors");
        Files.delete(legacy); Files.delete(dir); Files.delete(selected);
    }
    static void awaitChild(AtomicReference<Process> child) throws Exception {
        for (int i = 0; i < 100; i++) { if (child.get() != null) return; Thread.sleep(10); }
        throw new AssertionError("Login process did not start");
    }
    static void testUi(Path tokenFile) throws Exception {
        Map<String, String> preferences = new HashMap<>(); AtomicReference<Component> tab = new AtomicReference<>();
        AtomicReference<Object> unload = new AtomicReference<>(); List<HttpRequest> calls = new ArrayList<>();
        AtomicInteger factories = new AtomicInteger(); AtomicReference<ProcessBuilder> command = new AtomicReference<>(); AtomicReference<Process> child = new AtomicReference<>();
        MontoyaApi api = (MontoyaApi) mockWithUnload(MontoyaApi.class, preferences, tab, unload);
        BiFunction<String, String, NightVisionClient> apiClient = (base, token) -> {
            check(token.equals(TOKEN) && base.equals(NightVisionClient.DEFAULT_ORIGIN), "Reuse saved login only with the canonical NightVision API");
            return new NightVisionClient(base, token, req -> {
                calls.add(req);
                return new NightVisionClient.Reply(200, req.uri().getPath().equals("/api/v1/user/me/")
                    ? "{\"user\":{\"id\":\"user-1\",\"email\":\"analyst@example.invalid\"}}"
                    : "{\"results\":[{\"id\":\"" + SCAN + "\",\"target_name\":\"Synthetic scan\"}],\"next\":null}");
            });
        };
        NightVisionExtension extension = new NightVisionExtension(() -> { factories.incrementAndGet(); return login(tokenFile, "success", Duration.ofSeconds(5), command, child); }, apiClient);
        extension.initialize(api); SwingUtilities.invokeAndWait(() -> {});
        check(factories.get() == 0 && calls.isEmpty(), "Startup does not read saved credentials or start a browser login");
        SwingUtilities.invokeAndWait(() -> {
            ((JTextField) field(extension, "origin")).setText("https://other.example.invalid"); connectLogin(extension, false);
            check(factories.get() == 0 && calls.isEmpty(), "Custom origin is rejected before saved-login access or API requests");
            ((JTextField) field(extension, "origin")).setText(NightVisionClient.DEFAULT_ORIGIN); connectLogin(extension, false);
        });
        waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            check(field(extension, "client") != null && ((JComboBox<?>) field(extension, "scans")).getItemCount() == 1, "Saved login verifies user then loads scans");
            check(((JLabel) field(extension, "status")).getText().contains("analyst@example.invalid"), "Show the verified account identity");
            check(((JPasswordField) field(extension, "token")).getPassword().length == 0, "Do not copy SSO credentials into the manual token field");
            invoke(extension, "disconnect");
        });
        check(calls.size() == 2 && calls.get(0).uri().getPath().equals("/api/v1/user/me/") && calls.get(1).uri().getPath().equals("/api/v1/scans/"), "Verify saved identity before retrieving any scan pages");
        check(calls.stream().allMatch(r -> r.headers().firstValue("Authorization").orElse("").equals("Token " + TOKEN)), "Use the CLI token with NightVision's documented authorization scheme");
        check(preferences.isEmpty() && Files.readString(tokenFile).equals(TOKEN), "Reusing or disconnecting does not persist a token in Burp or change the CLI token file");
        SwingUtilities.invokeAndWait(() -> { ((JTextField) field(extension, "cliPath")).setText("C:\\Program Files\\Nightvision\\nightvision.exe"); connectLogin(extension, true); });
        waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> check(field(extension, "client") != null, "Browser-login process completion can establish a verified API connection"));
        check(preferences.size() == 1 && preferences.containsKey("nightvision.cli.path") && preferences.values().stream().noneMatch(v -> v.contains(TOKEN)), "Persist only the non-secret CLI path");
        testUiErrors(tokenFile, 401, "rejected", true);
        testUiErrors(tokenFile, 403, "permissions", true);
        testUiErrors(tokenFile, 500, "HTTP 500", false);
        testUiCancellation(tokenFile, false); testUiCancellation(tokenFile, true);
    }
    static void testUiErrors(Path tokenFile, int status, String expected, boolean authError) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        NightVisionExtension extension = new NightVisionExtension(() -> new NightVisionLogin(tokenFile, Duration.ofSeconds(5), pb -> { throw new AssertionError("Saved login must not launch a process"); }),
            (base, token) -> new NightVisionClient(base, token, req -> { requests.incrementAndGet(); return new NightVisionClient.Reply(status, "secret response " + TOKEN); }));
        extension.initialize((MontoyaApi) mock(MontoyaApi.class, new HashMap<>(), new AtomicReference<>())); SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> connectLogin(extension, false)); waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            String text = ((JLabel) field(extension, "status")).getText();
            check(field(extension, "client") == null && requests.get() == 1, "Rejected user verification prevents scan loading");
            check(text.contains(expected) && !text.contains(TOKEN), "Give useful sign-in errors without response bodies or credentials");
            if (!authError) check(!text.contains("rejected") && !text.contains("expired"), "Do not mislabel service failures as expired login");
        });
    }
    static void testUiCancellation(Path tokenFile, boolean unloading) throws Exception {
        AtomicReference<Process> child = new AtomicReference<>(); AtomicReference<Object> unload = new AtomicReference<>(); AtomicInteger requests = new AtomicInteger();
        NightVisionExtension extension = new NightVisionExtension(() -> login(tokenFile, "wait", Duration.ofSeconds(10), new AtomicReference<>(), child),
            (base, token) -> { requests.incrementAndGet(); throw new AssertionError("Canceled login must not create an API session"); });
        extension.initialize((MontoyaApi) mockWithUnload(MontoyaApi.class, new HashMap<>(), new AtomicReference<>(), unload)); SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {
            connectLogin(extension, true);
            check(((JButton) field(extension, "cancelSignIn")).isEnabled() && !((JTextField) field(extension, "cliPath")).isEnabled(), "Offer cancel while login runs in the background");
        });
        awaitChild(child);
        SwingUtilities.invokeAndWait(() -> {
            if (unloading) {
                try { Method method = unload.get().getClass().getInterfaces()[0].getMethods()[0]; method.invoke(unload.get()); }
                catch (Exception e) { throw new RuntimeException(e); }
            } else invoke(extension, "cancelSignIn");
        });
        waitWorker(extension);
        check(child.get().waitFor(2, TimeUnit.SECONDS) && requests.get() == 0, "Cancel or unload terminates the login listener and prevents API connection");
        SwingUtilities.invokeAndWait(() -> check(field(extension, "client") == null, "Canceled or unloaded sign-in never creates a connection"));
        check(Files.exists(tokenFile), "Cancellation does not delete the shared saved CLI credential");
    }
    static void connectLogin(Object extension, boolean browser) {
        try { Method method = extension.getClass().getDeclaredMethod("connectLogin", boolean.class); method.setAccessible(true); method.invoke(extension, browser); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static Object mockWithUnload(Class<?> type, Map<String, String> prefs, AtomicReference<Component> tab, AtomicReference<Object> unload) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> {
            if (method.getName().equals("registerUnloadingHandler")) { unload.set(args[0]); return null; }
            if (method.getName().equals("registerSuiteTab")) { tab.set((Component) args[1]); return null; }
            if (method.getName().equals("getString")) return prefs.get((String) args[0]);
            if (method.getName().equals("setString")) { prefs.put((String) args[0], (String) args[1]); return null; }
            if (method.getReturnType().equals(void.class)) return null;
            if (method.getReturnType().isInterface()) return mockWithUnload(method.getReturnType(), prefs, tab, unload);
            return null;
        });
    }
}
