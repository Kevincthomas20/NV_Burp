package local.nightvision;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/**
 * Runs the official CLI's browser sign-in and reads the credential it saves.
 * Passwords and SSO pages stay with the CLI/browser. This class owns process
 * lifetime, cancellation, saved-file discovery, and sanitized login diagnostics.
 */
public final class NightVisionLogin {
    static final String API_URL = NightVisionClient.DEFAULT_ORIGIN + "/api/v1/";
    static final int MAX_TOKEN_BYTES = 16 * 1024;
    // Injected by tests to simulate CLI success, failure, hangs, and cancellation.
    @FunctionalInterface interface Launcher { Process start(ProcessBuilder builder) throws IOException; }
    private final List<Path> tokenFiles;
    private final Duration timeout;
    private final Launcher launcher;
    // Shared with the UI's cancellation and Burp unload handlers.
    private volatile Process process;
    private volatile boolean cancelled;
    private final StringBuilder diagnostics = new StringBuilder("NightVision login diagnostics (credential contents and raw CLI output are omitted).\n");

    /** Uses the current OS user's CLI locations and a five-minute parent-side timeout. */
    public NightVisionLogin() {
        this(SavedLogin.defaultCandidates(), Duration.ofMinutes(5), ProcessBuilder::start);
    }
    /** Test constructor that expands a legacy token path into adjacent CLI config candidates. */
    NightVisionLogin(Path tokenFile, Duration timeout, Launcher launcher) {
        this(SavedLogin.candidates(tokenFile), timeout, launcher);
    }
    /** Takes an immutable candidate list so discovery stays stable throughout one attempt. */
    NightVisionLogin(List<Path> tokenFiles, Duration timeout, Launcher launcher) {
        this.tokenFiles = List.copyOf(tokenFiles); this.timeout = timeout; this.launcher = launcher;
    }
    /** Prevents automatically discovered SSO credentials from being sent to another API host. */
    public static void requireProductionOrigin(String base) {
        URI u = NightVisionClient.apiOrigin(base);
        if (!"api.nightvision.net".equalsIgnoreCase(u.getHost()) || !(u.getPort() == -1 || u.getPort() == 443))
            throw new IllegalArgumentException("SSO and saved CLI login connect to https://api.nightvision.net. Use a manual API token for other origins.");
    }
    /** Runs browser login, waits for CLI completion, then reads its saved credential. */
    public String signIn(String executable) throws Exception {
        checkCancelled();
        String path = executable.trim();
        if (path.isEmpty() || path.indexOf('\0') >= 0 || path.indexOf('\r') >= 0 || path.indexOf('\n') >= 0)
            throw new IllegalArgumentException("Select the NightVision CLI executable, without command arguments.");
        // The parent bounds login time, including for older CLIs without a --timeout flag.
        // Pass an argument list directly: spaces in an executable path never become shell syntax.
        ProcessBuilder builder = new ProcessBuilder(List.of(path, "login", "--api-url", API_URL));
        builder.redirectErrorStream(true);
        addDiagnostic("Launching CLI browser login. Timeout is enforced by the extension.");
        // A token inherited from Burp's environment must not bypass the requested browser login.
        builder.environment().remove("NIGHTVISION_TOKEN");
        builder.environment().remove("NIGHTVISION_API_URL");
        Process started;
        try { started = launcher.start(builder); }
        catch (IOException e) {
            throw new IllegalStateException("Could not start the NightVision CLI. Install the current CLI and select its executable using Browse.");
        }
        process = started;
        // Drain output concurrently so a noisy CLI cannot block on a full OS pipe.
        BoundedOutput output = new BoundedOutput(started.getInputStream());
        Thread drain = new Thread(output, "nightvision-login-output"); drain.setDaemon(true); drain.start();
        try {
            started.getOutputStream().close(); // Login is browser-driven; do not leave terminal stdin open.
            checkCancelled();
            if (!started.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                addDiagnostic("CLI login exceeded the allowed wait; listener stopped.");
                throw new IllegalStateException("SSO sign-in timed out. Try again and complete the browser login within five minutes.");
            }
            checkCancelled();
            drain.join(1000);
            addDiagnostic("CLI exit code: " + started.exitValue());
            if (started.exitValue() != 0) {
                String hint = failureHint(output.text()); addDiagnostic(hint);
                throw new IllegalStateException("NightVision CLI sign-in failed (exit " + started.exitValue() + "). " + hint + " See Connection diagnostics.");
            }
            // A zero exit code still requires a readable saved credential; the UI verifies it via the API.
            return savedToken();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); cancelled = true;
            throw new CancellationException("Sign-in canceled.");
        } finally { stop(started); try { started.getInputStream().close(); } catch (IOException ignored) {} process = null; }
    }
    /** Reads the standard candidate files after CLI login or when no override was selected. */
    public String savedToken() {
        return savedToken("");
    }
    /** Reuses one explicit file or searches known CLI locations without launching a process. */
    public String savedToken(String selectedFile) {
        checkCancelled();
        final List<Path> paths;
        try { paths = selectedFile.isBlank() ? tokenFiles : List.of(Path.of(selectedFile.trim()).toAbsolutePath().normalize()); }
        catch (InvalidPathException e) { throw new IllegalArgumentException("Select a valid saved-login file path."); }
        // Missing candidates may be skipped; an invalid existing config is not hidden by a stale fallback.
        for (Path path : paths) {
            checkCancelled(); addDiagnostic("Checking: " + path);
            if (!Files.exists(path)) { addDiagnostic("Not found."); continue; }
            final String token;
            try { token = SavedLogin.read(path); }
            catch (IllegalStateException e) { addDiagnostic(e.getMessage()); throw e; }
            checkCancelled();
            if (token != null) { addDiagnostic("Loaded credential from: " + path + " (value omitted)."); return token; }
            addDiagnostic("Config has no token field.");
        }
        throw new IllegalStateException("No reusable saved NightVision login found. Select your .nightvision/nightvision.yml using Browse login file, then click Use saved login. See Connection diagnostics for checked paths.");
    }
    // Synchronize diagnostics because cancellation can append from another thread.
    public synchronized String diagnostics() { return diagnostics.toString(); }
    private synchronized void addDiagnostic(String line) { diagnostics.append(line).append('\n'); }
    /** Classifies retained CLI output into fixed guidance without echoing any captured text. */
    static String failureHint(String output) {
        String text = output.toLowerCase(Locale.ROOT);
        if (text.contains("unknown flag") || text.contains("flag provided but not defined")) return "The CLI rejected a command-line option. Update the CLI or complete nightvision login in a terminal, then use the saved login.";
        if (text.contains("address already in use") || text.contains("bind: address")) return "The CLI login callback port is busy. Finish or close another CLI login, then retry.";
        if (text.contains("permission denied") || text.contains("access is denied")) return "The CLI reported a file or process permission problem. Run terminal login as the same desktop user as Burp.";
        if (text.contains("browser") || text.contains("xdg-open")) return "The CLI could not complete the browser flow. Run nightvision login in a desktop terminal, then click Use saved login.";
        return "Run nightvision login in a terminal, complete SSO, then click Use saved login. Raw CLI output is omitted to protect credentials.";
    }
    /** Drains the full stream but retains only its first 64 KiB in memory for classification. */
    private static final class BoundedOutput implements Runnable {
        private final InputStream input; private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
        BoundedOutput(InputStream input) { this.input = input; }
        @Override public void run() {
            byte[] chunk = new byte[4096];
            try { int n; while ((n = input.read(chunk)) >= 0) { synchronized (this) { int retain = Math.min(n, 65536 - kept.size()); if (retain > 0) kept.write(chunk, 0, retain); } } }
            catch (IOException ignored) {}
        }
        // Only failureHint consumes this value; raw output must not enter logs or the interface.
        synchronized String text() { return kept.toString(StandardCharsets.UTF_8); }
    }
    /** Cooperative checkpoint used between CLI, file, and API steps. */
    public void checkCancelled() {
        if (cancelled || Thread.currentThread().isInterrupted()) throw new CancellationException("Sign-in canceled.");
    }
    /** Marks the attempt canceled and stops only the CLI process owned by this attempt. */
    public void cancel() { cancelled = true; addDiagnostic("Sign-in canceled; CLI listener stopped. Browser and saved credentials are kept."); stop(process); }
    /** Also used in finally so success, failure, and timeout all release the callback listener. */
    private static void stop(Process p) {
        if (p == null) return;
        // Stop the CLI's callback server; leave the user's browser and web session alone.
        try { if (p.isAlive()) p.destroyForcibly(); } catch (RuntimeException ignored) {}
    }
}
