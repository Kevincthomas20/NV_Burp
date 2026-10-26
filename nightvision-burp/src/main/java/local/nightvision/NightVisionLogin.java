package local.nightvision;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Delegates interactive authentication to the official CLI; never receives passwords. */
public final class NightVisionLogin {
    static final String API_URL = NightVisionClient.DEFAULT_ORIGIN + "/api/v1/";
    static final int MAX_TOKEN_BYTES = 16 * 1024;
    @FunctionalInterface interface Launcher { Process start(ProcessBuilder builder) throws IOException; }
    private final List<Path> tokenFiles;
    private final Duration timeout;
    private final Launcher launcher;
    private volatile Process process;
    private volatile boolean cancelled;
    private final StringBuilder diagnostics = new StringBuilder("NightVision login diagnostics (credential contents and raw CLI output are omitted).\n");

    public NightVisionLogin() {
        this(SavedLogin.defaultCandidates(), Duration.ofMinutes(5), ProcessBuilder::start);
    }
    NightVisionLogin(Path tokenFile, Duration timeout, Launcher launcher) {
        this(SavedLogin.candidates(tokenFile), timeout, launcher);
    }
    NightVisionLogin(List<Path> tokenFiles, Duration timeout, Launcher launcher) {
        this.tokenFiles = List.copyOf(tokenFiles); this.timeout = timeout; this.launcher = launcher;
    }
    public static void requireProductionOrigin(String base) {
        URI u = NightVisionClient.apiOrigin(base);
        if (!"api.nightvision.net".equalsIgnoreCase(u.getHost()) || !(u.getPort() == -1 || u.getPort() == 443))
            throw new IllegalArgumentException("SSO and saved CLI login connect to https://api.nightvision.net. Use a manual API token for other origins.");
    }
    public String signIn(String executable) throws Exception {
        checkCancelled();
        String path = executable.trim();
        if (path.isEmpty() || path.indexOf('\0') >= 0 || path.indexOf('\r') >= 0 || path.indexOf('\n') >= 0)
            throw new IllegalArgumentException("Select the NightVision CLI executable, without command arguments.");
        // The parent bounds login time, including for older CLIs without a --timeout flag.
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
        BoundedOutput output = new BoundedOutput(started.getInputStream());
        Thread drain = new Thread(output, "nightvision-login-output"); drain.setDaemon(true); drain.start();
        try {
            started.getOutputStream().close();
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
            return savedToken();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); cancelled = true;
            throw new CancellationException("Sign-in canceled.");
        } finally { stop(started); try { started.getInputStream().close(); } catch (IOException ignored) {} process = null; }
    }
    public String savedToken() {
        return savedToken("");
    }
    public String savedToken(String selectedFile) {
        checkCancelled();
        final List<Path> paths;
        try { paths = selectedFile.isBlank() ? tokenFiles : List.of(Path.of(selectedFile.trim()).toAbsolutePath().normalize()); }
        catch (InvalidPathException e) { throw new IllegalArgumentException("Select a valid saved-login file path."); }
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
    public synchronized String diagnostics() { return diagnostics.toString(); }
    private synchronized void addDiagnostic(String line) { diagnostics.append(line).append('\n'); }
    static String failureHint(String output) {
        String text = output.toLowerCase(Locale.ROOT);
        if (text.contains("unknown flag") || text.contains("flag provided but not defined")) return "The CLI rejected a command-line option. Update the CLI or complete nightvision login in a terminal, then use the saved login.";
        if (text.contains("address already in use") || text.contains("bind: address")) return "The CLI login callback port is busy. Finish or close another CLI login, then retry.";
        if (text.contains("permission denied") || text.contains("access is denied")) return "The CLI reported a file or process permission problem. Run terminal login as the same desktop user as Burp.";
        if (text.contains("browser") || text.contains("xdg-open")) return "The CLI could not complete the browser flow. Run nightvision login in a desktop terminal, then click Use saved login.";
        return "Run nightvision login in a terminal, complete SSO, then click Use saved login. Raw CLI output is omitted to protect credentials.";
    }
    private static final class BoundedOutput implements Runnable {
        private final InputStream input; private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
        BoundedOutput(InputStream input) { this.input = input; }
        @Override public void run() {
            byte[] chunk = new byte[4096];
            try { int n; while ((n = input.read(chunk)) >= 0) { synchronized (this) { int retain = Math.min(n, 65536 - kept.size()); if (retain > 0) kept.write(chunk, 0, retain); } } }
            catch (IOException ignored) {}
        }
        synchronized String text() { return kept.toString(StandardCharsets.UTF_8); }
    }
    public void checkCancelled() {
        if (cancelled || Thread.currentThread().isInterrupted()) throw new CancellationException("Sign-in canceled.");
    }
    public void cancel() { cancelled = true; addDiagnostic("Sign-in canceled; CLI listener stopped. Browser and saved credentials are kept."); stop(process); }
    private static void stop(Process p) {
        if (p == null) return;
        // Stop the CLI's callback server; leave the user's browser and web session alone.
        try { if (p.isAlive()) p.destroyForcibly(); } catch (RuntimeException ignored) {}
    }
}
