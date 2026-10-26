package local.nightvision;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Builds certificate trust for this extension's API clients only. JVM roots remain
 * available; optional Windows stores and a selected CA file add trusted issuers.
 * Certificate validation and HTTPS hostname verification stay enabled throughout.
 */
public final class TlsSupport {
    private TlsSupport() {}
    /** Immutable UI settings captured when connecting; stores a path rather than certificate contents. */
    public record Options(String caFile, boolean windowsRoots) {
        public Options { caFile = caFile == null ? "" : caFile.trim(); }
        public static Options defaults() { return new Options("", onWindows()); }
    }
    /** Pairs the usable SSLContext with sanitized details about the trust sources it loaded. */
    public record Configuration(SSLContext context, String report) {}
    public static boolean onWindows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows"); }
    /** Reports runtime and selected paths without reading or displaying trust-store passwords. */
    public static String runtimeReport(Options options) {
        return "Java version: " + System.getProperty("java.version", "unknown")
            + "\nJava home: " + System.getProperty("java.home", "unknown")
            + "\nOS: " + System.getProperty("os.name", "unknown")
            + "\nJVM trust store: " + System.getProperty("javax.net.ssl.trustStore", "default JVM trust store")
            + "\nWindows roots requested: " + options.windowsRoots()
            + "\nAdditional CA file: " + (options.caFile().isBlank() ? "none" : options.caFile())
            + "\nHTTPS hostname verification: enabled\n";
    }
    /** Builds a private context without changing global JVM, Burp, browser, or CLI trust settings. */
    public static Configuration build(Options options) {
        StringBuilder report = new StringBuilder(runtimeReport(options));
        try {
            List<X509ExtendedTrustManager> managers = new ArrayList<>();
            // A null KeyStore asks Java to use its configured/default trust store.
            X509ExtendedTrustManager jvm = manager(null); managers.add(jvm);
            report.append("JVM trusted certificates: ").append(jvm.getAcceptedIssuers().length).append('\n');
            if (options.windowsRoots()) {
                if (!onWindows()) report.append("Windows certificate stores unavailable on this OS.\n");
                // Try current-user and machine roots separately; availability depends on the Java runtime.
                else for (String type : List.of("Windows-ROOT", "Windows-ROOT-LOCALMACHINE")) {
                    try {
                        KeyStore roots = KeyStore.getInstance(type); roots.load(null, null);
                        managers.add(manager(roots)); report.append(type).append(" loaded: ").append(roots.size()).append(" certificates.\n");
                    } catch (GeneralSecurityException | IOException e) {
                        // An unavailable native store does not remove working JVM trust or the CA-file option.
                        report.append(type).append(" unavailable (").append(e.getClass().getSimpleName()).append("). Use an additional CA file if needed.\n");
                    }
                }
            }
            if (!options.caFile().isBlank()) {
                Path path;
                try { path = Path.of(options.caFile()).toAbsolutePath().normalize(); }
                catch (InvalidPathException e) { throw new IllegalArgumentException("Select a valid CA certificate file path."); }
                final byte[] bytes;
                // Bound reads before parsing a PEM bundle or DER certificate selected by the analyst.
                try (InputStream in = Files.newInputStream(path)) { bytes = in.readNBytes(2 * 1024 * 1024 + 1); }
                if (bytes.length > 2 * 1024 * 1024) throw new IllegalArgumentException("CA certificate file exceeds 2 MiB.");
                var certs = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bytes));
                if (certs.isEmpty() || certs.size() > 32) throw new IllegalArgumentException("Select a PEM or DER file containing 1–32 trusted CA certificates.");
                KeyStore extra = KeyStore.getInstance(KeyStore.getDefaultType()); extra.load(null, null);
                int index = 0;
                for (var cert : certs) {
                    // Require current signing CAs; a downloaded server leaf is not a replacement trust anchor.
                    if (!(cert instanceof X509Certificate ca) || ca.getBasicConstraints() < 0)
                        throw new IllegalArgumentException("Select your trusted issuer/root CA certificate, rather than the server's leaf certificate.");
                    ca.checkValidity(); boolean[] usage = ca.getKeyUsage();
                    if (usage != null && (usage.length <= 5 || !usage[5])) throw new IllegalArgumentException("The selected CA certificate does not permit certificate signing.");
                    extra.setCertificateEntry("ca-" + index++, ca);
                    // Fingerprints identify public certificates without dumping their full contents.
                    report.append("Additional CA SHA-256: ").append(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(ca.getEncoded()))).append('\n');
                }
                managers.add(manager(extra)); report.append("Additional CA certificates loaded: ").append(index).append('\n');
            }
            SSLContext context = SSLContext.getInstance("TLS");
            // One composite manager supplies the union of trust sources; no client certificate keys are added.
            context.init(null, new TrustManager[]{new CombinedTrust(managers)}, null);
            return new Configuration(context, report.toString());
        } catch (IOException e) {
            throw new Failure("Could not read the selected CA certificate file. Check its path and access, then reconnect.", report.toString(), e);
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new Failure("The selected CA certificate is outside its validity dates. Obtain a current CA certificate from your IT team.", report.toString(), e);
        } catch (GeneralSecurityException e) {
            throw new Failure("Could not initialize API certificate trust. Check the CA file format and Java trust-store configuration.", report.toString(), e);
        } catch (IllegalArgumentException e) {
            throw new Failure(e.getMessage(), report.toString(), e);
        }
    }
    /** Uses extended managers so socket/engine-aware validation can retain hostname checks. */
    private static X509ExtendedTrustManager manager(KeyStore store) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(store);
        for (TrustManager tm : factory.getTrustManagers()) if (tm instanceof X509ExtendedTrustManager extended) return extended;
        throw new GeneralSecurityException("No extended X509 trust manager");
    }
    /** Explicitly requests HTTPS endpoint identification from the Java HTTP client. */
    public static SSLParameters httpsParameters() {
        SSLParameters parameters = new SSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS"); return parameters;
    }
    /** Converts a transport TLS failure into fixed user guidance plus sanitized diagnostics. */
    public static Failure connectionFailure(SSLException error, String report) {
        return new Failure(reason(error) + " See Connection diagnostics.", report, error);
    }
    /** Inspects exception details internally, returning only a fixed classification message. */
    static String reason(Throwable failure) {
        List<Throwable> causes = causes(failure);
        String text = causes.stream().map(t -> Objects.toString(t.getMessage(), "")).reduce("", (a, b) -> a + " " + b).toLowerCase(Locale.ROOT);
        // Prefer specific validity/name failures over generic chain or handshake errors.
        if (causes.stream().anyMatch(t -> t instanceof CertificateExpiredException || t instanceof CertificateNotYetValidException))
            return "The API certificate is outside its validity dates. Check the system clock and have the certificate or inspecting gateway checked.";
        if (text.contains("no subject alternative") || text.contains("no name matching") || text.contains("hostname") || text.contains("subject alternative names"))
            return "The API certificate does not match the requested hostname. Check the API origin and your network's TLS gateway.";
        if (text.contains("pkix") || text.contains("certification path") || text.contains("trust anchor") || text.contains("unable to find valid"))
            return "Java could not validate the API certificate chain. Use trusted Windows roots or select your IT-provided company CA certificate, then reconnect.";
        if (text.contains("protocol_version") || text.contains("handshake_failure") || text.contains("no appropriate protocol") || text.contains("cipher"))
            return "TLS negotiation with the API failed. Check the Java/Burp version and your network's TLS gateway.";
        return "The API TLS handshake failed. The browser and CLI may use a different certificate store from Java.";
    }
    /** Walks causes and suppressed trust-manager failures with cycle detection and a size bound. */
    private static List<Throwable> causes(Throwable error) {
        List<Throwable> out = new ArrayList<>(); Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<Throwable> pending = new ArrayDeque<>(); if (error != null) pending.add(error);
        while (!pending.isEmpty() && out.size() < 12) {
            Throwable t = pending.remove(); if (!seen.add(t)) continue; out.add(t);
            if (t.getCause() != null) pending.add(t.getCause());
            Collections.addAll(pending, t.getSuppressed());
        }
        return out;
    }
    /** Finds TLS details even when a remote-update error wraps the original handshake failure. */
    public static String diagnostics(Throwable error, Options options) {
        for (Throwable t : causes(error)) if (t instanceof Failure failure) return failure.diagnostics();
        for (Throwable t : causes(error)) if (t instanceof SSLException ssl) return connectionFailure(ssl, runtimeReport(options)).diagnostics();
        return "";
    }
    /** Keeps the original cause for classification while exposing only safe report text to the UI. */
    public static final class Failure extends IllegalStateException {
        private final String report;
        Failure(String message, String report, Throwable cause) { super(message, cause); this.report = report; }
        /** Emits cause class names, not arbitrary exception messages that could contain sensitive data. */
        public String diagnostics() {
            return report + "TLS result: " + getMessage() + "\nCause types: "
                + String.join(" → ", causes(getCause()).stream().map(t -> t.getClass().getSimpleName()).toList()) + "\nRaw exception messages are omitted.\n";
        }
    }
    /** Accepts a peer only when at least one configured source completes its normal validation. */
    private static final class CombinedTrust extends X509ExtendedTrustManager {
        private final List<X509ExtendedTrustManager> managers;
        CombinedTrust(List<X509ExtendedTrustManager> managers) { this.managers = List.copyOf(managers); }
        @FunctionalInterface private interface Check { void run(X509ExtendedTrustManager manager) throws CertificateException; }
        /** Tries each source; if all reject, preserves their failures for internal classification. */
        private void accepted(Check check) throws CertificateException {
            List<CertificateException> errors = new ArrayList<>();
            for (X509ExtendedTrustManager tm : managers) try { check.run(tm); return; } catch (CertificateException e) { errors.add(e); }
            if (errors.isEmpty()) throw new CertificateException("No trust managers configured");
            CertificateException failure = errors.get(errors.size() - 1);
            for (CertificateException other : errors) if (other != failure) failure.addSuppressed(other);
            throw failure;
        }
        // Forward every overload with its original socket/engine context. Dropping that context
        // could discard the endpoint-identification checks requested by the HTTP client.
        @Override public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { accepted(tm -> tm.checkServerTrusted(c, a)); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { accepted(tm -> tm.checkClientTrusted(c, a)); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { accepted(tm -> tm.checkServerTrusted(c, a, s)); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { accepted(tm -> tm.checkClientTrusted(c, a, s)); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { accepted(tm -> tm.checkServerTrusted(c, a, e)); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { accepted(tm -> tm.checkClientTrusted(c, a, e)); }
        // Advertise the combined issuer set instead of hiding issuers from any configured source.
        @Override public X509Certificate[] getAcceptedIssuers() { return managers.stream().flatMap(tm -> Arrays.stream(tm.getAcceptedIssuers())).distinct().toArray(X509Certificate[]::new); }
    }
}
