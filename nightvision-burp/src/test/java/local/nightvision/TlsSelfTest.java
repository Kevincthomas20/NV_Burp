package local.nightvision;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.Component;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static local.nightvision.SelfTest.*;

/** Real loopback HTTPS regression tests with an ephemeral CA; no external API calls. */
final class TlsSelfTest {
    // Fixture-only values protect disposable local keystores, not a real service or user credential.
    private static final String PASSWORD = "synthetic-test-password";
    private static final String TOKEN = "synthetic-tls-token";
    /** Starts a local HTTPS fixture and tests trust, hostname validation, isolation, and safe errors. */
    static void run() throws Exception {
        Path folder = Files.createTempDirectory("nightvision TLS tests ");
        HttpsServer server = null;
        try {
            // Build a disposable CA/server chain, then serve synthetic API JSON on a random local port.
            certificates(folder);
            Path ca = folder.resolve("root.pem");
            KeyStore keys = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(folder.resolve("server.p12"))) { keys.load(in, PASSWORD.toCharArray()); }
            KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(keys, PASSWORD.toCharArray());
            SSLContext context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), null, null);
            server = HttpsServer.create(new InetSocketAddress(0), 0); server.setHttpsConfigurator(new HttpsConfigurator(context));
            // The handler runs only after TLS succeeds, so counts reveal whether auth reached HTTP.
            AtomicInteger requests = new AtomicInteger(); AtomicBoolean auth = new AtomicBoolean();
            server.createContext("/", exchange -> {
                requests.incrementAndGet(); auth.set(("Token " + TOKEN).equals(exchange.getRequestHeaders().getFirst("Authorization")));
                byte[] body = (exchange.getRequestURI().getPath().contains("/scans/") ? "{\"results\":[],\"next\":null}" : "{\"id\":\"synthetic-user\"}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json"); exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
            }); server.start();
            String origin = "https://localhost:" + server.getAddress().getPort();
            TlsSupport.Options normal = new TlsSupport.Options("", false), trusted = new TlsSupport.Options(ca.toString(), false);
            // Unknown issuer: the handshake must fail before the Authorization header reaches the handler.
            try { new NightVisionClient(origin, TOKEN, normal).currentUser(); throw new AssertionError("Unknown CA must not be trusted"); }
            catch (TlsSupport.Failure e) {
                check(e.getMessage().contains("certificate chain"), "Classify a real untrusted API certificate chain");
                check(e.diagnostics().contains("Java home:") && e.diagnostics().contains("Cause types:") && !e.diagnostics().contains(TOKEN), "TLS diagnostics contain runtime and cause types without credentials");
            }
            check(requests.get() == 0, "Never send Authorization before the TLS peer is trusted");
            check(new NightVisionClient(origin, TOKEN, trusted).currentUser().get("id").getAsString().equals("synthetic-user") && auth.get(), "A selected trusted CA permits the API request with validated hostname");
            check(requests.get() == 1, "Only the verified HTTPS request reaches the server");
            // The certificate covers localhost only; trusting its issuer must not also trust another name.
            try { new NightVisionClient("https://127.0.0.1:" + server.getAddress().getPort(), TOKEN, trusted).currentUser(); throw new AssertionError("Trusted issuer cannot bypass hostname matching"); }
            catch (TlsSupport.Failure e) { check(e.getMessage().contains("hostname"), "Reject the wrong hostname even with the selected trusted CA"); }
            check(requests.get() == 1, "No Authorization request is sent on hostname mismatch");
            // A newly created default client must remain unaffected by the preceding custom-CA client.
            try { new NightVisionClient(origin, TOKEN, normal).currentUser(); throw new AssertionError("Selected trust must stay scoped to that client"); }
            catch (TlsSupport.Failure e) { check(true, "Adding a CA does not modify the JVM's global trust configuration"); }
            check(TlsSupport.httpsParameters().getEndpointIdentificationAlgorithm().equals("HTTPS"), "Explicitly enable HTTPS endpoint identification");
            // File validation and classification must produce useful guidance without echoing file/error text.
            rejects(() -> TlsSupport.build(new TlsSupport.Options(folder.resolve("missing.pem").toString(), false)), "Reject missing CA files with actionable guidance");
            rejects(() -> TlsSupport.build(new TlsSupport.Options(folder.resolve("server.pem").toString(), false)), "Do not silently import a leaf certificate as a company CA");
            Path invalid = folder.resolve("invalid.pem"); Files.writeString(invalid, "synthetic-secret-not-a-certificate");
            try { TlsSupport.build(new TlsSupport.Options(invalid.toString(), false)); throw new AssertionError("Invalid CA data must fail"); }
            catch (TlsSupport.Failure e) { check(!e.diagnostics().contains("synthetic-secret-not-a-certificate"), "Do not echo invalid certificate-file contents in diagnostics"); }
            TlsSupport.Configuration combined = TlsSupport.build(trusted);
            check(combined.report().contains("JVM trusted certificates:") && combined.report().contains("Additional CA certificates loaded: 1") && combined.report().contains("SHA-256"), "Preserve default JVM trust and identify the selected CA by fingerprint");
            SSLHandshakeException expired = new SSLHandshakeException("synthetic-message-secret"); expired.initCause(new CertificateExpiredException("synthetic-certificate-secret"));
            check(TlsSupport.reason(expired).contains("validity dates"), "Distinguish certificate expiry from an unknown issuer");
            SSLHandshakeException protocol = new SSLHandshakeException("Received fatal alert: protocol_version synthetic-secret");
            check(TlsSupport.reason(protocol).contains("TLS negotiation") && !TlsSupport.connectionFailure(protocol, "").diagnostics().contains("synthetic-secret"), "Report protocol problems without raw exception messages");
            SSLHandshakeException unknown = new SSLHandshakeException("synthetic-sensitive-detail");
            check(!TlsSupport.connectionFailure(unknown, "").diagnostics().contains("synthetic-sensitive-detail"), "Generic TLS errors do not expose underlying exception messages");
            // Wrapped write failures must keep both uncertainty and TLS details, without an automatic retry.
            AtomicInteger writes = new AtomicInteger();
            NightVisionClient failedWrite = new NightVisionClient("https://api.example.test", TOKEN, req -> {
                writes.incrementAndGet(); throw TlsSupport.connectionFailure(new SSLHandshakeException("PKIX synthetic-write-secret"), "Configured TLS\n");
            });
            try { failedWrite.markFalsePositive(ISSUE); throw new AssertionError("A TLS-failed update cannot be verified"); }
            catch (IllegalStateException e) {
                check(e.getMessage().contains("not confirmed") && writes.get() == 1, "Keep failed-update uncertainty and do not retry writes on TLS errors");
                String details = TlsSupport.diagnostics(e, normal);
                check(details.contains("TLS result:") && !details.contains("synthetic-write-secret"), "Preserve safe TLS diagnostics through remote-update error wrappers");
            }
            if (!TlsSupport.onWindows()) check(TlsSupport.build(new TlsSupport.Options("", true)).report().contains("unavailable on this OS"), "A non-Windows runtime does not silently assume access to Windows roots");
            testUi(origin, ca);
        } finally {
            // Always stop the server and delete its certificates and private keys after the checks.
            if (server != null) server.stop(0);
            try (var files = Files.walk(folder)) { for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(file); }
        }
    }
    /** Reproduces failed connection, visible TLS diagnostics, CA selection, and successful reconnect. */
    static void testUi(String origin, Path ca) throws Exception {
        Map<String, String> prefs = new HashMap<>(); NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) mock(MontoyaApi.class, prefs, new AtomicReference<Component>())); SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {
            ((JTextField) field(extension, "origin")).setText(origin); ((JPasswordField) field(extension, "token")).setText(TOKEN);
            ((JCheckBox) field(extension, "windowsRoots")).setSelected(false); invoke(extension, "connect");
        }); waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> {
            String report = ((JTextArea) field(extension, "connectionDiagnostics")).getText();
            check(field(extension, "client") == null && report.contains("TLS result:") && report.contains("Java home:") && !report.contains(TOKEN), "A failed UI connection shows safe TLS diagnostics without accepting a session");
            ((JTextField) field(extension, "caFile")).setText(ca.toString()); invoke(extension, "connect");
        }); waitWorker(extension);
        SwingUtilities.invokeAndWait(() -> check(field(extension, "client") != null && ((JLabel) field(extension, "status")).getText().contains("Connected using API token"), "Reconnect with the selected CA recovers the real Swing API flow"));
        check(ca.toString().equals(prefs.get("nightvision.tls.ca.file")) && prefs.values().stream().noneMatch(v -> v.contains(TOKEN)), "Remember the CA file path without persisting the API credential");
    }
    /** Creates short-lived local keys and signs a localhost-only leaf using the disposable test CA. */
    static void certificates(Path folder) throws Exception {
        String root = folder.resolve("root.p12").toString(), server = folder.resolve("server.p12").toString();
        keytool("-genkeypair", "-alias", "root", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=Synthetic NightVision Test CA", "-ext", "BC=ca:true,pathlen:1", "-ext", "KU=keyCertSign,cRLSign", "-keystore", root, "-storetype", "PKCS12");
        keytool("-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=localhost", "-keystore", server, "-storetype", "PKCS12");
        keytool("-certreq", "-alias", "server", "-file", folder.resolve("server.csr").toString(), "-keystore", server);
        keytool("-gencert", "-alias", "root", "-infile", folder.resolve("server.csr").toString(), "-outfile", folder.resolve("server.pem").toString(), "-rfc", "-ext", "SAN=dns:localhost", "-ext", "KU=digitalSignature,keyEncipherment", "-ext", "EKU=serverAuth", "-validity", "2", "-keystore", root);
        keytool("-exportcert", "-alias", "root", "-rfc", "-file", folder.resolve("root.pem").toString(), "-keystore", root);
        keytool("-importcert", "-alias", "root", "-file", folder.resolve("root.pem").toString(), "-noprompt", "-keystore", server);
        keytool("-importcert", "-alias", "server", "-file", folder.resolve("server.pem").toString(), "-noprompt", "-keystore", server);
    }
    /** Runs the JDK certificate utility with a deadline and discards routine fixture-generation output. */
    static void keytool(String... args) throws Exception {
        String exe = TlsSupport.onWindows() ? "keytool.exe" : "keytool";
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", exe).toString()));
        Collections.addAll(command, args); Collections.addAll(command, "-storepass", PASSWORD, "-keypass", PASSWORD);
        Process process = new ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("Synthetic certificate generation timed out"); }
        if (process.exitValue() != 0) throw new AssertionError("Synthetic keytool fixture failed (" + args[0] + ")");
    }
}
