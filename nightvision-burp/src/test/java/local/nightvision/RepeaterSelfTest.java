package local.nightvision;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import javax.swing.*;
import java.awt.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import static local.nightvision.SelfTest.*;

/** Clicks the registered Swing action and exercises Montoya's real static factory entry points. */
final class RepeaterSelfTest {
    private enum Failure { NONE, SERVICE, REQUEST, HANDOFF, LINKAGE, FOCUS, NAMED_UNAVAILABLE }
    private record Sent(HttpRequest request, String caption) {}

    // These public interface shapes model lookup differences without exposing private host classes.
    public interface BasicApi { BasicRepeater repeater(); }
    public interface BasicRepeater { void sendToRepeater(HttpRequest request); }
    public interface ReturningApi { ReturningRepeater repeater(); }
    public interface ReturningRepeater { Object sendToRepeater(HttpRequest request); }
    public interface NamedApi { NamedRepeater repeater(); }
    public interface NamedRepeater { void sendToRepeater(HttpRequest request, String name); }
    public interface BothApi { BothRepeater repeater(); }
    public interface BothRepeater { void sendToRepeater(HttpRequest request); void sendToRepeater(HttpRequest request, String name); }
    public interface MissingApi { Object repeater(); }

    /** The same compiled runner can also be started with an older real Montoya JAR on its classpath. */
    public static void main(String[] args) throws Exception {
        run(); System.out.println("PASS: " + checks + " Repeater button/API compatibility checks.");
    }

    static void run() throws Exception {
        // Only the build-time test installs a synthetic Montoya factory. Production uses Burp's factory.
        MontoyaObjectFactory previous = ObjectFactoryLocator.FACTORY;
        AtomicReference<Failure> failure = new AtomicReference<>(Failure.NONE);
        List<Sent> sent = new ArrayList<>(); List<String> errors = new ArrayList<>();
        Map<String, String> preferences = new HashMap<>();
        AtomicReference<Component> registered = new AtomicReference<>();
        ObjectFactoryLocator.FACTORY = factory(failure);
        NightVisionExtension extension = new NightVisionExtension();
        try {
            extension.initialize((MontoyaApi) host(MontoyaApi.class, preferences, registered, sent, errors, failure));
            SwingUtilities.invokeAndWait(() -> {});
            SwingUtilities.invokeAndWait(() -> {
                invoke(extension, "demo");
                Component panel = registered.get();
                JTabbedPane suite = new JTabbedPane();
                suite.addTab("Proxy", new JPanel()); suite.addTab("Repeater", new JPanel()); suite.addTab("NightVision", panel);
                suite.setSelectedComponent(panel);
                JButton button = findButton(panel);
                check(button != null && button.isEnabled(), "Registered Open in Repeater button is enabled after loading a finding");

                JTextArea request = (JTextArea) field(extension, "request");
                JTextField destination = (JTextField) field(extension, "destination");
                // A destination override changes the service, without silently rewriting Host/path/body.
                String edited = "POST /verify?q=%252F HTTP/1.1\nHost: captured.example.invalid\nX-Review: changed\n\nfirst\nsecond";
                request.setText(edited); destination.setText("https://override.example.invalid:8443/unused");
                ((JTextArea) field(extension, "notes")).setText("unsaved review notes");
                ((JComboBox<?>) field(extension, "verdict")).setSelectedItem("Needs review");
                failure.set(Failure.NAMED_UNAVAILABLE); button.doClick(); failure.set(Failure.NONE);
                check(sent.size() == 1, "Actual button hands one request to Burp Repeater");
                Sent first = sent.get(0); HttpService service = first.request().httpService();
                check(service.host().equals("override.example.invalid") && service.port() == 8443 && service.secure(), "Repeater uses the explicit destination's host, port, and TLS");
                check(first.request().toString().equals(Finding.prepareRequest(edited)), "Repeater receives edited headers/path and body with only header newline normalization");
                check(first.caption() == null, "Handoff works without the named-tab overload and uses Burp's default tab name");
                check(suite.getSelectedIndex() == 1, "Open in Repeater selects the docked Repeater tool tab");
                check(feedback(extension).contains("Burp default tab name"), "Visible handoff receipt truthfully explains the default Repeater tab name");
                check(preferences.isEmpty() && ((JTextArea) field(extension, "notes")).getText().equals("unsaved review notes") && ((JComboBox<?>) field(extension, "verdict")).getSelectedItem().equals("Needs review"), "Handoff preserves unsaved notes/verdict and writes no preferences");

                // Missing/invalid inputs fail visibly and do not create a tab or issue traffic.
                for (String bad : List.of("", "body only")) {
                    request.setText(bad); button.doClick();
                    check(sent.size() == 1 && feedback(extension).startsWith("Error:"), "Invalid request is rejected beside the Repeater button");
                }
                request.setText(edited); destination.setText("file:///tmp/synthetic"); button.doClick();
                check(sent.size() == 1 && feedback(extension).contains("HTTP(S)"), "Invalid destination has actionable visible feedback without a handoff");
                ((JTable) field(extension, "table")).clearSelection(); button.doClick();
                check(sent.size() == 1 && feedback(extension).contains("Select a finding"), "A missing finding is reported at the action itself");
                ((JTable) field(extension, "table")).setRowSelectionInterval(0, 0);
                request.setText(edited); destination.setText("http://plain.example.invalid/");
                button.doClick();
                check(sent.size() == 2 && sent.get(1).request().httpService().port() == 80 && !sent.get(1).request().httpService().secure(), "Plain HTTP uses port 80 and no TLS by default");
                destination.setText("https://secure.example.invalid/"); button.doClick();
                check(sent.size() == 3 && sent.get(2).request().httpService().port() == 443 && sent.get(2).request().httpService().secure(), "HTTPS uses port 443 by default");

                // The old RuntimeException-only catch let linkage errors escape the Swing listener.
                for (Failure mode : List.of(Failure.SERVICE, Failure.REQUEST, Failure.HANDOFF, Failure.LINKAGE)) {
                    failure.set(mode); suite.setSelectedComponent(panel); int before = sent.size();
                    button.doClick();
                    check(sent.size() == before && feedback(extension).startsWith("Error:") && !feedback(extension).contains("synthetic-secret"), "Burp " + mode + " failure is caught with safe visible feedback");
                    check(suite.getSelectedComponent() == panel, "Failed " + mode + " handoff does not switch tools or retry");
                }
                check(errors.size() == 4 && errors.stream().noneMatch(s -> s.contains("synthetic-secret")) && errors.stream().anyMatch(s -> s.contains("NoSuchMethodError")), "Extension error log records failure stage/type without raw exception/request text");

                // Focus is a best effort after a successful send, never a reason to duplicate the request.
                failure.set(Failure.NONE); suite.remove(panel); button.doClick();
                check(sent.size() == 4 && feedback(extension).contains("select Repeater"), "Detached/custom UI still hands off once and explains how to find the tab");
                JTabbedPane failingFocus = new JTabbedPane() {
                    @Override public void setSelectedIndex(int index) {
                        if (failure.get() == Failure.FOCUS && index == 0) throw new IllegalStateException("synthetic-secret");
                        super.setSelectedIndex(index);
                    }
                };
                failingFocus.addTab("Repeater", new JPanel()); failingFocus.addTab("NightVision", panel); failingFocus.setSelectedComponent(panel);
                failure.set(Failure.FOCUS); button.doClick();
                check(sent.size() == 5 && !feedback(extension).startsWith("Error:") && feedback(extension).contains("select Repeater"), "A focus failure retains the truthful successful handoff receipt");
                failure.set(Failure.NONE); setField(extension, "unloaded", true); button.doClick();
                check(sent.size() == 5 && feedback(extension).contains("unloaded"), "A retained button cannot use the API after extension unload");
            });
            compatibilityShapes();
        } finally {
            ObjectFactoryLocator.FACTORY = previous;
            EvidenceController evidence = (EvidenceController) field(extension, "evidence");
            if (evidence != null) SwingUtilities.invokeAndWait(evidence::close);
        }
    }

    private static String feedback(NightVisionExtension extension) { return ((JLabel) field(extension, "repeaterStatus")).getText(); }
    private static JButton findButton(Component c) {
        if (c instanceof JButton b && b.getText().equals("Open in Repeater")) return b;
        if (c instanceof Container parent) for (Component child : parent.getComponents()) { JButton found = findButton(child); if (found != null) return found; }
        return null;
    }
    private static MontoyaObjectFactory factory(AtomicReference<Failure> failure) {
        return proxy(MontoyaObjectFactory.class, (method, args) -> {
            if (method.getName().equals("httpService")) {
                if (failure.get() == Failure.SERVICE) throw new IllegalStateException("synthetic-secret");
                check(args.length == 3, "Handoff uses Montoya's explicit host/port/TLS service factory");
                return proxy(HttpService.class, (m, a) -> switch (m.getName()) { case "host" -> args[0]; case "port" -> args[1]; case "secure" -> args[2]; default -> null; });
            }
            if (method.getName().equals("httpRequest")) {
                if (failure.get() == Failure.REQUEST) throw new IllegalStateException("synthetic-secret");
                if (failure.get() == Failure.LINKAGE) throw new NoSuchMethodError("synthetic-secret");
                check(args.length == 2 && args[0] instanceof HttpService && args[1] instanceof String, "Actual static request factory receives the explicit service and edited HTTP text");
                return proxy(HttpRequest.class, (m, a) -> switch (m.getName()) { case "httpService" -> args[0]; case "toString" -> args[1]; default -> null; });
            }
            throw new AssertionError("Unexpected Montoya factory call: " + method.getName());
        });
    }
    private static Object host(Class<?> type, Map<String, String> preferences, AtomicReference<Component> registered, List<Sent> sent, List<String> errors, AtomicReference<Failure> failure) {
        return proxy(type, (method, args) -> {
            if (method.getName().equals("sendRequest")) throw new AssertionError("Opening Repeater must never send network traffic");
            if (method.getName().equals("sendToRepeater")) {
                if (failure.get() == Failure.HANDOFF) throw new IllegalStateException("synthetic-secret");
                if (failure.get() == Failure.NAMED_UNAVAILABLE && args.length == 2)
                    throw new NoSuchMethodError("'void burp.api.montoya.repeater.Repeater.sendToRepeater(burp.api.montoya.http.message.requests.HttpRequest, java.lang.String)'");
                sent.add(new Sent((HttpRequest) args[0], args.length == 2 ? (String) args[1] : null)); return null;
            }
            if (method.getName().equals("logToError")) { errors.add((String) args[0]); return null; }
            if (method.getName().equals("registerSuiteTab")) { registered.set((Component) args[1]); return null; }
            if (method.getName().equals("getString")) return preferences.get((String) args[0]);
            if (method.getName().equals("setString")) { preferences.put((String) args[0], (String) args[1]); return null; }
            if (method.getReturnType().isInterface()) return host(method.getReturnType(), preferences, registered, sent, errors, failure);
            return null;
        });
    }
    /** Check return descriptors, overload lookup, inaccessible implementations, and no retry after invocation. */
    private static void compatibilityShapes() throws Exception {
        HttpRequest request = proxy(HttpRequest.class, (m, a) -> null);
        AtomicInteger basicCalls = new AtomicInteger(), namedCalls = new AtomicInteger();
        BasicApi basic = new PrivateBasicApi(basicCalls);
        RepeaterBridge.Resolved plain = RepeaterBridge.resolve(BasicApi.class);
        plain.send(basic, request, "unused caption");
        check(basicCalls.get() == 1 && !plain.named(), "A public basic interface can invoke a private Burp-style implementation exactly once");

        ReturningApi returning = () -> r -> { basicCalls.incrementAndGet(); return new Object(); };
        RepeaterBridge.Resolved changedReturn = RepeaterBridge.resolve(ReturningApi.class);
        changedReturn.send(returning, request, "unused caption");
        check(basicCalls.get() == 2 && changedReturn.description().contains("java.lang.Object"), "Runtime lookup tolerates a non-void handoff return descriptor without compile-time binding");

        NamedApi named = () -> (r, name) -> { check(r == request && name.equals("NV explicit"), "A named-only API receives the supplied request/caption"); namedCalls.incrementAndGet(); };
        RepeaterBridge.Resolved namedOnly = RepeaterBridge.resolve(NamedApi.class);
        namedOnly.send(named, request, "NV explicit");
        check(namedOnly.named() && namedCalls.get() == 1, "Named-only compatibility is selected before any invocation");
        rejects(() -> RepeaterBridge.resolve(MissingApi.class), "Missing Repeater methods must fail during preflight");

        BothApi broken = () -> proxy(BothRepeater.class, (method, args) -> {
            if (args.length == 1) { basicCalls.incrementAndGet(); throw new NoSuchMethodError("'void burp.api.montoya.repeater.Repeater.syntheticMissing()' synthetic-secret"); }
            namedCalls.incrementAndGet(); return null;
        });
        int before = basicCalls.get();
        try { RepeaterBridge.resolve(BothApi.class).send(broken, request, "unused caption"); throw new AssertionError("Underlying linkage failure must propagate"); }
        catch (NoSuchMethodError expected) {
            check(basicCalls.get() == before + 1 && namedCalls.get() == 1, "An invoked method's linkage failure is unwrapped without retrying another overload");
            String signature = RepeaterBridge.missingMember(expected);
            check(signature.equals("void burp.api.montoya.repeater.Repeater.syntheticMissing()") && !signature.contains("synthetic-secret"), "Missing-member diagnostics extract only the JVM-style Montoya signature");
        }
        check(RepeaterBridge.missingMember(new NoSuchMethodError("synthetic-secret")).isEmpty()
            && RepeaterBridge.missingMember(new IllegalStateException("synthetic-secret")).isEmpty()
            && RepeaterBridge.missingMember(new NoSuchMethodError("x".repeat(3000))).isEmpty(), "Arbitrary, unrelated, or oversized exception text is omitted from compatibility diagnostics");
        check(RepeaterBridge.missingMember(new NoSuchMethodError("'void burp.api.montoya.repeater.Repeater.sendToRepeater(burp.api.montoya.http.message.requests.HttpRequest, java.lang.String)' synthetic-secret"))
            .equals("void burp.api.montoya.repeater.Repeater.sendToRepeater(burp.api.montoya.http.message.requests.HttpRequest, java.lang.String)"), "A missing named handoff signature is reported without surrounding exception content");
        AtomicReference<String> versionText = new AtomicReference<>("Burp Suite Professional 2025.12.3-12345");
        Version version = proxy(Version.class, (m, a) -> {
            if (List.of("major", "minor", "build").contains(m.getName())) throw new AssertionError("Do not use version accessors marked for removal");
            return m.getName().equals("toString") ? versionText.get() : null;
        });
        BurpSuite suite = proxy(BurpSuite.class, (m, a) -> m.getName().equals("version") ? version : null);
        MontoyaApi host = proxy(MontoyaApi.class, (m, a) -> m.getName().equals("burpSuite") ? suite : null);
        check(RepeaterBridge.hostVersion(host).equals(versionText.get()), "Compatibility diagnostics include bounded Burp product-version text without deprecated accessors");
        versionText.set("synthetic-secret");
        check(RepeaterBridge.hostVersion(host).equals("unavailable"), "Non-version text from a host cannot leak through version diagnostics");
        check(RepeaterBridge.hostVersion(proxy(MontoyaApi.class, (m, a) -> { throw new NoSuchMethodError("synthetic-secret"); })).equals("unavailable"), "Missing optional product-version API cannot obscure the original handoff failure");
    }
    private static final class PrivateBasicApi implements BasicApi {
        private final AtomicInteger calls;
        PrivateBasicApi(AtomicInteger calls) { this.calls = calls; }
        @Override public BasicRepeater repeater() { return request -> calls.incrementAndGet(); }
    }
    private interface Call { Object apply(Method method, Object[] args); }
    private static <T> T proxy(Class<T> type, Call call) { return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> call.apply(m, a))); }
}
