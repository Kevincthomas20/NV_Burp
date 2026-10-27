package local.nightvision;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.tools.ToolProvider;
import static local.nightvision.SelfTest.*;

/** Runs the compiled capture adapter against isolated synthetic editor API return descriptors. */
final class EvidenceCompatibilitySelfTest {
    private static final String EDITOR = "burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse";
    private static final String CAPTURE = "local.nightvision.EvidenceCapture";

    public static void main(String[] args) throws Exception {
        run(); System.out.println("PASS: " + checks + " evidence editor/API compatibility checks.");
    }

    static void run() throws Exception {
        Path folder = Files.createTempDirectory("nightvision-editor-api-");
        try {
            HttpRequestResponse chosen = exchange(), unrelated = exchange();
            // The v0.5.2 direct interface invocation fails with the user's exact NoSuchMethodError
            // when the editor's runtime return descriptor differs. Keep the real class/method names.
            check(select(folder.resolve("object"), "Object requestResponse();", chosen, unrelated).orElseThrow() == chosen,
                "Compiled capture adapter reads an Object-returning runtime editor accessor without NoSuchMethodError");
            check(select(folder.resolve("early"), "Object getRequestResponse();", chosen, unrelated).orElseThrow() == chosen,
                "Compiled capture adapter selects the documented pre-1.0 getRequestResponse() name");
            check(select(folder.resolve("optional"), "java.util.Optional<?> requestResponse();", Optional.of(chosen), unrelated).orElseThrow() == chosen,
                "Runtime editor access supports an Optional-returning descriptor without choosing a different table row");
            check(select(folder.resolve("empty"), "java.util.Optional<?> requestResponse();", Optional.empty(), unrelated).isEmpty(),
                "An explicitly empty editor exchange does not fall back to an unrelated selected row");
            check(select(folder.resolve("null"), "Object requestResponse();", null, unrelated).isEmpty(),
                "A null editor exchange does not redirect evidence to a different table selection");
            rejects(() -> select(folder.resolve("unsupported"), "Object requestResponse();", "synthetic-secret", unrelated),
                "An unsupported editor return value must fail without guessing a message");
            rejects(() -> select(folder.resolve("missing"), "", chosen, unrelated),
                "A genuinely missing editor accessor must fail without substituting a table row");
            menuFailures(folder.resolve("must-not-be-created"));
        } finally {
            try (var files = Files.walk(folder)) { for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path); }
        }
    }

    /** Exercise the actual registered provider: callback failures must remain visible and never save. */
    private static void menuFailures(Path evidenceFolder) throws Exception {
        List<String> errors = new ArrayList<>(), notices = new ArrayList<>();
        AtomicReference<ContextMenuItemsProvider> registered = new AtomicReference<>();
        NightVisionExtension extension = new NightVisionExtension();
        extension.initialize((MontoyaApi) host(MontoyaApi.class, evidenceFolder, errors, registered));
        AtomicReference<EvidenceController> controller = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                invoke(extension, "demo");
                EvidenceController evidence = (EvidenceController) field(extension, "evidence"); controller.set(evidence);
                evidence.notice = notices::add;
                evidence.prompt = (capture, targets, selected, folder) -> { throw new AssertionError("Unreadable exchanges must never reach the save prompt"); };
                ContextMenuItemsProvider provider = registered.get();
                check(provider == evidence, "Compatibility checks use the context-menu provider registered by the real extension");
                ContextMenuEvent broken = event(null, new NoSuchMethodError("'burp.api.montoya.http.message.HttpRequestResponse burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.requestResponse()' synthetic-secret"));
                for (int i = 0; i < 3; i++) {
                    JMenuItem action = action(provider, broken);
                    check(action.isEnabled() && action.getText().equals("Attach retest evidence to NightVision…"), "An editor linkage error retains a visible diagnostic action in the menu");
                    action.doClick();
                }
                check(errors.size() == 1 && errors.get(0).contains("MessageEditorHttpRequestResponse.requestResponse()"), "Repeated right-clicks log the exact safe missing-member signature only once");
                check(notices.size() == 3 && notices.stream().allMatch(s -> s.contains("No evidence was saved") && !s.contains("synthetic-secret")), "Diagnostic actions explain the failure without opening a capture or exposing raw error text");

                action(provider, event(null, new IllegalStateException("synthetic-secret"))).doClick();
                check(errors.size() == 2 && notices.get(3).contains("IllegalStateException"), "Runtime callback failures are visible rather than silently removing the menu");
                HttpRequestResponse brokenAvailability = exchange((method, args) -> { throw new NoSuchMethodError("'boolean burp.api.montoya.http.message.HttpRequestResponse.hasResponse()' synthetic-secret"); });
                action(provider, event(brokenAvailability, null)).doClick();
                check(errors.size() == 3 && errors.get(2).contains("hasResponse()"), "Response-availability checks are covered by the menu compatibility guard");

                HttpRequestResponse brokenSnapshot = exchange((method, args) -> switch (method.getName()) {
                    case "hasResponse" -> true;
                    case "request" -> throw new NoSuchMethodError("'burp.api.montoya.http.message.requests.HttpRequest burp.api.montoya.http.message.HttpRequestResponse.request()' synthetic-secret");
                    default -> null;
                });
                action(provider, event(brokenSnapshot, null)).doClick();
                check(errors.size() == 4 && notices.get(5).contains("No evidence was saved"), "A linkage error after clicking Attach is caught before a prompt or filesystem write");
                JMenuItem unfinished = action(provider, event(exchange((m, a) -> m.getName().equals("hasResponse") ? false : null), null));
                check(!unfinished.isEnabled() && unfinished.getToolTipText().contains("Send this request"), "A request without a response shows a disabled action explaining how to enable it");
                check(errors.stream().noneMatch(s -> s.contains("synthetic-secret")), "Evidence API diagnostics never copy arbitrary exception text");
            });
            check(!Files.exists(evidenceFolder), "Unreadable context-menu exchanges do not create or modify an evidence folder");
        } finally {
            SwingUtilities.invokeAndWait(() -> { setField(extension, "unloaded", true); if (controller.get() != null) controller.get().close(); });
        }
    }

    private static JMenuItem action(ContextMenuItemsProvider provider, ContextMenuEvent event) {
        List<Component> items = provider.provideMenuItems(event);
        if (items.size() != 1 || !(items.get(0) instanceof JMenuItem)) throw new AssertionError("Expected one visible evidence action");
        return (JMenuItem) items.get(0);
    }
    private static ContextMenuEvent event(HttpRequestResponse exchange, Throwable failure) {
        Object editor = java.lang.reflect.Proxy.newProxyInstance(MessageEditorHttpRequestResponse.class.getClassLoader(), new Class<?>[]{MessageEditorHttpRequestResponse.class}, (p, m, a) -> m.getName().equals("requestResponse") ? exchange : null);
        return (ContextMenuEvent) java.lang.reflect.Proxy.newProxyInstance(ContextMenuEvent.class.getClassLoader(), new Class<?>[]{ContextMenuEvent.class}, (p, m, a) -> switch (m.getName()) {
            case "messageEditorRequestResponse" -> { if (failure != null) throw failure; yield Optional.of(editor); }
            case "selectedRequestResponses" -> throw new AssertionError("An unreadable editor must not redirect evidence to a table selection");
            case "toolType" -> ToolType.REPEATER;
            default -> null;
        });
    }
    private static Object host(Class<?> type, Path folder, List<String> errors, AtomicReference<ContextMenuItemsProvider> registered) {
        return java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> {
            if (m.getName().equals("sendRequest") || m.getName().equals("sendToRepeater") || m.getName().equals("setString")) throw new AssertionError("Compatibility failures must not send requests or write preferences");
            if (m.getName().equals("getString")) return a[0].equals("nightvision.evidence.folder") ? folder.toString() : null;
            if (m.getName().equals("registerContextMenuItemsProvider")) { registered.set((ContextMenuItemsProvider) a[0]); return null; }
            if (m.getName().equals("logToError")) { errors.add((String) a[0]); return null; }
            if (m.getReturnType().isInterface()) return host(m.getReturnType(), folder, errors, registered);
            return null;
        });
    }

    /** Compile only the changed public interface into a disposable directory; Burp never sees this fixture. */
    private static Optional<?> select(Path folder, String declaration, Object value, HttpRequestResponse unrelated) throws Exception {
        Path source = folder.resolve(EDITOR.replace('.', '/') + ".java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "package burp.api.montoya.ui.contextmenu; public interface MessageEditorHttpRequestResponse { " + declaration + " }");
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new AssertionError("A JDK compiler is required for the isolated API regression fixture");
        int result = compiler.run(null, null, null, "--release", "17", "-d", folder.toString(), source.toString());
        if (result != 0) throw new AssertionError("Could not compile the synthetic editor API fixture");
        ClassLoader parent = EvidenceCompatibilitySelfTest.class.getClassLoader();
        try (URLClassLoader loader = new URLClassLoader(new URL[]{folder.toUri().toURL()}, parent) {
            @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                synchronized (getClassLoadingLock(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null && name.equals(EDITOR)) loaded = findClass(name);
                    if (loaded == null && name.equals(CAPTURE)) {
                        try (var input = parent.getResourceAsStream(name.replace('.', '/') + ".class")) {
                            if (input == null) throw new ClassNotFoundException(name);
                            byte[] bytes = input.readAllBytes(); loaded = defineClass(name, bytes, 0, bytes.length);
                        } catch (java.io.IOException e) { throw new ClassNotFoundException(name, e); }
                    }
                    if (loaded == null) loaded = super.loadClass(name, false);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
            }
        }) {
            Class<?> editorType = loader.loadClass(EDITOR);
            Object editor = java.lang.reflect.Proxy.newProxyInstance(loader, new Class<?>[]{editorType}, (p, m, a) -> value);
            AtomicBoolean tableRead = new AtomicBoolean();
            ContextMenuEvent event = (ContextMenuEvent) java.lang.reflect.Proxy.newProxyInstance(parent, new Class<?>[]{ContextMenuEvent.class}, (p, m, a) -> switch (m.getName()) {
                case "messageEditorRequestResponse" -> Optional.of(editor);
                case "selectedRequestResponses" -> { tableRead.set(true); yield List.of(unrelated); }
                default -> null;
            });
            Method method = loader.loadClass(CAPTURE).getDeclaredMethod("selected", ContextMenuEvent.class);
            method.setAccessible(true); // Test-only access to the adapter, not Burp's private implementation.
            try {
                Optional<?> selected = (Optional<?>) method.invoke(null, event);
                check(!tableRead.get(), "Editor API compatibility never changes the source to a table selection");
                return selected;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException runtime) throw runtime;
                if (cause instanceof Error error) throw error;
                throw new AssertionError(cause);
            }
        }
    }

    private static HttpRequestResponse exchange() {
        return exchange((m, a) -> null);
    }
    private static HttpRequestResponse exchange(java.util.function.BiFunction<Method, Object[], Object> call) {
        return (HttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(HttpRequestResponse.class.getClassLoader(), new Class<?>[]{HttpRequestResponse.class}, (p, m, a) -> call.apply(m, a));
    }
}
