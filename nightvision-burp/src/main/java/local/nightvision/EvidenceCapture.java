package local.nightvision;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import java.lang.reflect.*;
import java.util.*;

/** Adapts one explicit Burp context-menu selection without intercepting or sending traffic. */
final class EvidenceCapture {
    private EvidenceCapture() {}
    static Optional<HttpRequestResponse> selected(ContextMenuEvent event) {
        // The message editor is the most specific source; do not substitute a different table row.
        var editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) return editorExchange(editor.get());
        List<HttpRequestResponse> rows = event.selectedRequestResponses();
        return rows != null && rows.size() == 1 ? Optional.ofNullable(rows.get(0)) : Optional.empty();
    }

    /** Resolve the installed public editor method rather than linking to the SDK's return descriptor. */
    private static Optional<HttpRequestResponse> editorExchange(Object editor) {
        try {
            // Invoking the public interface also works when Burp's concrete implementation is private.
            Method accessor = required(MessageEditorHttpRequestResponse.class, "requestResponse", "getRequestResponse");
            Object value = invoke(accessor, editor);
            if (value instanceof Optional<?> optional) value = optional.orElse(null);
            if (value == null) return Optional.empty();
            if (value instanceof HttpRequestResponse exchange) return Optional.of(exchange);
            throw new IllegalStateException("The installed editor API returned an unsupported HTTP exchange type.");
        } catch (IllegalStateException e) {
            throw new IllegalStateException("The installed Burp editor API does not expose a readable HTTP exchange.", e);
        }
    }

    /** Pre-1.0 Montoya has no hasResponse(); use its explicit response getter instead. */
    static boolean completed(HttpRequestResponse exchange) {
        Method predicate = optional(HttpRequestResponse.class, "hasResponse");
        if (predicate != null) return Boolean.TRUE.equals(invoke(predicate, exchange));
        return response(exchange) != null;
    }

    static EvidenceStore.Captured snapshot(HttpRequestResponse selected, String tool) {
        if (selected == null || !completed(selected))
            throw new IllegalArgumentException("Select one completed HTTP request/response before attaching retest evidence.");
        HttpRequest selectedRequest = value(HttpRequest.class, invoke(required(HttpRequestResponse.class, "request", "httpRequest"), selected));
        HttpResponse selectedResponse = response(selected);
        if (selectedRequest == null || selectedResponse == null) throw new IllegalArgumentException("Select a completed exchange with both request and response.");
        ByteArray request = value(ByteArray.class, invoke(required(HttpRequest.class, "toByteArray", "asBytes"), selectedRequest));
        ByteArray response = value(ByteArray.class, invoke(required(HttpResponse.class, "toByteArray", "asBytes"), selectedResponse));
        if (request == null || response == null) throw new IllegalStateException("Burp did not expose the selected HTTP message bytes.");
        // Check sizes before asking Burp to allocate a byte[] for a large message.
        if (request.length() < 1 || request.length() > EvidenceStore.MAX_REQUEST || response.length() < 1 || response.length() > EvidenceStore.MAX_RESPONSE)
            throw new IllegalArgumentException("Evidence supports requests up to 1 MiB and responses up to 2 MiB. Select a smaller exchange.");
        // The early exchange interface has no service accessor. Its own request supplies the service.
        Method serviceAccessor = optional(HttpRequestResponse.class, "httpService");
        HttpService service = serviceAccessor == null ? selectedRequest.httpService()
            : value(HttpService.class, invoke(serviceAccessor, selected));
        if (service == null) throw new IllegalArgumentException("The selected exchange has no HTTP service.");
        return new EvidenceStore.Captured(request.getBytes(), response.getBytes(), selectedRequest.url(), service.host(), service.port(), service.secure(), tool, selectedResponse.statusCode());
    }

    private static HttpResponse response(HttpRequestResponse exchange) {
        return value(HttpResponse.class, invoke(required(HttpRequestResponse.class, "response", "httpResponse"), exchange));
    }
    /** Choose a documented public alias before invocation; never retry a failing method body. */
    private static Method optional(Class<?> type, String... names) {
        for (String name : names) try { return type.getMethod(name); } catch (NoSuchMethodException absent) { /* Try the pre-1.0 alias. */ }
        return null;
    }
    private static Method required(Class<?> type, String... names) {
        Method method = optional(type, names);
        if (method == null) throw new IllegalStateException("The installed Burp API is missing a required public HTTP evidence accessor.");
        return method;
    }
    private static <T> T value(Class<T> type, Object value) {
        if (value instanceof Optional<?> optional) value = optional.orElse(null);
        if (value == null) return null;
        if (!type.isInstance(value)) throw new IllegalStateException("The installed Burp API returned an unsupported HTTP evidence value.");
        return type.cast(value);
    }
    private static Object invoke(Method accessor, Object target) {
        try { return accessor.invoke(target); }
        catch (IllegalAccessException e) { throw new IllegalStateException("The selected public Burp HTTP evidence accessor is inaccessible.", e); }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtime) throw runtime;
            if (cause instanceof Error error) throw error;
            throw new IllegalStateException("The selected Burp HTTP exchange could not be read.", cause);
        }
    }
}
