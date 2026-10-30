package local.nightvision;

import com.google.gson.*;
import java.net.URI;
import java.util.*;

/**
 * Wraps one API issue without discarding its original JSON. Supplies display fields,
 * traffic accessors, and the validation used before opening a request in Repeater.
 */
public record Finding(JsonObject data) {
    // Plain-text JSON formatting for the detail tab and local validation exports.
    public static final Gson JSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    /** Reads a scalar field without failing when optional fields are absent or structured. */
    public static String s(JsonObject o, String key) {
        JsonElement e = o == null ? null : o.get(key);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : "";
    }
    /** Returns a child object, or an empty object so optional metadata is safe to inspect. */
    public static JsonObject object(JsonObject o, String key) {
        JsonElement e = o == null ? null : o.get(key);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : new JsonObject();
    }
    public String id() { return s(data, "id"); }
    /** Prefers a scanner template name, then the issue kind, then an ID-based fallback. */
    public String title() {
        String name = s(object(data, "nuclei_template"), "name");
        if (name.isBlank()) name = s(object(data, "kind"), "name");
        return name.isBlank() ? "Issue " + s(data, "kind_id") : name;
    }
    public String severity() { return s(data, "severity"); }
    /** Keeps the server resolution distinct from the analyst's separate local verdict. */
    public String resolutionDisplay() {
        String resolution = s(data, "resolution");
        return switch (resolution) {
            case "0" -> "Open (0)";
            case "1" -> "Resolved (1)";
            case "2" -> "False positive (2)";
            case "4" -> "Won't fix (4)";
            default -> resolution.isBlank() ? "Unknown" : "API value " + resolution;
        };
    }
    /** Builds a fallback destination from finding metadata when a capture has no URL. */
    public String targetUrl() {
        String protocol = s(data, "protocol").toLowerCase(Locale.ROOT).replace("://", "");
        if (protocol.isBlank()) protocol = "https";
        String host = s(data, "fqdn");
        if (host.isBlank()) return "";
        String port = s(data, "port");
        String path = s(data, "url_path");
        if (!path.startsWith("/")) path = "/" + path;
        // URL authorities require brackets around an IPv6 address.
        if (host.contains(":") && !host.startsWith("[")) host = "[" + host + "]";
        return protocol + "://" + host + (port.isBlank() || port.equals("0") ? "" : ":" + port) + path;
    }
    // Arrays remain independent: matching request/response positions do not establish pairing.
    public List<Traffic.Message> requests() { return Traffic.messages(data, "request"); }
    public List<Traffic.Message> responses() { return Traffic.messages(data, "response"); }
    // Convenience accessors for the first usable message; the UI also exposes all captures.
    public String request() { return requests().stream().map(Traffic.Message::text).filter(t -> !t.isEmpty()).findFirst().orElse(""); }
    public String response() { return responses().stream().map(Traffic.Message::text).filter(t -> !t.isEmpty()).findFirst().orElse(""); }
    /** Validates the explicit service URL before Burp receives the edited request. */
    public static URI destination(String input) {
        URI u;
        try { u = URI.create(input.trim()); }
        catch (RuntimeException e) { throw new IllegalArgumentException("Enter a valid HTTP or HTTPS destination URL."); }
        if (!("http".equalsIgnoreCase(u.getScheme()) || "https".equalsIgnoreCase(u.getScheme()))
            || u.getHost() == null || u.getRawUserInfo() != null || u.getFragment() != null
            || u.getPort() == 0 || u.getPort() > 65535)
            throw new IllegalArgumentException("Destination must be an HTTP(S) URL without embedded credentials or fragment.");
        return u;
    }
    /** Checks the HTTP request line and normalizes headers without changing body text. */
    public static String prepareRequest(String raw) {
        if (!Traffic.looksLike(raw, "request")) throw new IllegalArgumentException("Paste a complete HTTP request starting with METHOD /path HTTP/1.1.");
        int split = raw.indexOf("\r\n\r\n");
        int delimiter = 4;
        if (split < 0) { split = raw.indexOf("\n\n"); delimiter = 2; }
        String head = split < 0 ? raw : raw.substring(0, split);
        String body = split < 0 ? "" : raw.substring(split + delimiter);
        // Only the header block is normalized. The message body is preserved verbatim.
        return head.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
            .replaceAll("[\\r\\n]+$", "") + "\r\n\r\n" + body;
    }
}
