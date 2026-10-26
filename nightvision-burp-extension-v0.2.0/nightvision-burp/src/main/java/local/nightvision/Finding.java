package local.nightvision;

import com.google.gson.*;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/** Schema-backed fields plus conservative, explicitly best-effort traffic extraction. */
public record Finding(JsonObject data) {
    public static final Gson JSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    public static String s(JsonObject o, String key) {
        JsonElement e = o == null ? null : o.get(key);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : "";
    }
    public static JsonObject object(JsonObject o, String key) {
        JsonElement e = o == null ? null : o.get(key);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : new JsonObject();
    }
    public String id() { return s(data, "id"); }
    public String title() {
        String name = s(object(data, "nuclei_template"), "name");
        if (name.isBlank()) name = s(object(data, "kind"), "name");
        return name.isBlank() ? "Issue " + s(data, "kind_id") : name;
    }
    public String severity() { return s(data, "severity"); }
    public String resolutionDisplay() {
        String resolution = s(data, "resolution");
        return switch (resolution) {
            case "0" -> "Open (0)";
            case "1" -> "False positive (1)";
            case "2" -> "Resolved (2)";
            default -> resolution.isBlank() ? "Unknown" : "API value " + resolution;
        };
    }
    public String targetUrl() {
        String protocol = s(data, "protocol").toLowerCase(Locale.ROOT).replace("://", "");
        if (protocol.isBlank()) protocol = "https";
        String host = s(data, "fqdn");
        if (host.isBlank()) return "";
        String port = s(data, "port");
        String path = s(data, "url_path");
        if (!path.startsWith("/")) path = "/" + path;
        if (host.contains(":") && !host.startsWith("[")) host = "[" + host + "]";
        return protocol + "://" + host + (port.isBlank() || port.equals("0") ? "" : ":" + port) + path;
    }
    public String request() { return traffic("request"); }
    public String response() { return traffic("response"); }
    private String traffic(String direction) {
        JsonObject extra = object(data, "extra_info");
        for (JsonObject container : List.of(extra, data)) {
            for (String key : List.of("raw_" + direction, "http_" + direction, direction)) {
                JsonElement v = container.get(key);
                if (v == null) continue;
                if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
                    String raw = v.getAsString();
                    if (looksLike(raw, direction)) return raw;
                }
                if (v.isJsonObject()) {
                    for (String rawKey : List.of("raw", "raw_" + direction)) {
                        String raw = s(v.getAsJsonObject(), rawKey);
                        if (looksLike(raw, direction)) return raw;
                    }
                }
            }
            String head = s(container, direction + "Header");
            if (head.isBlank()) head = s(container, direction + "_header");
            String body = s(container, direction + "Body");
            if (body.isEmpty()) body = s(container, direction + "_body");
            if (looksLike(head, direction)) return head.replaceAll("[\\r\\n]+$", "") + "\r\n\r\n" + body;
        }
        return "";
    }
    private static boolean looksLike(String text, String direction) {
        return direction.equals("request")
            ? Pattern.compile("^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]* [^\\r\\n ]+ HTTP/\\d(?:\\.\\d)?(?:\\r?\\n|$)").matcher(text).find()
            : text.startsWith("HTTP/");
    }
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
    public static String prepareRequest(String raw) {
        if (!looksLike(raw, "request")) throw new IllegalArgumentException("Paste a complete HTTP request starting with METHOD /path HTTP/1.1.");
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
