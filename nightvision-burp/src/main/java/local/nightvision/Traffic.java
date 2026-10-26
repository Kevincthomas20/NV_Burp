package local.nightvision;

import com.google.gson.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.regex.Pattern;

/** Adapts NightVision's captured HAR-style arrays without making target requests. */
public final class Traffic {
    private Traffic() {}
    public record Message(String text, String destination, String source, String note) {
        @Override public String toString() {
            return source + " — " + (text.isEmpty() ? note : text.lines().findFirst().orElse(""))
                + (destination.isEmpty() ? "" : " | " + destination);
        }
    }
    private static final Pattern METHOD = Pattern.compile("[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*");
    private record Header(String name, String value) {}

    public static List<Message> messages(JsonObject issue, String direction) {
        List<Message> out = new ArrayList<>();
        for (JsonObject container : List.of(Finding.object(issue, "extra_info"), issue)) {
            String prefix = container == issue ? "" : "extra_info.";
            JsonElement array = container.get("http_" + direction + "s");
            if (array != null && !array.isJsonNull()) {
                String source = prefix + "http_" + direction + "s";
                if (array.isJsonArray()) {
                    for (int i = 0; i < array.getAsJsonArray().size(); i++)
                        out.add(read(array.getAsJsonArray().get(i), direction, source + "[" + i + "]"));
                } else out.add(new Message("", "", source, "Unsupported capture format; inspect Full finding JSON."));
                if (!out.isEmpty()) return List.copyOf(out);
            }
            for (String key : List.of("raw_" + direction, "http_" + direction, direction)) {
                JsonElement value = container.get(key);
                if (value == null || value.isJsonNull()) continue;
                Message message = read(value, direction, prefix + key);
                if (!message.text().isEmpty()) return List.of(message);
            }
            String head = Finding.s(container, direction + "Header");
            if (head.isBlank()) head = Finding.s(container, direction + "_header");
            String body = Finding.s(container, direction + "Body");
            if (body.isEmpty()) body = Finding.s(container, direction + "_body");
            if (looksLike(head, direction)) return List.of(new Message(
                head.replaceAll("[\\r\\n]+$", "") + "\r\n\r\n" + body, "", prefix + direction + "Header", "Captured header/body text"));
        }
        return List.of();
    }
    static boolean looksLike(String text, String direction) {
        return direction.equals("request")
            ? Pattern.compile("^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]* [^\\r\\n ]+ HTTP/\\d(?:\\.\\d)?(?:\\r?\\n|$)").matcher(text).find()
            : text.startsWith("HTTP/");
    }
    private static Message read(JsonElement value, String direction, String source) {
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString() && looksLike(value.getAsString(), direction))
                return new Message(value.getAsString(), "", source, "Captured raw HTTP text");
            if (!value.isJsonObject()) throw new IllegalArgumentException("Capture is not recognizable HTTP text or a structured message.");
            JsonObject message = value.getAsJsonObject();
            String destination = direction.equals("request") ? requestUrl(message) : "";
            for (String key : List.of("raw", "raw_" + direction)) {
                String raw = Finding.s(message, key);
                if (looksLike(raw, direction)) return new Message(raw, destination, source, "Captured raw HTTP text");
            }
            List<Header> headers = headers(message.get("headers"));
            String firstLine;
            String body;
            if (direction.equals("request")) {
                String method = Finding.s(message, "method");
                if (!METHOD.matcher(method).matches()) throw new IllegalArgumentException("Capture has no valid HTTP method.");
                if (destination.isEmpty()) throw new IllegalArgumentException("Capture has no valid absolute HTTP(S) URL.");
                URI url = URI.create(destination);
                String path = url.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (url.getRawQuery() != null) path += "?" + url.getRawQuery();
                // HAR HTTP/2 messages are represented as editable HTTP/1.1 for Repeater.
                firstLine = method + " " + path + " HTTP/1.1";
                if (!has(headers, "Host")) headers.add(0, new Header("Host", url.getRawAuthority()));
                JsonElement post = message.get("postData");
                body = body(post == null || post.isJsonNull() ? message.get("body") : post);
                if (post != null && post.isJsonObject()) {
                    String mime = Finding.s(post.getAsJsonObject(), "mimeType");
                    if (!mime.isBlank() && !has(headers, "Content-Type")) headers.add(new Header("Content-Type", safe(mime)));
                }
                JsonElement cookies = message.get("cookies");
                if (!has(headers, "Cookie") && cookies != null && cookies.isJsonArray()) {
                    List<String> parts = new ArrayList<>();
                    for (JsonElement item : cookies.getAsJsonArray()) {
                        if (!item.isJsonObject()) throw new IllegalArgumentException("Unsupported cookies; inspect Full finding JSON.");
                        JsonObject cookie = item.getAsJsonObject();
                        String name = safe(Finding.s(cookie, "name"));
                        if (name.isBlank()) throw new IllegalArgumentException("Cookie has no name.");
                        parts.add(name + "=" + safe(Finding.s(cookie, "value")));
                    }
                    if (!parts.isEmpty()) headers.add(new Header("Cookie", String.join("; ", parts)));
                }
            } else {
                String status = Finding.s(message, "status");
                if (status.isBlank()) status = Finding.s(message, "status_code");
                if (!status.matches("[1-5][0-9]{2}")) throw new IllegalArgumentException("Capture has no valid HTTP status code.");
                String reason = safe(Finding.s(message, "statusText"));
                String version = Finding.s(message, "httpVersion").toUpperCase(Locale.ROOT);
                if (!version.matches("HTTP/[0-9](\\.[0-9])?")) version = "HTTP/1.1";
                firstLine = version + " " + status + (reason.isEmpty() ? "" : " " + reason);
                JsonElement content = message.get("content");
                body = body(content == null || content.isJsonNull() ? message.get("body") : content);
            }
            StringBuilder text = new StringBuilder(firstLine).append("\r\n");
            for (Header header : headers) text.append(header.name()).append(": ").append(header.value()).append("\r\n");
            text.append("\r\n").append(body);
            return new Message(text.toString(), destination, source, "Reconstructed from captured fields; verify before replay");
        } catch (IllegalArgumentException e) {
            return new Message("", "", source, e.getMessage());
        }
    }
    private static String requestUrl(JsonObject message) {
        try { return Finding.destination(Finding.s(message, "url")).toASCIIString(); }
        catch (IllegalArgumentException e) { return ""; }
    }
    private static String safe(String text) {
        if (text.indexOf('\r') >= 0 || text.indexOf('\n') >= 0 || text.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Structured header contains a line break or NUL; inspect Full finding JSON.");
        return text;
    }
    private static boolean has(List<Header> headers, String name) {
        return headers.stream().anyMatch(h -> h.name().equalsIgnoreCase(name));
    }
    private static List<Header> headers(JsonElement value) {
        List<Header> out = new ArrayList<>();
        if (value == null || value.isJsonNull()) return out;
        if (value.isJsonArray()) {
            for (JsonElement entry : value.getAsJsonArray()) {
                if (!entry.isJsonObject()) throw new IllegalArgumentException("Unsupported headers; inspect Full finding JSON.");
                JsonObject h = entry.getAsJsonObject();
                addHeader(out, Finding.s(h, "name"), h.get("value"));
            }
        } else if (value.isJsonObject()) {
            for (var entry : value.getAsJsonObject().entrySet()) {
                if (entry.getValue().isJsonArray()) for (JsonElement v : entry.getValue().getAsJsonArray()) addHeader(out, entry.getKey(), v);
                else addHeader(out, entry.getKey(), entry.getValue());
            }
        } else throw new IllegalArgumentException("Unsupported headers; inspect Full finding JSON.");
        return out;
    }
    private static void addHeader(List<Header> out, String name, JsonElement value) {
        if (!METHOD.matcher(name).matches() && !Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+").matcher(name).matches())
            throw new IllegalArgumentException("Unsupported header name; inspect Full finding JSON.");
        if (value == null || !value.isJsonPrimitive()) throw new IllegalArgumentException("Unsupported header value; inspect Full finding JSON.");
        out.add(new Header(name, safe(value.getAsString())));
    }
    private static String body(JsonElement value) {
        if (value == null || value.isJsonNull()) return "";
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) return value.getAsString();
        if (!value.isJsonObject()) throw new IllegalArgumentException("Body is not captured text; inspect Full finding JSON.");
        JsonObject body = value.getAsJsonObject();
        JsonElement text = body.get("text");
        if (text == null || !text.isJsonPrimitive() || !text.getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("Captured body text is missing; inspect Full finding JSON or paste the original request.");
        String encoding = Finding.s(body, "encoding");
        if (encoding.isBlank()) return text.getAsString();
        if (!encoding.equalsIgnoreCase("base64")) throw new IllegalArgumentException("Unsupported body encoding; inspect Full finding JSON.");
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(Base64.getDecoder().decode(text.getAsString()))).toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            throw new IllegalArgumentException("Base64 body is invalid or binary; this editor supports UTF-8 text only.");
        }
    }
}
