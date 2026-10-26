package local.nightvision;

import com.google.gson.*;
import java.io.InputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import javax.net.ssl.SSLException;

/** REST client with explicit, single-issue false-positive updates. No target traffic. */
public final class NightVisionClient {
    public static final String DEFAULT_ORIGIN = "https://api.nightvision.net";
    static final int MAX_BODY = 20 * 1024 * 1024;
    // NightVision's own src/types/index.ts documents 1=false_positive.
    public static final int FALSE_POSITIVE_RESOLUTION = 1;
    public record Reply(int status, String body) {}
    @FunctionalInterface interface Transport { Reply send(HttpRequest request) throws Exception; }
    private final URI origin;
    private final String authorization;
    private final Transport transport;

    public NightVisionClient(String base, String token) {
        this(base, token, networkTransport(TlsSupport.Options.defaults()));
    }
    public NightVisionClient(String base, String token, TlsSupport.Options tls) {
        this(base, token, networkTransport(tls));
    }
    NightVisionClient(String base, String token, Transport transport) {
        this.origin = apiOrigin(base);
        String t = token.trim();
        if (t.regionMatches(true, 0, "Token ", 0, 6)) t = t.substring(6).trim();
        if (t.isBlank() || t.chars().anyMatch(c -> c < 33 || c > 126))
            throw new IllegalArgumentException("Enter your NightVision API token (without Bearer).");
        authorization = "Token " + t;
        this.transport = transport;
    }
    static URI apiOrigin(String base) {
        URI u;
        try { u = URI.create(base.trim()); }
        catch (RuntimeException e) { throw new IllegalArgumentException("Enter a valid HTTPS API origin."); }
        if (!"https".equalsIgnoreCase(u.getScheme()) || u.getHost() == null || u.getRawUserInfo() != null
                || u.getRawQuery() != null || u.getFragment() != null || u.getPort() == 0 || u.getPort() > 65535
                || !(u.getPath().isEmpty() || u.getPath().equals("/")))
            throw new IllegalArgumentException("API origin must be HTTPS, with no path, query, or credentials.");
        return URI.create("https://" + u.getRawAuthority());
    }
    private static Transport networkTransport(TlsSupport.Options options) {
        TlsSupport.Configuration tls = TlsSupport.build(options);
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15))
                .sslContext(tls.context()).sslParameters(TlsSupport.httpsParameters())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        return request -> {
            try {
            HttpResponse<InputStream> r = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = r.body()) {
                byte[] bytes = in.readNBytes(MAX_BODY + 1);
                if (bytes.length > MAX_BODY) throw new IllegalStateException("API response exceeds 20 MiB; narrow your scan selection.");
                return new Reply(r.statusCode(), new String(bytes, StandardCharsets.UTF_8));
            }
            } catch (SSLException e) { throw TlsSupport.connectionFailure(e, tls.report()); }
        };
    }
    public String origin() { return origin.toString(); }
    public JsonObject currentUser() throws Exception {
        JsonObject reply = get(origin.resolve("/api/v1/user/me/"));
        JsonObject user = Finding.object(reply, "user");
        if (user.size() == 0) user = reply;
        if (Finding.s(user, "id").isBlank()) throw new IllegalStateException("NightVision login could not be verified: the user response has no ID.");
        return user;
    }
    public List<JsonObject> scans(String project) throws Exception {
        String path = "/api/v1/scans/?page_size=100&order=-created_at";
        if (!project.isBlank()) path += "&project=" + id(project);
        return list(path);
    }
    public List<JsonObject> issues(String scan) throws Exception {
        return list("/api/v1/issues/?page_size=100&scan=" + id(scan));
    }
    public JsonObject issue(String id) throws Exception { return get(origin.resolve("/api/v1/issues/" + id(id) + "/")); }
    public JsonObject markFalsePositive(String issueId) throws Exception {
        String selectedId = id(issueId);
        URI endpoint = origin.resolve("/api/v1/issues/" + selectedId + "/");
        JsonObject body = new JsonObject();
        body.addProperty("resolution", FALSE_POSITIVE_RESOLUTION);
        try {
            exchange(endpoint, body);
        } catch (Exception e) {
            String detail = e instanceof IllegalStateException ? " " + e.getMessage() : "";
            throw new IllegalStateException("The NightVision update was not confirmed." + detail
                + " Fetch the full finding before retrying; an interrupted request may still have been applied.", e);
        }
        try {
            JsonObject refreshed = issue(selectedId);
            if (!selectedId.equals(Finding.s(refreshed, "id"))
                || !Integer.toString(FALSE_POSITIVE_RESOLUTION).equals(Finding.s(refreshed, "resolution")))
                throw new IllegalStateException("Read-back did not match the selected issue and resolution.");
            return refreshed;
        } catch (Exception e) {
            throw new IllegalStateException("NightVision accepted the update, but its saved resolution could not be verified."
                + " Fetch the full finding to check its current status before retrying.", e);
        }
    }
    static String id(String id) {
        try { return UUID.fromString(id.trim()).toString(); }
        catch (RuntimeException e) { throw new IllegalArgumentException("Scan, project, and issue IDs must be UUIDs."); }
    }
    private List<JsonObject> list(String path) throws Exception {
        List<JsonObject> out = new ArrayList<>();
        URI next = origin.resolve(path);
        String expectedPath = next.getPath();
        Set<URI> seen = new HashSet<>();
        for (int pages = 0; next != null; pages++) {
            if (pages >= 200 || !seen.add(next)) throw new IllegalStateException("Pagination limit or loop; use a narrower project or scan.");
            validatePage(next, expectedPath);
            JsonObject page = get(next);
            JsonElement rows = page.get("results");
            if (rows == null || !rows.isJsonArray()) throw new IllegalStateException("API response is missing the documented results array.");
            for (JsonElement row : rows.getAsJsonArray()) {
                if (!row.isJsonObject()) throw new IllegalStateException("Invalid API record.");
                out.add(row.getAsJsonObject());
                if (out.size() > 50000) throw new IllegalStateException("More than 50,000 records; use a narrower project or scan.");
            }
            String value = Finding.s(page, "next");
            next = value.isBlank() ? null : next.resolve(value);
        }
        return List.copyOf(out);
    }
    void validatePage(URI u, String expectedPath) {
        int port = u.getPort() == -1 ? 443 : u.getPort();
        int basePort = origin.getPort() == -1 ? 443 : origin.getPort();
        if (!"https".equalsIgnoreCase(u.getScheme()) || !Objects.equals(origin.getHost(), u.getHost())
                || port != basePort || u.getRawUserInfo() != null || u.getFragment() != null
                || !expectedPath.equals(u.getPath()))
            throw new IllegalStateException("Refused a pagination link outside the selected API endpoint.");
    }
    private JsonObject get(URI u) throws Exception {
        return exchange(u, null);
    }
    private JsonObject exchange(URI u, JsonObject update) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(u).timeout(Duration.ofSeconds(45))
                .header("Authorization", authorization).header("Accept", "application/json")
                .header("User-Agent", "NightVision-Burp/0.3.2");
        if (update == null) builder.GET();
        else builder.header("Content-Type", "application/json").PUT(HttpRequest.BodyPublishers.ofString(update.toString(), StandardCharsets.UTF_8));
        Reply r = transport.send(builder.build());
        if (r.status() != 200) {
            String hint = switch (r.status()) {
                case 401 -> "Check your API token.";
                case 403 -> "Your token lacks access to this resource.";
                case 404 -> "Check the scan or issue ID and API origin.";
                case 429 -> "Rate limited; wait before retrying.";
                default -> "Check connectivity and the NightVision service. Redirects are disabled.";
            };
            throw new ApiException(r.status(), "NightVision returned HTTP " + r.status() + ". " + hint);
        }
        try { return JsonParser.parseString(r.body()).getAsJsonObject(); }
        catch (RuntimeException e) { throw new IllegalStateException("NightVision returned invalid JSON."); }
    }
    public static final class ApiException extends IllegalStateException {
        private final int status;
        ApiException(int status, String message) { super(message); this.status = status; }
        public int status() { return status; }
    }
}
