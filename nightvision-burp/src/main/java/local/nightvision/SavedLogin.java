package local.nightvision;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Reads current YAML/JSON CLI configuration or a legacy plain-text token file.
 * Only a top-level token is accepted; files are never rewritten and parser errors
 * never expose the credential-bearing source text.
 */
final class SavedLogin {
    static final int MAX_CONFIG_BYTES = 1024 * 1024;
    private SavedLogin() {}
    /** Prefers current CLI config files over a possibly stale legacy token in the same directory. */
    static List<Path> candidates(Path legacy) {
        return List.of(legacy.resolveSibling("nightvision.yml"), legacy.resolveSibling("nightvision.yaml"),
            legacy.resolveSibling("nightvision.json"), legacy);
    }
    /** Searches only known filenames under Java and OS home hints; never recursively scans a home. */
    static List<Path> defaultCandidates() {
        Set<Path> paths = new LinkedHashSet<>();
        // Read the OS home hints; never change the environment seen by the CLI.
        for (String home : List.of(System.getProperty("user.home", ""), Objects.toString(System.getenv("USERPROFILE"), ""), Objects.toString(System.getenv("HOME"), ""))) {
            if (!home.isBlank()) try { paths.addAll(candidates(Path.of(home, ".nightvision", "token").toAbsolutePath().normalize())); }
            catch (InvalidPathException ignored) {}
        }
        return List.copyOf(paths);
    }
    /** Reads a bounded file and selects structured-config parsing or legacy token validation. */
    static String read(Path path) {
        final byte[] bytes;
        try (InputStream in = Files.newInputStream(path)) { bytes = in.readNBytes(MAX_CONFIG_BYTES + 1); }
        catch (IOException e) { throw new IllegalStateException("Cannot read saved login file: " + path + ". Choose the file used by your desktop CLI login."); }
        if (bytes.length > MAX_CONFIG_BYTES) throw new IllegalStateException("Saved login file exceeds 1 MiB: " + path);
        String text = new String(bytes, StandardCharsets.UTF_8);
        if (text.startsWith("\ufeff")) text = text.substring(1); // Accept a UTF-8 byte-order mark.
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        // Recognize known config suffixes plus common config content in an explicitly chosen file.
        boolean structured = name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".json")
            || text.stripLeading().startsWith("{") || java.util.regex.Pattern.compile("(?m)^token\\s*:").matcher(text).find();
        if (!structured) return validate(text);
        final Object parsed;
        try {
            // SafeConstructor forbids custom object construction. Limits reject duplicate keys,
            // collection aliases, and deeply nested data.
            // JSON is also valid YAML, so both config formats use the same constrained parser.
            LoaderOptions options = new LoaderOptions(); options.setAllowDuplicateKeys(false);
            options.setMaxAliasesForCollections(0); options.setCodePointLimit(MAX_CONFIG_BYTES);
            options.setNestingDepthLimit(25);
            parsed = new Yaml(new SafeConstructor(options)).load(text);
        } catch (RuntimeException e) {
            // YAML exceptions can include the source line, including the secret. Never propagate them.
            throw new IllegalStateException("Saved login config is invalid or unsupported: " + path + ". Its contents were not logged.");
        }
        if (parsed == null) return null;
        if (!(parsed instanceof Map<?, ?> config)) throw new IllegalStateException("Saved login config must contain a top-level token field: " + path);
        // Inspect top-level keys only: unrelated nested secrets must never be guessed as the login token.
        Object token = null; boolean seen = false;
        for (var entry : config.entrySet()) {
            if (!(entry.getKey() instanceof String key)) continue;
            if (key.equalsIgnoreCase("token")) {
                if (seen) throw new IllegalStateException("Saved login config has ambiguous token fields: " + path);
                seen = true; token = entry.getValue();
            }
            // When API metadata exists, verify it belongs to the production service before token reuse.
            if (key.replace("-", "").replace("_", "").equalsIgnoreCase("apiurl") && entry.getValue() != null)
                checkApi(entry.getValue());
        }
        if (token == null) return null;
        if (!(token instanceof String value)) throw new IllegalStateException("Saved login token must be a text value. Sign in again with the CLI.");
        return validate(value);
    }
    /** Accepts a single bounded printable token, preventing control characters in HTTP headers. */
    private static String validate(String text) {
        String token = text.trim();
        if (token.isEmpty() || token.length() > NightVisionLogin.MAX_TOKEN_BYTES || token.chars().anyMatch(c -> c < 33 || c > 126))
            throw new IllegalStateException("Saved NightVision credential is empty, too large, or unsupported. Sign in again using the CLI.");
        return token;
    }
    /** Accepts the production HTTPS origin with either a bare origin or the known API base path. */
    private static void checkApi(Object value) {
        try {
            if (!(value instanceof String text)) throw new IllegalArgumentException();
            URI uri = URI.create(text);
            NightVisionLogin.requireProductionOrigin("https://" + uri.getRawAuthority());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getFragment() != null
                || !List.of("", "/", "/api/v1", "/api/v1/").contains(uri.getPath())) throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Saved CLI config is for a different or unsupported API origin. Use a production NightVision login, or supply a manual token for the intended origin.");
        }
    }
}
