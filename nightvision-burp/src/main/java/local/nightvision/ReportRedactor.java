package local.nightvision;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * Removes recognizable credentials from report fields without changing the source
 * finding or saved notes. This is pattern-based redaction, not a general detector
 * for personal data or secrets embedded in arbitrary prose/binary content.
 */
final class ReportRedactor {
    private ReportRedactor() {}
    private static final String MASK = "[REDACTED]";
    private static final Set<String> KEYS = Set.of("authorization", "proxyauthorization", "cookie", "setcookie",
        "password", "passwd", "pwd", "secret", "clientsecret", "token", "accesstoken", "refreshtoken",
        "idtoken", "apikey", "xapikey", "xauthtoken", "auth", "jwt", "session", "sessionid", "jsessionid",
        "csrftoken", "xcsrftoken", "xsrftoken", "xxsrftoken", "code");
    // Consume folded continuation lines as part of a credential-bearing HTTP header.
    private static final Pattern HEADERS = Pattern.compile(
        "(?im)^([ \\t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-xsrf-token)[ \\t]*:)[^\\r\\n]*(?:\\r?\\n[ \\t]+[^\\r\\n]*)*+");
    // Accept quoted JSON/YAML values as well as URL/form/header-like key-value text.
    // Possessive loops avoid regex stack growth on long credentials or many escaped characters.
    private static final Pattern VALUES = Pattern.compile(
        "(?<![A-Za-z0-9_.%\\-])([\"']?)([A-Za-z][A-Za-z0-9_.%\\-]{0,79})\\1(\\s*[:=]\\s*)(\"(?:[^\"\\\\]++|\\\\.)*+\"|'(?:[^'\\\\]++|\\\\.)*+'|[^\\s&;,<>\"']+)");
    private static final Pattern AUTH = Pattern.compile("(?i)\\b(Bearer|Basic)[ \\t]+[A-Za-z0-9._~+/=\\-]+");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b");
    private static final Pattern USERINFO = Pattern.compile("(?i)(https?://)[^\\s/@]+@");
    private static final Pattern QUERY = Pattern.compile("([?&;])([^=&\\s<>\"']{1,100})=([^&\\s<>\"'#]*)");

    /** Applies the same redaction to report metadata, notes, evidence, and HTTP text. */
    static String redact(String value) {
        String text = Objects.toString(value, "");
        text = replace(HEADERS, text, m -> m.group(1) + " " + MASK);
        // Redact query values first: a surrounding URL or JSON value may otherwise consume the whole URL.
        text = replace(QUERY, text, m -> sensitive(m.group(2)) ? m.group(1) + m.group(2) + "=" + MASK : m.group());
        text = replace(VALUES, text, m -> {
            if (!sensitive(m.group(2))) return m.group();
            String raw = m.group(4);
            String quote = raw.startsWith("\"") ? "\"" : raw.startsWith("'") ? "'" : "";
            return m.group(1) + m.group(2) + m.group(1) + m.group(3) + quote + MASK + quote;
        });
        text = replace(AUTH, text, m -> m.group(1) + " " + MASK);
        text = JWT.matcher(text).replaceAll(MASK);
        return replace(USERINFO, text, m -> m.group(1) + MASK + "@");
    }

    /** Normalizes common separators and percent-encoded parameter names before comparison. */
    private static boolean sensitive(String raw) {
        String key;
        try { key = URLDecoder.decode(raw, StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { key = raw; }
        return KEYS.contains(key.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT));
    }

    /** Quotes replacements so credential text cannot acquire regex replacement semantics. */
    private static String replace(Pattern pattern, String text, java.util.function.Function<Matcher, String> replacement) {
        Matcher matcher = pattern.matcher(text);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) matcher.appendReplacement(out, Matcher.quoteReplacement(replacement.apply(matcher)));
        matcher.appendTail(out);
        return out.toString();
    }
}
