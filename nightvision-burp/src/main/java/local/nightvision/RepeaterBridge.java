package local.nightvision;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.lang.reflect.*;
import java.util.Objects;
import java.util.regex.*;

/** Resolves the installed public Repeater API before issuing one local UI handoff. */
final class RepeaterBridge {
    private RepeaterBridge() {}

    // Only JVM-style Montoya member signatures may be extracted from a linkage error. Arbitrary
    // exception text can contain HTTP data and must never be copied into diagnostics.
    private static final String API_TYPE = "(?:boolean|byte|char|short|int|long|float|double|burp\\.api\\.montoya\\.[A-Za-z0-9_.$]+|java\\.lang\\.(?:String|Object))(?:\\[\\])*";
    private static final Pattern MISSING_MEMBER = Pattern.compile(
        "(?:void|" + API_TYPE + ") burp\\.api\\.montoya\\.[A-Za-z0-9_.$]+\\((?:" + API_TYPE + "(?:, " + API_TYPE + ")*)?\\)");

    static Resolved resolve() { return resolve(MontoyaApi.class); }

    /** Public interface methods avoid illegal-access failures on Burp's private implementation classes. */
    static Resolved resolve(Class<?> apiInterface) {
        try {
            Method accessor = apiInterface.getMethod("repeater");
            Class<?> repeaterInterface = accessor.getReturnType();
            Method handoff;
            boolean named = false;
            try {
                // Prefer the basic API: a default Burp tab name is enough for manual testing.
                handoff = repeaterInterface.getMethod("sendToRepeater", HttpRequest.class);
            } catch (NoSuchMethodException absent) {
                // Choose an alternate signature only during lookup, never after invoking a handoff.
                handoff = repeaterInterface.getMethod("sendToRepeater", HttpRequest.class, String.class);
                named = true;
            }
            // Reflection resolves the host's actual return descriptor too. Do not bind the send call
            // to the compile-time SDK's void/other return type or access its private implementation.
            return new Resolved(accessor, handoff, named);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Installed Burp does not expose a supported public Repeater handoff API.", e);
        }
    }

    record Resolved(Method accessor, Method handoff, boolean named) {
        /** No target traffic is sent. Each click invokes exactly one selected Repeater method. */
        void send(Object api, HttpRequest request, String caption) {
            Object repeater = Objects.requireNonNull(invoke(accessor, api), "Burp returned no Repeater tool.");
            if (named) invoke(handoff, repeater, request, caption);
            else invoke(handoff, repeater, request);
        }
        String description() {
            return accessor.getDeclaringClass().getName() + ".repeater() -> " + accessor.getReturnType().getName()
                + "; " + handoff.getName() + "(HttpRequest" + (named ? ", String" : "") + ") -> " + handoff.getReturnType().getName();
        }
    }

    /** Unwrap the original API failure so the UI reports its real class; never retry its method body. */
    private static Object invoke(Method method, Object receiver, Object... args) {
        try { return method.invoke(receiver, args); }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtime) throw runtime;
            if (cause instanceof Error error) throw error;
            throw new IllegalStateException("Burp's Repeater API call failed.", cause);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Burp's public Repeater API is inaccessible.", e);
        }
    }

    /** Return a tightly allowlisted method signature, not the surrounding exception message. */
    static String missingMember(Throwable error) {
        if (!(error instanceof LinkageError)) return "";
        String message = error.getMessage();
        if (message == null || message.length() > 2048) return "";
        Matcher matcher = MISSING_MEMBER.matcher(message);
        return matcher.find() && matcher.group().length() <= 400 ? matcher.group() : "";
    }

    /** Bounded product-version text helps diagnosis; it is never used to select a compatibility path. */
    static String hostVersion(MontoyaApi api) {
        try {
            String text = api.burpSuite().version().toString();
            // Version.toString() is the supported human-readable form; deprecated component accessors
            // may disappear. A diagnostic-only shape check omits arbitrary host text or future formats.
            return text != null && text.length() <= 120 && text.matches(
                "(?:Burp Suite (?:Professional|Community Edition|Enterprise Edition) )?[0-9]{4}(?:\\.[0-9]+){1,3}(?:[- ][0-9]+)?")
                ? text : "unavailable";
        } catch (RuntimeException | LinkageError ignored) { return "unavailable"; }
    }
}
