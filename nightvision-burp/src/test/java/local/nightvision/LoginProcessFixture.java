package local.nightvision;

import java.nio.file.*;

/** Synthetic executable used by process tests; never launches a browser or calls NightVision. */
public final class LoginProcessFixture {
    /** args[0] selects a scenario; args[1] is its temporary saved-token path. */
    public static void main(String[] args) throws Exception {
        // Intentional fake secrets verify that captured stdout/stderr never appear in diagnostics.
        System.out.println("synthetic-output-secret-that-must-not-be-logged");
        System.err.println("synthetic-error-secret-that-must-not-be-logged");
        // Modes simulate token/config writes, old flags, pipe pressure, failure, hangs, and missing output.
        switch (args[0]) {
            case "success" -> Files.writeString(Path.of(args[1]), "synthetic-sso-credential\n");
            case "old-cli" -> {
                if (java.util.Arrays.asList(args).contains("--timeout")) { System.err.println("Error: unknown flag: --timeout"); System.exit(2); }
                Files.writeString(Path.of(args[1]).resolveSibling("nightvision.yml"), "api-url: https://api.nightvision.net/api/v1/\ntoken: synthetic-sso-credential\n");
            }
            case "noisy-failure" -> { for (int i = 0; i < 10000; i++) System.err.println("synthetic-secret-omit-this-output"); System.err.println("unknown flag: --timeout"); System.exit(2); }
            case "failure" -> System.exit(7);
            case "wait" -> Thread.sleep(60000); // The parent must terminate this child on cancel/timeout.
            case "missing" -> { }
            default -> throw new IllegalArgumentException("Unknown fixture");
        }
    }
}
