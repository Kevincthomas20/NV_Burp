package local.nightvision;

import java.nio.file.*;

/** Synthetic executable used by process tests; never launches a browser or calls NightVision. */
public final class LoginProcessFixture {
    public static void main(String[] args) throws Exception {
        System.out.println("synthetic-output-secret-that-must-not-be-logged");
        System.err.println("synthetic-error-secret-that-must-not-be-logged");
        switch (args[0]) {
            case "success" -> Files.writeString(Path.of(args[1]), "synthetic-sso-credential\n");
            case "old-cli" -> {
                if (java.util.Arrays.asList(args).contains("--timeout")) { System.err.println("Error: unknown flag: --timeout"); System.exit(2); }
                Files.writeString(Path.of(args[1]).resolveSibling("nightvision.yml"), "api-url: https://api.nightvision.net/api/v1/\ntoken: synthetic-sso-credential\n");
            }
            case "noisy-failure" -> { for (int i = 0; i < 10000; i++) System.err.println("synthetic-secret-omit-this-output"); System.err.println("unknown flag: --timeout"); System.exit(2); }
            case "failure" -> System.exit(7);
            case "wait" -> Thread.sleep(60000);
            case "missing" -> { }
            default -> throw new IllegalArgumentException("Unknown fixture");
        }
    }
}
