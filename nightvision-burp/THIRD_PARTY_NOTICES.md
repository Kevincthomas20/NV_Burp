# Third-party notices

The compiled extension includes Google Gson 2.13.2, copyright Google and Gson contributors, licensed under Apache License 2.0. The license text is in `licenses/GSON-APACHE-2.0.txt` and within the JAR at `META-INF/licenses/GSON-APACHE-2.0.txt`.

The compiled extension also includes SnakeYAML 2.5, copyright SnakeYAML contributors, licensed under Apache License 2.0. Its license text is in `licenses/SNAKEYAML-APACHE-2.0.txt` and in the JAR under `META-INF/licenses/`. It is used with a SafeConstructor and bounded input to read CLI configuration.

PortSwigger's Montoya API 2026.7 is a build-time provided dependency. Its classes are not bundled in the extension JAR. Burp Suite supplies the runtime implementation. Montoya API 0.10.1 is additionally downloaded by the Python build only for isolated pre-1.0 evidence workflow tests. It is also excluded from the release JAR and ZIP.

Public dependency locations and SHA-256 digests are pinned in `tools/build.py`.
