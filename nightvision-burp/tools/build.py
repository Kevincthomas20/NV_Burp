#!/usr/bin/env python3
"""Build a Burp JAR and run offline checks using Python 3 and JDK 17 or 21.

No Maven installation is required. The first build downloads four pinned,
hash-checked public dependencies from Maven Central. Burp supplies Montoya
at runtime; Gson and SnakeYAML are included in the output JAR.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import os
import urllib.request
import zipfile

# Resolve paths from this script so the caller can start the build from any directory.
ROOT = Path(__file__).resolve().parent.parent
# Each entry pins a dependency's filename, Maven Central path, and expected SHA-256.
# Montoya is compile-only; the remaining libraries are bundled into the extension JAR.
DEPENDENCIES = [
    ("montoya-api-2026.7.jar", "net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar",
     "cb852b7b883290fcc1d21b13d80fa10f5b13a0f57335d710d2b1e5956ecb2a94"),
    ("gson-2.13.2.jar", "com/google/code/gson/gson/2.13.2/gson-2.13.2.jar",
     "dd0ce1b55a3ed2080cb70f9c655850cda86c206862310009dcb5e5c95265a5e0"),
    ("snakeyaml-2.5.jar", "org/yaml/snakeyaml/2.5/snakeyaml-2.5.jar",
     "e6682acf1ace77508ef13649cbf4f8d09d2cf5457bdb61d25ffb6ac0233d78dd"),
]
# Separate test-only API: never add this JAR to the modern compile/test classpath or release artifact.
LEGACY_API = ("montoya-api-0.10.1.jar", "net/portswigger/burp/extensions/montoya-api/0.10.1/montoya-api-0.10.1.jar",
              "cc4da37f9471e4aa4c34a5fce39d04b1ea1a5b9dfa4d68539fa36c94dd798b94")

def run(args):
    # Pass arguments directly, without a shell; a failed compiler/test process stops the build.
    subprocess.run([str(x) for x in args], check=True, cwd=ROOT)

def build():
    # The optional preview is produced by the same headless Swing regression runner.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview", type=Path, help="Optional path for a mock-host UI PNG")
    options = parser.parse_args()
    java = shutil.which("java")
    if not java:
        raise SystemExit("Install JDK 17 or 21 and put its bin directory on PATH.")
    # Cache downloaded dependencies, verifying both new downloads and existing cached bytes.
    deps = ROOT / ".build" / "deps"
    deps.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, suffix, expected in [*DEPENDENCIES, LEGACY_API]:
        path = deps / name
        if not path.exists():
            print("Downloading " + name, flush=True)
            with urllib.request.urlopen("https://repo.maven.apache.org/maven2/" + suffix, timeout=45) as response:
                content = response.read(5 * 1024 * 1024 + 1)
            if len(content) > 5 * 1024 * 1024:
                raise SystemExit("Dependency exceeded expected size.")
            if hashlib.sha256(content).hexdigest() != expected:
                raise SystemExit("Dependency checksum mismatch: " + name)
            path.write_bytes(content)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("Cached dependency checksum mismatch; remove " + str(path) + " and retry.")
        paths.append(path)
    legacy_api = paths.pop()
    # Start with clean class directories so deleted/renamed classes cannot leak into the JAR.
    classes = ROOT / "target" / "classes"
    tests = ROOT / "target" / "test-classes"
    for path in (classes, tests):
        if path.exists(): shutil.rmtree(path)
        path.mkdir(parents=True)
    # Prefer javac on PATH; a modular JDK can also invoke its compiler through java.
    compiler = [shutil.which("javac")] if shutil.which("javac") else [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]
    cp = os.pathsep.join(str(p) for p in paths)
    sources = sorted((ROOT / "src" / "main" / "java").rglob("*.java"))
    # Compile runtime code for Java 17 compatibility and copy the bundled offline demo resource.
    run(compiler + ["--release", "17", "-encoding", "UTF-8", "-cp", cp, "-d", classes] + sources)
    shutil.copytree(ROOT / "src" / "main" / "resources", classes, dirs_exist_ok=True)
    # Compile tests separately: test fixtures and test resources are never added to the release JAR.
    test_cp = str(classes) + os.pathsep + cp
    test_sources = sorted((ROOT / "src" / "test" / "java").rglob("*.java"))
    run(compiler + ["--release", "17", "-encoding", "UTF-8", "-cp", test_cp, "-d", tests] + test_sources)
    if (ROOT / "src" / "test" / "resources").exists():
        shutil.copytree(ROOT / "src" / "test" / "resources", tests, dirs_exist_ok=True)
    # Require all regression checks to pass before assembling any new release artifact.
    cmd = [java, "-Djava.awt.headless=true", "-cp", str(tests) + os.pathsep + test_cp, "local.nightvision.SelfTest"]
    if options.preview: cmd.append(options.preview.resolve())
    run(cmd)
    # Exercise the whole evidence workflow against the real early API, including its renamed getters.
    # A separate JVM/classpath prevents modern SDK classes from masking missing legacy methods.
    legacy_cp = os.pathsep.join(str(p) for p in [tests, classes, legacy_api, *paths[1:]])
    run([java, "-Djava.awt.headless=true", "-cp", legacy_cp, "local.nightvision.EvidenceSelfTest"])
    output = ROOT / "dist" / "nightvision-burp-0.5.4.jar"
    output.parent.mkdir(exist_ok=True)
    # A JAR is a ZIP containing the manifest, compiled classes/resources, and bundled libraries.
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nImplementation-Title: NightVision Finding Validator\r\nImplementation-Version: 0.5.4\r\n\r\n")
        for path in sorted(classes.rglob("*")):
            if path.is_file(): jar.write(path, path.relative_to(classes).as_posix())
        # Exclude Montoya (paths[0]): Burp supplies that API at runtime.
        for bundled in paths[1:]:
            with zipfile.ZipFile(bundled) as dependency:
                for item in dependency.infolist():
                    name = item.filename
                    # Dependency manifests/module descriptors do not describe this combined JAR.
                    if item.is_dir() or name.upper() == "META-INF/MANIFEST.MF" or name.endswith("module-info.class"):
                        continue
                    # Original signatures are invalid once dependency entries are repackaged.
                    if name.upper().endswith((".SF", ".RSA", ".DSA")): continue
                    jar.writestr(name, dependency.read(name))
        # Ship the third-party license texts alongside the bundled dependency code.
        for license_file in sorted((ROOT / "licenses").glob("*")):
            if license_file.is_file(): jar.write(license_file, "META-INF/licenses/" + license_file.name)
    print("Built " + str(output), flush=True)

if __name__ == "__main__":
    # Convert a failed compiler/test process into a concise command-line build error.
    try: build()
    except subprocess.CalledProcessError as error:
        raise SystemExit("Build or offline checks failed (exit " + str(error.returncode) + ").")
