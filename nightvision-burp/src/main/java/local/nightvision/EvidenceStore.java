package local.nightvision;

import com.google.gson.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * Stores explicitly attached Burp messages outside Java preferences. Each immutable
 * attachment has metadata and two binary files, committed by a directory rename.
 * Bytes are preserved as supplied by Burp; nothing here sends traffic or changes a verdict.
 */
final class EvidenceStore {
    static final int MAX_REQUEST = 1024 * 1024, MAX_RESPONSE = 2 * 1024 * 1024, MAX_RECORDS = 50;
    private static final int MAX_METADATA = 128 * 1024;
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private final Path root;
    EvidenceStore(Path root) { this.root = root.toAbsolutePath().normalize(); }

    /** The origin and issue UUID identify the attachment's owner; other fields are descriptive snapshots. */
    record Target(String origin, String issueId, String scanId, String title, String url) {
        Target {
            if (!"offline-demo".equals(origin)) NightVisionClient.apiOrigin(origin);
            issueId = NightVisionClient.id(issueId);
            scanId = scanId == null || scanId.isBlank() ? "" : NightVisionClient.id(scanId);
            title = clipped(Objects.toString(title, ""), 512); url = clipped(Objects.toString(url, ""), 8192);
        }
        @Override public String toString() { return title + " | " + url + " | " + issueId; }
    }
    /** A defensive snapshot prevents later Burp editor changes from altering a pending attachment. */
    record Captured(byte[] request, byte[] response, String url, String host, int port, boolean tls, String tool, int status) {
        Captured {
            checkBytes(request, MAX_REQUEST); checkBytes(response, MAX_RESPONSE);
            request = request.clone(); response = response.clone();
            url = clipped(Objects.toString(url, ""), 8192); host = checked(host, 512);
            tool = checked(tool, 80);
            if (port < 1 || port > 65535 || status < 100 || status > 599) throw new IllegalArgumentException("The selected HTTP exchange has invalid service or response metadata.");
        }
        @Override public byte[] request() { return request.clone(); }
        @Override public byte[] response() { return response.clone(); }
    }
    record Labels(String label, String context, String testedAt, String notes) {
        Labels {
            label = checked(label == null || label.isBlank() ? "Manual retest" : label.trim(), 160);
            context = checked(Objects.toString(context, ""), 500); notes = checked(Objects.toString(notes, ""), 4000);
            testedAt = Objects.toString(testedAt, "").trim();
            if (!testedAt.isEmpty()) try { testedAt = Instant.parse(testedAt).toString(); }
            catch (RuntimeException e) { throw new IllegalArgumentException("Tested at must be a UTC ISO timestamp, such as 2026-10-26T16:30:00Z, or blank."); }
        }
    }
    /** Metadata can be listed without loading potentially large HTTP bodies into the interface. */
    record Metadata(int schema, String id, Target target, String attachedAt, Labels labels, String tool,
                    String url, String host, int port, boolean tls, int status,
                    int requestBytes, int responseBytes, String requestSha256, String responseSha256) {
        Metadata {
            if (schema != 1 || target == null || labels == null) throw new IllegalArgumentException("Unsupported evidence metadata.");
            id = NightVisionClient.id(id); attachedAt = Instant.parse(attachedAt).toString();
            tool = checked(tool, 80); url = checked(url, 8192); host = checked(host, 512);
            if (port < 1 || port > 65535 || status < 100 || status > 599 || requestBytes < 1 || requestBytes > MAX_REQUEST || responseBytes < 1 || responseBytes > MAX_RESPONSE
                || requestSha256 == null || !requestSha256.matches("[0-9a-f]{64}") || responseSha256 == null || !responseSha256.matches("[0-9a-f]{64}"))
                throw new IllegalArgumentException("Invalid evidence metadata.");
        }
        @Override public String toString() { return attachedAt + " | " + labels.label() + " | " + tool + " | HTTP " + status; }
    }
    record Entry(Metadata metadata, byte[] request, byte[] response) {
        Entry { request = request.clone(); response = response.clone(); }
        @Override public byte[] request() { return request.clone(); }
        @Override public byte[] response() { return response.clone(); }
    }
    /** Text-only reports use a safe representation of binary bodies; raw files remain complete. */
    record ReportEvidence(Metadata metadata, String requestText, String responseText) {}

    /** Saves a new attachment, verifies its hashes, and publishes only a complete record. */
    Metadata save(Target target, Captured captured, Labels labels) {
        Path issue = issueFolder(target), staged = null;
        try {
            directory(root); directory(issue);
            Path lockPath = issue.resolve(".lock");
            if (Files.isSymbolicLink(lockPath)) throw new IOException();
            try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock lock = lock(channel)) {
                if (list(target).size() >= MAX_RECORDS) throw new IllegalStateException("This finding already has 50 evidence attachments. Remove an attachment before saving another.");
                String id = UUID.randomUUID().toString();
                Metadata metadata = new Metadata(1, id, target, Instant.now().toString(), labels, captured.tool(), captured.url(), captured.host(), captured.port(), captured.tls(), captured.status(),
                    captured.request.length, captured.response.length, sha(captured.request), sha(captured.response));
                byte[] json = JSON.toJson(metadata).getBytes(StandardCharsets.UTF_8);
                if (json.length > MAX_METADATA) throw new IllegalArgumentException("Evidence metadata is too large. Shorten the label, context, or notes.");
                staged = Files.createTempDirectory(issue, ".capture-"); permissions(staged, true);
                write(staged.resolve("request.bin"), captured.request); write(staged.resolve("response.bin"), captured.response);
                write(staged.resolve("metadata.json"), json);
                readAt(staged, target, id); // Verify bytes before the record becomes visible to readers.
                move(staged, issue.resolve(id)); staged = null;
                return read(target, id).metadata();
            }
        } catch (IOException e) { throw failure("Evidence save was not confirmed. Check the folder and write access, then refresh before retrying.", e); }
        finally { if (staged != null) cleanup(staged); }
    }

    /** Lists small metadata records only; incomplete staging/removal directories are excluded. */
    List<Metadata> list(Target target) {
        Path issue = issueFolder(target);
        if (!Files.exists(issue, LinkOption.NOFOLLOW_LINKS)) return List.of();
        try {
            regularDirectory(issue);
            List<Metadata> records = new ArrayList<>();
            try (DirectoryStream<Path> paths = Files.newDirectoryStream(issue)) {
                for (Path path : paths) {
                    String id = path.getFileName().toString();
                    if (!uuid(id)) continue;
                    records.add(metadata(path, target, id));
                    if (records.size() > MAX_RECORDS) throw new IOException();
                }
            }
            records.sort(Comparator.comparing((Metadata m) -> Instant.parse(m.attachedAt())).reversed().thenComparing(Metadata::id));
            return List.copyOf(records);
        } catch (IOException | RuntimeException e) { throw failure("Could not read this finding's evidence list. Check the evidence folder for incomplete or invalid records.", e); }
    }

    /** Loads and verifies a single selected record, including immutable content hashes. */
    Entry read(Target target, String id) {
        try { return readAt(issueFolder(target).resolve(NightVisionClient.id(id)), target, NightVisionClient.id(id)); }
        catch (IOException | RuntimeException e) { throw failure("Evidence could not be verified. A file is missing, changed, unsupported, or belongs to another finding.", e); }
    }
    private Entry readAt(Path path, Target target, String id) throws IOException {
        Metadata metadata = metadata(path, target, id);
        byte[] request = bytes(path.resolve("request.bin"), MAX_REQUEST), response = bytes(path.resolve("response.bin"), MAX_RESPONSE);
        if (!sha(request).equals(metadata.requestSha256()) || !sha(response).equals(metadata.responseSha256())) throw new IOException();
        return new Entry(metadata, request, response);
    }
    private Metadata metadata(Path path, Target target, String id) throws IOException {
        regularDirectory(path);
        Metadata metadata = JSON.fromJson(new String(bytes(path.resolve("metadata.json"), MAX_METADATA), StandardCharsets.UTF_8), Metadata.class);
        if (metadata == null || !metadata.id().equals(id) || !metadata.target().origin().equals(target.origin()) || !metadata.target().issueId().equals(target.issueId())) throw new IOException();
        for (String file : List.of("request.bin", "response.bin")) {
            Path raw = path.resolve(file); regularFile(raw);
            if (Files.size(raw) != (file.equals("request.bin") ? metadata.requestBytes() : metadata.responseBytes())) throw new IOException();
        }
        return metadata;
    }

    /** Detaches a verified record atomically, then deletes only its three known files. */
    boolean remove(Target target, String id) {
        Path issue = issueFolder(target);
        try {
            regularDirectory(issue);
            Path lockPath = issue.resolve(".lock");
            if (Files.isSymbolicLink(lockPath)) throw new IOException();
            try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock lock = lock(channel)) {
                read(target, id);
                Path path = issue.resolve(NightVisionClient.id(id));
                try (var contents = Files.list(path)) { if (!contents.map(p -> p.getFileName().toString()).sorted().toList().equals(List.of("metadata.json", "request.bin", "response.bin"))) throw new IOException(); }
                Path removed = issue.resolve(".removed-" + id + "-" + UUID.randomUUID());
                move(path, removed);
                return cleanup(removed);
            }
        } catch (IOException e) { throw failure("Evidence removal was not confirmed. Refresh the list and check the folder before retrying.", e); }
    }

    ReportEvidence forReport(Entry entry) { return new ReportEvidence(entry.metadata(), messageText(entry.request), messageText(entry.response)); }

    /** Binary or non-UTF-8 bodies get an explicit display note, with exact bytes retained on disk. */
    static String messageText(byte[] bytes) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (text.indexOf('\0') < 0) return text;
        } catch (CharacterCodingException ignored) {}
        int end = -1;
        for (int i = 0; i < Math.min(bytes.length - 3, 65536); i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') { end = i + 4; break; }
            if (bytes[i] == '\n' && bytes[i + 1] == '\n') { end = i + 2; break; }
        }
        return (end < 0 ? "" : new String(bytes, 0, end, StandardCharsets.ISO_8859_1))
            + "[Binary or non-UTF-8 " + (end < 0 ? "message" : "body") + " omitted from text display; complete bytes are saved locally.]";
    }
    static String displayText(byte[] bytes) { return clipped(messageText(bytes), 65536); }
    private Path issueFolder(Target target) { return root.resolve(sha((target.origin() + "\n" + target.issueId()).getBytes(StandardCharsets.UTF_8))); }
    static String sha(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable."); }
    }
    private static String checked(String value, int max) {
        if (value == null || value.length() > max || value.indexOf('\0') >= 0) throw new IllegalArgumentException("Evidence label, context, or notes exceed their supported limits or contain NUL.");
        return value;
    }
    private static String clipped(String value, int max) {
        if (value.length() <= max) return value;
        String marker = "\n[Display truncated]"; int end = max - marker.length();
        if (Character.isHighSurrogate(value.charAt(end - 1))) end--;
        return value.substring(0, end) + marker;
    }
    private static void checkBytes(byte[] value, int max) { if (value == null || value.length == 0 || value.length > max) throw new IllegalArgumentException("Evidence requires a request up to 1 MiB and a response up to 2 MiB."); }
    private static boolean uuid(String value) { try { return UUID.fromString(value).toString().equals(value); } catch (RuntimeException e) { return false; } }
    private static void regularDirectory(Path path) throws IOException { if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException(); }
    private static void regularFile(Path path) throws IOException { if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException(); }
    private static byte[] bytes(Path path, int max) throws IOException {
        regularFile(path);
        try (InputStream in = Files.newInputStream(path)) { byte[] bytes = in.readNBytes(max + 1); if (bytes.length > max) throw new IOException(); return bytes; }
    }
    private static void directory(Path path) throws IOException { if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) { Files.createDirectories(path); permissions(path, true); } regularDirectory(path); }
    private static void permissions(Path path, boolean directory) throws IOException {
        if (Files.getFileStore(path).supportsFileAttributeView("posix")) Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
    }
    private static void write(Path path, byte[] bytes) throws IOException { Files.createFile(path); permissions(path, false); Files.write(path, bytes); }
    private static void move(Path from, Path to) throws IOException {
        try { Files.move(from, to, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException e) { throw new IllegalStateException("This evidence folder does not support atomic saves. Choose a local folder on a supported filesystem."); }
    }
    private static FileLock lock(FileChannel channel) throws IOException {
        try { FileLock lock = channel.tryLock(); if (lock == null) throw new IOException(); return lock; }
        catch (OverlappingFileLockException e) { throw new IOException(); }
    }
    private static boolean cleanup(Path directory) {
        boolean complete = true;
        for (String name : List.of("request.bin", "response.bin", "metadata.json")) try { Files.deleteIfExists(directory.resolve(name)); } catch (IOException e) { complete = false; }
        try { Files.deleteIfExists(directory); } catch (IOException e) { complete = false; }
        return complete;
    }
    private static IllegalStateException failure(String message, Exception cause) { return new IllegalStateException(message, cause); }
}
