package local.nightvision;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.*;
import javax.swing.*;
import java.awt.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.*;

/**
 * Owns the explicit attach dialog and local evidence tab. File operations use
 * background workers and immutable finding targets. Selecting another finding
 * cannot redirect a pending save or display a stale response under the new row.
 */
final class EvidenceController implements ContextMenuItemsProvider {
    record Choice(EvidenceStore.Target target, EvidenceStore.Labels labels, Path folder) {}
    @FunctionalInterface interface Prompt {
        Choice choose(EvidenceStore.Captured captured, List<EvidenceStore.Target> targets, EvidenceStore.Target selected, Path folder);
    }
    private final MontoyaApi api;
    private final Component parent;
    private final Supplier<List<EvidenceStore.Target>> targets;
    private final Supplier<EvidenceStore.Target> selected;
    private final BooleanSupplier apiBusy;
    private final JPanel panel = new JPanel(new BorderLayout(5, 5));
    private final JTextField folder = new JTextField(48);
    private final JComboBox<EvidenceStore.Metadata> entries = new JComboBox<>();
    private final JTextArea metadata = area(), request = area(), response = area();
    private final JLabel state = new JLabel("Select a finding to view saved retest evidence.");
    private final JButton browse = new JButton("Browse folder"), refresh = new JButton("Refresh"), remove = new JButton("Remove attachment");
    private volatile SwingWorker<?, ?> loadWorker, saveWorker;
    private volatile boolean closed;
    private long generation;
    private boolean filling;
    private String lastCompatibilityFailure = ""; // Avoid repeating the same API warning on every right-click.
    // Test seams exercise the actual context-menu action without displaying modal dialogs.
    Prompt prompt = this::prompt;
    Consumer<String> notice;

    EvidenceController(MontoyaApi api, Component parent, Supplier<List<EvidenceStore.Target>> targets,
                       Supplier<EvidenceStore.Target> selected, BooleanSupplier apiBusy) {
        this.api = api; this.parent = parent; this.targets = targets; this.selected = selected; this.apiBusy = apiBusy;
        notice = text -> JOptionPane.showMessageDialog(parent, text, "NightVision retest evidence", JOptionPane.INFORMATION_MESSAGE);
        String configured = null;
        try { configured = api.persistence().preferences().getString("nightvision.evidence.folder"); } catch (RuntimeException ignored) {}
        try { folder.setText(configured == null || configured.isBlank() ? Path.of(System.getProperty("user.home"), "NightVision-Burp", "evidence").toString() : configured); }
        catch (RuntimeException e) { folder.setText(""); }
        folder.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void changed() {
                ++generation; if (loadWorker != null) loadWorker.cancel(true); loadWorker = null;
                filling = true; entries.removeAllItems(); filling = false;
                metadata.setText(""); request.setText(""); response.setText(""); state.setText("Evidence folder changed. Click Refresh to load attachments."); controls();
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { changed(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { changed(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { changed(); }
        });
        DefaultListCellRenderer renderer = new DefaultListCellRenderer(); renderer.putClientProperty("html.disable", Boolean.TRUE); entries.setRenderer(renderer);
        entries.setPreferredSize(new Dimension(720, 27));
        entries.addActionListener(e -> { if (!filling) loadEntry(); });
        browse.addActionListener(e -> {
            Path chosen = chooseFolder(parent, folder.getText());
            if (chosen != null) { folder.setText(chosen.toString()); rememberFolder(chosen); selectionChanged(); }
        });
        refresh.addActionListener(e -> selectionChanged());
        remove.addActionListener(e -> remove());
        JPanel top = new JPanel(); top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(row(new JLabel("Evidence folder"), folder, browse)); top.add(row(new JLabel("Attachment"), entries, refresh, remove));
        top.add(row(new JLabel("Attach a completed exchange from Burp: right-click → Attach retest evidence to NightVision…")));
        metadata.setRows(4);
        JTabbedPane messages = new JTabbedPane(); messages.addTab("Retest request", new JScrollPane(request)); messages.addTab("Retest response", new JScrollPane(response));
        messages.addTab("Attachment details / hashes", new JScrollPane(metadata)); messages.setSelectedIndex(1);
        panel.add(top, BorderLayout.NORTH); panel.add(messages, BorderLayout.CENTER); panel.add(state, BorderLayout.SOUTH);
        controls();
    }
    JPanel panel() { return panel; }
    Path folderPath() { return parseFolder(folder.getText()); }
    static Path parseFolder(String text) {
        try { if (text == null || text.isBlank()) throw new IllegalArgumentException(); return Path.of(text.trim()).toAbsolutePath().normalize(); }
        catch (RuntimeException e) { throw new IllegalArgumentException("Choose a valid local evidence folder in the Retest evidence tab."); }
    }

    /** The menu references one explicitly selected exchange, not a globally active request. */
    @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (closed) return List.of();
        try {
            Optional<HttpRequestResponse> picked = EvidenceCapture.selected(event);
            if (picked.isEmpty()) return List.of();
            HttpRequestResponse exchange = picked.get();
            String tool = event.toolType() == null ? "UNKNOWN" : event.toolType().name();
            JMenuItem item = new JMenuItem("Attach retest evidence to NightVision…");
            // Check availability inside the compatibility guard as well; getters can fail on older hosts.
            boolean completed = EvidenceCapture.completed(exchange);
            item.setEnabled(completed);
            item.setToolTipText(completed ? "Choose the finding to attach this completed exchange to."
                : "Send this request and wait for a response before attaching retest evidence.");
            item.addActionListener(e -> onEdt(() -> attach(exchange, tool)));
            return List.of(item);
        } catch (RuntimeException | LinkageError e) {
            // A callback failure otherwise removes the entire menu contribution. Keep a clickable,
            // diagnostic-only action visible; it cannot capture a different message or save evidence.
            String message = compatibilityFailure(e);
            JMenuItem item = new JMenuItem("Attach retest evidence to NightVision…");
            item.setToolTipText("Burp could not read this exchange. Click for compatibility details.");
            item.addActionListener(action -> onEdt(() -> { if (!closed) { state.setText(message); notice.accept(message); } }));
            return List.of(item);
        }
    }

    /** Captures bytes before the dialog, then saves to the chosen immutable target and folder. */
    private void attach(HttpRequestResponse exchange, String tool) {
        if (closed) return;
        if (apiBusy.getAsBoolean() || saving()) { notice.accept("Wait for the current operation to finish, then attach the exchange."); return; }
        try {
            List<EvidenceStore.Target> available = List.copyOf(targets.get());
            if (available.isEmpty()) throw new IllegalArgumentException("Load scan findings in the NightVision tab before attaching evidence.");
            EvidenceStore.Captured captured = EvidenceCapture.snapshot(exchange, tool);
            Choice choice = prompt.choose(captured, available, selected.get(), folderPath());
            if (choice == null || closed) return;
            if (!available.contains(choice.target())) throw new IllegalArgumentException("Choose a finding from the loaded collection.");
            folder.setText(choice.folder().toAbsolutePath().normalize().toString());
            state.setText("Saving and verifying local evidence…");
            saveWorker = new SwingWorker<EvidenceStore.Metadata, Void>() {
                @Override protected EvidenceStore.Metadata doInBackground() { return new EvidenceStore(choice.folder()).save(choice.target(), captured, choice.labels()); }
                @Override protected void done() {
                    if (closed) return;
                    try {
                        EvidenceStore.Metadata saved = get();
                        boolean remembered = rememberFolder(choice.folder());
                        String message = "Evidence saved locally and SHA-256 verified for issue " + saved.target().issueId() + ". Local verdict and NightVision were not changed."
                            + (remembered ? "" : " The folder setting could not be remembered; keep its path for the next session.");
                        state.setText(message); notice.accept(message);
                    } catch (Exception e) { String message = failure(e); state.setText(message); notice.accept(message); }
                    finally { saveWorker = null; controls(); selectionChanged(); }
                }
            };
            controls(); saveWorker.execute();
        } catch (LinkageError e) { String message = compatibilityFailure(e); state.setText(message); notice.accept(message); }
        catch (RuntimeException e) { String message = failure(e); state.setText(message); notice.accept(message); }
    }

    /** Log only API/version metadata once per distinct failure, never message bodies or raw exception text. */
    private synchronized String compatibilityFailure(Throwable error) {
        String type = error.getClass().getSimpleName(), missing = RepeaterBridge.missingMember(error);
        String detail = type + (missing.isBlank() ? "" : "; missing member: " + missing);
        if (!detail.equals(lastCompatibilityFailure)) {
            lastCompatibilityFailure = detail;
            try { api.logging().logToError("NightVision 0.5.8 evidence: could not read the selected HTTP exchange (" + detail
                + "). Editor, exchange, and byte access use public current/pre-1.0 API aliases resolved at runtime. Burp version: " + RepeaterBridge.hostVersion(api)
                + ". No other selection was substituted. Raw HTTP and other exception text omitted."); }
            catch (RuntimeException | LinkageError ignored) { /* The visible action still explains the failure. */ }
        }
        return "Could not read this Burp HTTP exchange (" + type + "). See Extensions > NightVision > Errors for compatibility details. No evidence was saved.";
    }
    private static void onEdt(Runnable action) { if (SwingUtilities.isEventDispatchThread()) action.run(); else SwingUtilities.invokeLater(action); }

    /** A dialog confirms the finding, context, optional actual test time, and raw local storage destination. */
    private Choice prompt(EvidenceStore.Captured captured, List<EvidenceStore.Target> targets, EvidenceStore.Target selected, Path initialFolder) {
        JComboBox<EvidenceStore.Target> finding = new JComboBox<>(targets.toArray(EvidenceStore.Target[]::new));
        DefaultListCellRenderer renderer = new DefaultListCellRenderer(); renderer.putClientProperty("html.disable", Boolean.TRUE); finding.setRenderer(renderer);
        finding.setPreferredSize(new Dimension(850, 27)); if (selected != null && targets.contains(selected)) finding.setSelectedItem(selected);
        JTextArea owner = area(); owner.setRows(3); owner.setLineWrap(true);
        Runnable describe = () -> { var target = (EvidenceStore.Target) finding.getSelectedItem(); owner.setText("API origin: " + target.origin() + "\nIssue: " + target.issueId() + " / Scan: " + target.scanId() + "\nFinding target: " + target.url()); };
        finding.addActionListener(e -> describe.run()); describe.run();
        JTextField label = new JTextField("Manual retest", 28), context = new JTextField(36), testedAt = new JTextField(25), path = new JTextField(initialFolder.toString(), 55);
        JTextArea notes = new JTextArea(3, 60); notes.setLineWrap(true); notes.setWrapStyleWord(true);
        JTextArea req = area(), res = area(); req.setText(EvidenceStore.displayText(captured.request())); res.setText(EvidenceStore.displayText(captured.response())); req.setCaretPosition(0); res.setCaretPosition(0);
        JTabbedPane preview = new JTabbedPane(); preview.addTab("Selected Burp request", new JScrollPane(req)); preview.addTab("Selected Burp response", new JScrollPane(res));
        preview.setPreferredSize(new Dimension(900, 240));
        JButton browse = new JButton("Browse folder"); browse.addActionListener(e -> { Path picked = chooseFolder(parent, path.getText()); if (picked != null) path.setText(picked.toString()); });
        JPanel form = new JPanel(); form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.add(row(new JLabel("Attach to finding"), finding)); form.add(new JScrollPane(owner));
        form.add(row(new JLabel("Label"), label, new JLabel("Test context / role (optional)"), context));
        form.add(row(new JLabel("Tested at UTC (optional, ISO timestamp)"), testedAt, new JLabel("Blank = test time not asserted")));
        form.add(row(new JLabel("Local evidence folder"), path, browse));
        form.add(row(new JLabel("Source: " + captured.tool() + " | HTTP " + captured.status() + " | Request " + captured.request().length + " bytes | Response " + captured.response().length + " bytes")));
        form.add(preview); form.add(row(new JLabel("Evidence notes (optional, up to 4,000 characters)"))); form.add(new JScrollPane(notes));
        form.add(row(new JLabel("Raw HTTP is saved locally and may contain session credentials. HTML reports redact common credential patterns.")));
        JScrollPane scroll = new JScrollPane(form); scroll.setPreferredSize(new Dimension(1000, 650));
        while (true) {
            int action = JOptionPane.showOptionDialog(parent, scroll, "Attach manual retest evidence", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null,
                new Object[]{"Save evidence", "Cancel"}, "Save evidence");
            if (action != 0) return null;
            try { return new Choice((EvidenceStore.Target) finding.getSelectedItem(), new EvidenceStore.Labels(label.getText(), context.getText(), testedAt.getText(), notes.getText()), parseFolder(path.getText())); }
            catch (RuntimeException e) { JOptionPane.showMessageDialog(parent, "Check the evidence folder, timestamp, and field length limits.", "Evidence options", JOptionPane.ERROR_MESSAGE); }
        }
    }

    /** Refresh is read-only. Late callbacks are ignored after selection/folder changes or unload. */
    void selectionChanged() {
        long current = ++generation; if (loadWorker != null) loadWorker.cancel(true); loadWorker = null;
        filling = true; entries.removeAllItems(); filling = false; request.setText(""); response.setText(""); metadata.setText("");
        if (closed) return;
        EvidenceStore.Target target;
        Path path;
        try { target = selected.get(); if (target == null) { state.setText("Select a finding to view saved retest evidence."); controls(); return; } path = folderPath(); }
        catch (RuntimeException e) { state.setText(failure(e)); controls(); return; }
        state.setText("Reading saved evidence list…");
        loadWorker = new SwingWorker<List<EvidenceStore.Metadata>, Void>() {
            @Override protected List<EvidenceStore.Metadata> doInBackground() { return new EvidenceStore(path).list(target); }
            @Override protected void done() {
                if (closed || current != generation) return;
                loadWorker = null;
                try {
                    List<EvidenceStore.Metadata> saved = get();
                    filling = true; for (var entry : saved) entries.addItem(entry); filling = false;
                    state.setText(saved.size() + " saved retest attachments.");
                    if (!saved.isEmpty()) loadEntry(); else metadata.setText("No saved retest evidence. Attach a completed exchange from a Burp message's context menu.");
                } catch (Exception e) { filling = false; state.setText(failure(e)); }
                controls();
            }
        };
        controls(); loadWorker.execute();
    }
    private void loadEntry() {
        EvidenceStore.Metadata chosen = (EvidenceStore.Metadata) entries.getSelectedItem();
        if (chosen == null || closed) return;
        long current = ++generation; if (loadWorker != null) loadWorker.cancel(true);
        Path path;
        try { path = folderPath(); } catch (RuntimeException e) { state.setText(failure(e)); return; }
        request.setText(""); response.setText(""); metadata.setText("Verifying saved message hashes…");
        loadWorker = new SwingWorker<EvidenceView, Void>() {
            @Override protected EvidenceView doInBackground() {
                var entry = new EvidenceStore(path).read(chosen.target(), chosen.id());
                return new EvidenceView(entry.metadata(), EvidenceStore.displayText(entry.request()), EvidenceStore.displayText(entry.response()));
            }
            @Override protected void done() {
                if (closed || current != generation) return;
                loadWorker = null;
                try {
                    EvidenceView view = get(); var m = view.metadata();
                    metadata.setText("Label: " + m.labels().label() + "\nIssue: " + m.target().issueId() + " | Source: " + m.tool() + " | HTTP " + m.status()
                        + "\nScan when attached: " + m.target().scanId() + "\nAttached UTC: " + m.attachedAt() + " | Tested at: " + (m.labels().testedAt().isBlank() ? "Not supplied" : m.labels().testedAt())
                        + "\nContext: " + m.labels().context() + "\nCaptured URL: " + m.url() + "\nService: " + m.host() + ":" + m.port() + " | TLS: " + m.tls()
                        + "\nRequest SHA-256: " + m.requestSha256() + "\nResponse SHA-256: " + m.responseSha256() + "\nAttachment notes:\n" + m.labels().notes());
                    request.setText(view.request()); response.setText(view.response());
                    for (JTextArea area : List.of(metadata, request, response)) area.setCaretPosition(0);
                    state.setText("Stored message hashes verified. Raw messages are local; no vulnerability verdict was inferred.");
                } catch (Exception e) { metadata.setText(failure(e)); state.setText(failure(e)); }
                controls();
            }
        };
        controls(); loadWorker.execute();
    }
    private record EvidenceView(EvidenceStore.Metadata metadata, String request, String response) {}

    private void remove() {
        var chosen = (EvidenceStore.Metadata) entries.getSelectedItem(); if (chosen == null || saving() || closed) return;
        if (JOptionPane.showConfirmDialog(parent, "Remove this saved evidence attachment? Local validation and NightVision will not change.", "Remove retest evidence", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        Path path = folderPath();
        saveWorker = new SwingWorker<Boolean, Void>() {
            @Override protected Boolean doInBackground() { return new EvidenceStore(path).remove(chosen.target(), chosen.id()); }
            @Override protected void done() {
                if (closed) return;
                try { notice.accept(get() ? "Evidence attachment removed locally." : "Evidence removed from the finding; local cleanup is incomplete. Check the evidence folder."); }
                catch (Exception e) { notice.accept(failure(e)); }
                finally { saveWorker = null; selectionChanged(); controls(); }
            }
        };
        controls(); saveWorker.execute();
    }

    private boolean saving() { return saveWorker != null; }
    private void controls() { boolean enabled = !closed && !saving(); folder.setEnabled(enabled); browse.setEnabled(enabled); refresh.setEnabled(enabled); entries.setEnabled(enabled && entries.getItemCount() > 0); remove.setEnabled(enabled && entries.getSelectedItem() != null && (loadWorker == null || loadWorker.isDone())); }
    private boolean rememberFolder(Path path) {
        try { String value = path.toAbsolutePath().normalize().toString(); api.persistence().preferences().setString("nightvision.evidence.folder", value); return value.equals(api.persistence().preferences().getString("nightvision.evidence.folder")); }
        catch (RuntimeException e) { return false; }
    }
    void close() { closed = true; if (loadWorker != null) loadWorker.cancel(true); if (saveWorker != null) saveWorker.cancel(true); }
    private static String failure(Throwable error) {
        Throwable cause = error instanceof java.util.concurrent.ExecutionException && error.getCause() != null ? error.getCause() : error;
        if (cause instanceof CancellationException) return "Evidence operation canceled.";
        return cause instanceof IllegalArgumentException || cause instanceof IllegalStateException ? Objects.toString(cause.getMessage(), "Evidence operation failed.")
            : "Evidence operation failed. Check the selected folder and try refreshing the list.";
    }
    private static Path chooseFolder(Component parent, String initial) {
        JFileChooser chooser = new JFileChooser(); chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); chooser.setDialogTitle("Choose the local retest evidence folder");
        if (!initial.isBlank()) chooser.setSelectedFile(new java.io.File(initial));
        return chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath().toAbsolutePath().normalize() : null;
    }
    private static JTextArea area() { JTextArea area = new JTextArea(); area.setEditable(false); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); return area; }
    private static JPanel row(Component... components) { JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3)); for (Component component : components) panel.add(component); return panel; }
}
