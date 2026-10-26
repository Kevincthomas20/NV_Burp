package local.nightvision;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class NightVisionExtension implements BurpExtension {
    private MontoyaApi api;
    private NightVisionClient client;
    private final Supplier<NightVisionLogin> loginFactory;
    private final BiFunction<String, String, NightVisionClient> clientFactory;
    private volatile NightVisionLogin activeLogin;
    private final JTextField cliPath = new JTextField(32);
    private final JTextField savedLoginFile = new JTextField(48);
    private final JTextArea connectionDiagnostics = area(false);
    private final JTextField caFile = new JTextField(42);
    private final JCheckBox windowsRoots = new JCheckBox("Use trusted Windows roots", TlsSupport.onWindows());
    private TlsSupport.Options appliedTls = TlsSupport.Options.defaults();
    private JButton cancelSignIn;
    private JPanel root;
    private final JTextField origin = new JTextField(NightVisionClient.DEFAULT_ORIGIN, 26);
    private final JPasswordField token = new JPasswordField(22);
    private final JTextField project = new JTextField(22), scanId = new JTextField(28), search = new JTextField(30);
    private final JComboBox<ScanChoice> scans = new JComboBox<>();
    private final JLabel status = new JLabel("Sign in with SSO, use a saved login, enter an API token, or try the offline demo.");
    private final JTextArea details = area(false), request = area(true), response = area(false), raw = area(false), notes = area(true);
    private final JComboBox<Traffic.Message> capturedRequests = new JComboBox<>(), capturedResponses = new JComboBox<>();
    private final JLabel requestInfo = new JLabel("Select a finding."), responseInfo = new JLabel("Select a finding.");
    private boolean fillingTraffic;
    private final JTextField destination = new JTextField(50);
    private final JComboBox<String> verdict = new JComboBox<>(new String[]{"Not reviewed", "Confirmed", "False positive", "Needs review", "Retest passed"});
    private final List<Finding> findings = new ArrayList<>();
    private final List<JButton> buttons = new ArrayList<>();
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Severity", "Finding", "Method", "Host", "Path", "NightVision resolution", "Local validation"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JTable table = new JTable(model);
    private final TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
    private volatile SwingWorker<?, ?> worker;
    private String namespace = "offline-demo";
    private volatile boolean unloaded;

    public NightVisionExtension() { this(NightVisionLogin::new, null); }
    NightVisionExtension(Supplier<NightVisionLogin> loginFactory, BiFunction<String, String, NightVisionClient> clientFactory) {
        this.loginFactory = loginFactory; this.clientFactory = clientFactory;
    }

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("NightVision Finding Validator");
        api.extension().registerUnloadingHandler(() -> {
            unloaded = true;
            NightVisionLogin login = activeLogin;
            if (login != null) login.cancel();
            activeLogin = null;
            SwingWorker<?, ?> running = worker;
            if (running != null) running.cancel(true);
            worker = null;
            client = null;
            SwingUtilities.invokeLater(() -> token.setText(""));
        });
        SwingUtilities.invokeLater(() -> {
            if (unloaded) return;
            buildUi();
            api.userInterface().registerSuiteTab("NightVision", root);
            api.logging().logToOutput("NightVision validator 0.3.2 loaded. SSO uses the official NightVision CLI and its saved credential. The extension does not persist tokens or passwords. Target requests open in Repeater for manual sending.");
        });
    }
    private static JTextArea area(boolean editable) {
        JTextArea a = new JTextArea();
        a.setEditable(editable); a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); a.setTabSize(4);
        return a;
    }
    private JButton button(String text, Runnable action) {
        JButton b = new JButton(text); b.addActionListener(e -> action.run()); buttons.add(b); return b;
    }
    private static JPanel row(Component... components) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 7, 4));
        for (Component c : components) p.add(c);
        return p;
    }
    private void buildUi() {
        root = new JPanel(new BorderLayout(7, 7));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JPanel top = new JPanel(); top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(row(new JLabel("API origin"), origin, new JLabel("API token (memory only)"), token));
        String configured = api.persistence().preferences().getString("nightvision.cli.path");
        if (configured == null || configured.isBlank()) configured = System.getenv("NIGHTVISION_CLI_PATH");
        cliPath.setText(configured == null || configured.isBlank() ? "nightvision" : configured);
        cancelSignIn = new JButton("Cancel sign-in"); cancelSignIn.setEnabled(false);
        cancelSignIn.addActionListener(e -> cancelSignIn());
        top.add(row(new JLabel("NightVision CLI"), cliPath, button("Browse…", this::browseCli),
            button("Sign in with SSO", () -> connectLogin(true)), button("Use saved login", () -> connectLogin(false)), cancelSignIn));
        String savedPath = api.persistence().preferences().getString("nightvision.login.file");
        savedLoginFile.setText(savedPath == null ? "" : savedPath);
        savedLoginFile.setToolTipText("Optional file used by Use saved login; leave blank to find current CLI config automatically.");
        top.add(row(new JLabel("Saved login file (optional)"), savedLoginFile, button("Browse login file", this::browseLoginFile), new JLabel("Blank = auto-detect CLI config")));
        String ca = api.persistence().preferences().getString("nightvision.tls.ca.file"); caFile.setText(ca == null ? "" : ca);
        String useRoots = api.persistence().preferences().getString("nightvision.tls.windows.roots");
        if (useRoots != null) windowsRoots.setSelected(Boolean.parseBoolean(useRoots) && TlsSupport.onWindows());
        windowsRoots.setEnabled(TlsSupport.onWindows());
        top.add(row(new JLabel("Additional trusted CA (optional)"), caFile, button("Browse CA", this::browseCa), windowsRoots));
        top.add(row(new JLabel("Project UUID (optional)"), project,
            button("Connect / load scans", this::connect), button("Disconnect", this::disconnect), button("Offline demo", this::demo)));
        scans.setPreferredSize(new Dimension(650, 27));
        DefaultListCellRenderer scanRenderer = new DefaultListCellRenderer();
        scanRenderer.putClientProperty("html.disable", Boolean.TRUE);
        scans.setRenderer(scanRenderer);
        scans.addActionListener(e -> { ScanChoice s = (ScanChoice) scans.getSelectedItem(); if (s != null) scanId.setText(s.id()); });
        top.add(row(new JLabel("Scan"), scans));
        top.add(row(new JLabel("Scan UUID"), scanId, button("Load findings", this::loadFindings), button("Fetch full finding", this::fetchDetail)));
        top.add(row(new JLabel("Filter findings"), search, button("Export local validations", this::export)));
        root.add(top, BorderLayout.NORTH);

        table.setRowSorter(sorter); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24); table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        DefaultTableCellRenderer cell = new DefaultTableCellRenderer();
        cell.putClientProperty("html.disable", Boolean.TRUE); table.setDefaultRenderer(Object.class, cell);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Finding / evidence", new JScrollPane(details));
        tabs.addTab("Request (editable)", trafficPanel(true));
        tabs.addTab("Original response", trafficPanel(false));
        tabs.addTab("Full finding JSON", new JScrollPane(raw));
        connectionDiagnostics.setText("Use Sign in with SSO or Use saved login to collect connection diagnostics. Credential contents and raw CLI output are omitted.");
        tabs.addTab("Connection diagnostics", new JScrollPane(connectionDiagnostics));
        JScrollPane tablePane = new JScrollPane(table);
        tablePane.setColumnHeaderView(table.getTableHeader());
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePane, tabs);
        split.setResizeWeight(0.42); split.setDividerLocation(240); root.add(split, BorderLayout.CENTER);

        JPanel bottom = new JPanel(); bottom.setLayout(new BoxLayout(bottom, BoxLayout.Y_AXIS));
        bottom.add(row(new JLabel("Destination URL (verify host / port / TLS)"), destination, button("Open in Repeater", this::repeater)));
        bottom.add(row(new JLabel("Local validation"), verdict, button("Save local validation", this::saveValidation),
            new JLabel("Replay manually in Repeater; then record your result here.")));
        bottom.add(row(button("Mark false positive in NightVision", this::markFalsePositive),
            new JLabel("Updates the selected issue. Analyst notes stay local.")));
        notes.setRows(3); notes.setLineWrap(true); notes.setWrapStyleWord(true);
        JScrollPane notePane = new JScrollPane(notes); notePane.setBorder(BorderFactory.createTitledBorder("Analyst notes (saved locally only)"));
        bottom.add(notePane); bottom.add(status); root.add(bottom, BorderLayout.SOUTH);
    }
    private JPanel trafficPanel(boolean isRequest) {
        JComboBox<Traffic.Message> choices = isRequest ? capturedRequests : capturedResponses;
        JLabel info = isRequest ? requestInfo : responseInfo;
        DefaultListCellRenderer renderer = new DefaultListCellRenderer();
        renderer.putClientProperty("html.disable", Boolean.TRUE); choices.setRenderer(renderer);
        info.putClientProperty("html.disable", Boolean.TRUE);
        choices.setPreferredSize(new Dimension(780, 27));
        choices.addActionListener(e -> { if (!fillingTraffic) showTraffic(isRequest); });
        JPanel header = new JPanel(new BorderLayout(4, 4));
        header.add(row(new JLabel(isRequest ? "Captured request" : "Captured response"), choices), BorderLayout.NORTH);
        header.add(info, BorderLayout.SOUTH);
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(header, BorderLayout.NORTH); panel.add(new JScrollPane(isRequest ? request : response), BorderLayout.CENTER);
        return panel;
    }
    private void fillTraffic(Finding f) {
        fillingTraffic = true;
        try {
            capturedRequests.removeAllItems(); capturedResponses.removeAllItems();
            if (f != null) {
                f.requests().forEach(capturedRequests::addItem); f.responses().forEach(capturedResponses::addItem);
                // Prefer a usable capture while retaining unsupported entries for inspection.
                chooseUsable(capturedRequests); chooseUsable(capturedResponses);
            }
        } finally { fillingTraffic = false; }
        showTraffic(true); showTraffic(false);
    }
    private static void chooseUsable(JComboBox<Traffic.Message> choices) {
        for (int i = 0; i < choices.getItemCount(); i++) if (!choices.getItemAt(i).text().isEmpty()) { choices.setSelectedIndex(i); return; }
    }
    private void showTraffic(boolean isRequest) {
        JComboBox<Traffic.Message> choices = isRequest ? capturedRequests : capturedResponses;
        JTextArea editor = isRequest ? request : response;
        JLabel info = isRequest ? requestInfo : responseInfo;
        Traffic.Message message = (Traffic.Message) choices.getSelectedItem();
        choices.setEnabled(choices.getItemCount() > 1);
        editor.setText(message == null ? "" : message.text()); editor.setCaretPosition(0);
        info.setText(message == null
            ? "No captured HTTP " + (isRequest ? "request" : "response") + " returned. Use Fetch full finding; inspect Full finding JSON if still missing."
            : (choices.getSelectedIndex() + 1) + " of " + choices.getItemCount() + " — " + message.note());
        if (isRequest) {
            Finding f = selected();
            destination.setText(message != null && !message.destination().isBlank() ? message.destination() : f == null ? "" : f.targetUrl());
        }
    }
    private void filter() {
        String term = search.getText().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> e) {
                for (int i = 0; i < e.getValueCount(); i++) if (e.getStringValue(i).toLowerCase(Locale.ROOT).contains(term)) return true;
                return false;
            }
        });
    }
    private <T> void background(String message, Callable<T> work, Consumer<T> done) {
        if (worker != null && !worker.isDone()) return;
        buttons.forEach(b -> b.setEnabled(false)); origin.setEnabled(false); token.setEnabled(false); project.setEnabled(false); scanId.setEnabled(false); scans.setEnabled(false); cliPath.setEnabled(false); savedLoginFile.setEnabled(false);
        cancelSignIn.setEnabled(activeLogin != null); caFile.setEnabled(false); windowsRoots.setEnabled(false);
        table.setEnabled(false); search.setEnabled(false); notes.setEnabled(false); verdict.setEnabled(false); request.setEnabled(false); destination.setEnabled(false);
        capturedRequests.setEnabled(false); capturedResponses.setEnabled(false);
        status.setText(message);
        worker = new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return work.call(); }
            @Override protected void done() {
                if (unloaded) return;
                String failureDetails = "";
                try { done.accept(get()); }
                catch (Exception e) {
                    Throwable cause = e.getCause() == null ? e : e.getCause();
                    if (cause instanceof CancellationException) { status.setText("Sign-in canceled. The browser session and any CLI-saved login are kept."); return; }
                    String text = cause instanceof IllegalArgumentException || cause instanceof IllegalStateException
                        ? cause.getMessage() : "Connection failed (" + cause.getClass().getSimpleName() + "). Check network access and TLS trust.";
                    if (cause instanceof javax.net.ssl.SSLException ssl) text = TlsSupport.reason(ssl) + " See Connection diagnostics.";
                    failureDetails = TlsSupport.diagnostics(cause, appliedTls);
                    error(text);
                } finally {
                    worker = null;
                    connectionDiagnostics.setText((activeLogin == null ? "" : activeLogin.diagnostics() + "\n")
                        + "API connection settings\n" + TlsSupport.runtimeReport(appliedTls) + failureDetails);
                    connectionDiagnostics.setCaretPosition(0);
                    activeLogin = null; cancelSignIn.setEnabled(false);
                    buttons.forEach(b -> b.setEnabled(true)); origin.setEnabled(true); token.setEnabled(true); project.setEnabled(true); scanId.setEnabled(true); scans.setEnabled(true); cliPath.setEnabled(true); savedLoginFile.setEnabled(true);
                    caFile.setEnabled(true); windowsRoots.setEnabled(TlsSupport.onWindows());
                    table.setEnabled(true); search.setEnabled(true); notes.setEnabled(true); verdict.setEnabled(true); request.setEnabled(true); destination.setEnabled(true);
                    capturedRequests.setEnabled(capturedRequests.getItemCount() > 1); capturedResponses.setEnabled(capturedResponses.getItemCount() > 1);
                }
            }
        };
        worker.execute();
    }
    private void connect() {
        char[] chars = token.getPassword();
        String p = project.getText().trim(), base = origin.getText().trim();
        final String credential;
        try { NightVisionClient.apiOrigin(base); credential = new String(chars); if (credential.isBlank()) throw new IllegalArgumentException("Enter an API token or use an SSO login button."); }
        catch (RuntimeException e) { error(e.getMessage()); return; }
        finally { Arrays.fill(chars, '\0'); }
        TlsSupport.Options tls = tlsOptions();
        disconnectState();
        background("Connecting and loading scans…", () -> {
            NightVisionClient pending = createClient(base, credential, tls);
            return new LoginConnection(pending, pending.scans(p), "Connected using API token.");
        }, session -> connected(session.client(), session.scans(), session.message()));
    }
    private NightVisionClient createClient(String base, String credential, TlsSupport.Options tls) {
        return clientFactory == null ? new NightVisionClient(base, credential, tls) : clientFactory.apply(base, credential);
    }
    private TlsSupport.Options tlsOptions() {
        appliedTls = new TlsSupport.Options(caFile.getText(), windowsRoots.isSelected());
        try {
            if (!appliedTls.caFile().isBlank() || api.persistence().preferences().getString("nightvision.tls.ca.file") != null)
                api.persistence().preferences().setString("nightvision.tls.ca.file", appliedTls.caFile());
            if (appliedTls.windowsRoots() != TlsSupport.onWindows() || api.persistence().preferences().getString("nightvision.tls.windows.roots") != null)
                api.persistence().preferences().setString("nightvision.tls.windows.roots", Boolean.toString(appliedTls.windowsRoots()));
        } catch (RuntimeException ignored) {}
        return appliedTls;
    }
    private void browseCa() {
        JFileChooser picker = new JFileChooser(); picker.setDialogTitle("Select your IT-provided trusted CA certificate (PEM or DER)");
        if (picker.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) caFile.setText(picker.getSelectedFile().getAbsolutePath());
    }
    private void connected(NightVisionClient pending, List<JsonObject> rows, String message) {
        client = pending; namespace = pending.origin(); scans.removeAllItems();
        for (JsonObject s : rows) scans.addItem(new ScanChoice(Finding.s(s, "id"),
            Finding.s(s, "target_name") + " | " + Finding.s(s, "status_value") + " | " + Finding.s(s, "created_at") + " | " + Finding.s(s, "id")));
        status.setText(message + " " + rows.size() + " scans loaded. Select a scan or paste a scan UUID.");
    }
    private void browseCli() {
        JFileChooser picker = new JFileChooser(); picker.setDialogTitle("Select the official NightVision CLI executable (nightvision or nightvision.exe)");
        if (picker.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) {
            cliPath.setText(picker.getSelectedFile().getAbsolutePath()); rememberCliPath();
        }
    }
    private void rememberCliPath() {
        try { api.persistence().preferences().setString("nightvision.cli.path", cliPath.getText().trim()); }
        catch (RuntimeException ignored) { /* An unavailable preference store does not prevent this sign-in. */ }
    }
    private void browseLoginFile() {
        JFileChooser picker = new JFileChooser(); picker.setDialogTitle("Select NightVision CLI config (nightvision.yml) or legacy token file");
        if (picker.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) {
            savedLoginFile.setText(picker.getSelectedFile().getAbsolutePath());
            try { api.persistence().preferences().setString("nightvision.login.file", savedLoginFile.getText()); } catch (RuntimeException ignored) {}
        }
    }
    private void connectLogin(boolean browser) {
        if (worker != null) return;
        String p = project.getText().trim(); String executable = cliPath.getText().trim(); String selectedFile = savedLoginFile.getText().trim();
        try {
            NightVisionLogin.requireProductionOrigin(origin.getText());
            if (!p.isBlank()) NightVisionClient.id(p);
            if (browser && executable.isBlank()) throw new IllegalArgumentException("Select the NightVision CLI executable using Browse.");
        } catch (RuntimeException e) { error(e.getMessage()); return; }
        NightVisionLogin login = loginFactory.get();
        TlsSupport.Options tls = tlsOptions();
        disconnectState(); token.setText(""); activeLogin = login;
        if (browser) rememberCliPath();
        else try {
            if (!selectedFile.isBlank() || api.persistence().preferences().getString("nightvision.login.file") != null)
                api.persistence().preferences().setString("nightvision.login.file", selectedFile);
        } catch (RuntimeException ignored) {}
        background(browser ? "Complete NightVision SSO in your browser. Sign-in waits up to five minutes…" : "Checking your saved NightVision login and loading scans…", () -> {
            String credential = browser ? login.signIn(executable) : login.savedToken(selectedFile);
            login.checkCancelled();
            NightVisionClient pending = createClient(NightVisionClient.DEFAULT_ORIGIN, credential, tls);
            try {
                JsonObject user = pending.currentUser(); login.checkCancelled();
                List<JsonObject> rows = pending.scans(p); login.checkCancelled();
                String email = Finding.s(user, "email");
                return new LoginConnection(pending, rows, email.isBlank() ? "Connected using NightVision CLI login." : "Connected as " + email + " using NightVision CLI login.");
            } catch (NightVisionClient.ApiException e) {
                if (e.status() == 401) throw new IllegalStateException("NightVision rejected the saved login (HTTP 401). Click Sign in with SSO to authenticate again.");
                if (e.status() == 403) throw new IllegalStateException("NightVision denied access (HTTP 403). Check your account permissions; sign in again if you need a different account.");
                throw e;
            }
        }, session -> { login.checkCancelled(); connected(session.client(), session.scans(), session.message()); });
    }
    private void cancelSignIn() {
        NightVisionLogin login = activeLogin;
        if (login == null) return;
        login.cancel();
        SwingWorker<?, ?> running = worker;
        if (running != null) running.cancel(true);
    }
    private record LoginConnection(NightVisionClient client, List<JsonObject> scans, String message) {}
    private void disconnectState() {
        client = null; namespace = "offline-demo"; scans.removeAllItems(); scanId.setText(""); setFindings(List.of());
    }
    private void disconnect() { disconnectState(); token.setText(""); status.setText("Disconnected. In-memory credential cleared. Saved CLI login is kept."); }
    private void loadFindings() {
        NightVisionClient c = client;
        if (c == null) { error("Connect to NightVision first."); return; }
        String id = scanId.getText().trim();
        background("Loading all pages of findings…", () -> c.issues(id), rows -> {
            setFindings(rows); status.setText(rows.size() + " findings loaded. Select one to inspect evidence.");
        });
    }
    private void fetchDetail() {
        Finding selected = selected(); NightVisionClient c = client;
        if (selected == null) { error("Select a finding."); return; }
        if (c == null) { error("The offline demo already includes the complete sample finding."); return; }
        background("Fetching full finding…", () -> c.issue(selected.id()), data -> {
            for (int i = 0; i < findings.size(); i++) if (findings.get(i).id().equals(selected.id())) {
                findings.set(i, new Finding(data)); updateRow(i); break;
            }
            showSelected(); status.setText("Full finding retrieved. Review the request before opening Repeater.");
        });
    }
    private Finding selected() {
        int row = table.getSelectedRow();
        if (row < 0) return null;
        int index = table.convertRowIndexToModel(row);
        return index < findings.size() ? findings.get(index) : null;
    }
    private void setFindings(List<JsonObject> rows) {
        table.clearSelection(); model.setRowCount(0); findings.clear();
        for (JsonObject data : rows) { findings.add(new Finding(data)); model.addRow(new Object[7]); updateRow(findings.size() - 1); }
        showSelected();
    }
    private void updateRow(int i) {
        Finding f = findings.get(i); JsonObject a = annotation(f.id());
        String state = Finding.s(a, "status"); if (state.isBlank()) state = "Not reviewed";
        Object[] cells = {f.severity(), f.title(), Finding.s(f.data(), "http_method"), Finding.s(f.data(), "fqdn"), Finding.s(f.data(), "url_path"), f.resolutionDisplay(), state};
        for (int c = 0; c < cells.length; c++) model.setValueAt(cells[c], i, c);
    }
    private void showSelected() {
        Finding f = selected();
        if (f == null) {
            for (JTextArea a : List.of(details, request, response, raw, notes)) a.setText("");
            fillTraffic(null); destination.setText(""); verdict.setSelectedIndex(0); return;
        }
        JsonObject a = annotation(f.id());
        details.setText(f.title() + "\nSeverity: " + f.severity() + "\nIssue ID: " + f.id()
            + "\nNightVision resolution: " + f.resolutionDisplay()
            + "\nParameter: " + Finding.s(f.data(), "parameter_name") + " (" + Finding.s(f.data(), "parameter_type") + ")"
            + "\n\nPayload:\n" + Finding.s(f.data(), "payload") + "\n\nEvidence:\n" + Finding.s(f.data(), "evidence")
            + "\n\nEvidence details:\n" + Finding.s(f.data(), "evidence_details")
            + "\n\nNightVision explanation:\n" + Finding.s(f.data(), "ai_explanation")
            + "\n\nCaptured requests: " + f.requests().size() + "; captured responses: " + f.responses().size()
            + (f.request().isBlank() ? "\nNo usable request text. Fetch full finding, inspect JSON, or paste the original request in the Request tab." : "\nRequest evidence is available. Structured captures are reconstructed for display and replay; verify destination, headers, body, and current credentials.")
            + "\nRequest and response selectors are independent; matching positions do not prove an exchange pairing.");
        fillTraffic(f); raw.setText(Finding.JSON.toJson(f.data()));
        String state = Finding.s(a, "status"); verdict.setSelectedItem(state.isBlank() ? "Not reviewed" : state);
        notes.setText(Finding.s(a, "notes"));
        for (JTextArea text : List.of(details, request, response, raw, notes)) text.setCaretPosition(0);
    }
    private void repeater() {
        Finding f = selected(); if (f == null) { error("Select a finding first."); return; }
        try {
            URI u = Finding.destination(destination.getText());
            String message = Finding.prepareRequest(request.getText());
            int port = u.getPort() == -1 ? (u.getScheme().equalsIgnoreCase("https") ? 443 : 80) : u.getPort();
            HttpService service = HttpService.httpService(u.getHost(), port, u.getScheme().equalsIgnoreCase("https"));
            api.repeater().sendToRepeater(HttpRequest.httpRequest(service, message), "NV " + f.id().substring(0, Math.min(8, f.id().length())));
            status.setText("Opened in Repeater. Verify the request, then click Send there. No validation result was inferred.");
        } catch (RuntimeException e) { error(e instanceof IllegalArgumentException ? e.getMessage() : "Could not create the Burp request. Check the request and destination."); }
    }
    private String annotationKey(String id) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest((namespace + "\n" + id).getBytes(StandardCharsets.UTF_8));
            return "nightvision.validation." + HexFormat.of().formatHex(digest);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
    private JsonObject annotation(String id) {
        String saved = api.persistence().preferences().getString(annotationKey(id));
        if (saved == null) return new JsonObject();
        try { return JsonParser.parseString(saved).getAsJsonObject(); }
        catch (RuntimeException e) { return new JsonObject(); }
    }
    private void saveValidation() {
        Finding f = selected(); if (f == null) { error("Select a finding first."); return; }
        JsonObject value = annotation(f.id()).deepCopy();
        value.addProperty("status", Objects.toString(verdict.getSelectedItem())); value.addProperty("notes", notes.getText());
        value.addProperty("updated_at", Instant.now().toString());
        String json = Finding.JSON.toJson(value);
        if (json.length() > 7000 || json.getBytes(StandardCharsets.UTF_8).length > 7000) { error("Shorten the notes to fit the local preference store (7,000 bytes)."); return; }
        try {
            api.persistence().preferences().setString(annotationKey(f.id()), json);
            updateRow(table.convertRowIndexToModel(table.getSelectedRow()));
            status.setText("Validation saved in this Burp installation. NightVision was not updated.");
        } catch (RuntimeException e) { error("Could not save local validation to Burp preferences."); }
    }
    private void markFalsePositive() {
        Finding f = selected(); NightVisionClient c = client;
        if (f == null) { error("Select a finding first."); return; }
        if (c == null) { error("Connect to NightVision to update a finding. The offline demo cannot change remote findings."); return; }
        String noteText = notes.getText();
        JsonObject sizeCheck = new JsonObject(); sizeCheck.addProperty("notes", noteText);
        if (Finding.JSON.toJson(sizeCheck).getBytes(StandardCharsets.UTF_8).length > 6200) {
            error("Shorten the analyst notes before updating so they can be saved with the sync result."); return;
        }
        background("Marking the selected finding false positive in NightVision, then verifying…",
            () -> c.markFalsePositive(f.id()), refreshed -> recordRemoteUpdate(f.id(), refreshed, noteText));
    }
    private void recordRemoteUpdate(String issueId, JsonObject refreshed, String noteText) {
        String now = Instant.now().toString();
        JsonObject value = annotation(issueId).deepCopy();
        value.addProperty("status", "False positive"); value.addProperty("notes", noteText); value.addProperty("updated_at", now);
        JsonObject sync = new JsonObject(); sync.addProperty("status", "verified"); sync.addProperty("resolution", NightVisionClient.FALSE_POSITIVE_RESOLUTION); sync.addProperty("verified_at", now);
        value.add("nightvision_sync", sync);
        boolean localSaved = false;
        try {
            api.persistence().preferences().setString(annotationKey(issueId), Finding.JSON.toJson(value));
            localSaved = true;
        } catch (RuntimeException e) { /* The verified remote change still succeeded. */ }
        for (int i = 0; i < findings.size(); i++) if (findings.get(i).id().equals(issueId)) {
            findings.set(i, new Finding(refreshed)); updateRow(i); break;
        }
        showSelected();
        if (!localSaved) { verdict.setSelectedItem("False positive"); notes.setText(noteText); }
        status.setText(localSaved
            ? "NightVision marked this issue False positive and read-back verified it. Analyst notes saved locally."
            : "NightVision marked this issue False positive and read-back verified it. Local notes could not be saved; copy them before leaving.");
    }
    private void export() {
        if (findings.isEmpty()) { error("Load findings first."); return; }
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("nightvision-validations.json"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) return;
        Path path = chooser.getSelectedFile().toPath();
        if (Files.exists(path) && JOptionPane.showConfirmDialog(root, "Replace the existing export?", "Export", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        JsonObject doc = new JsonObject(); doc.addProperty("format", "nightvision-burp-validations-v1");
        doc.addProperty("api_origin", namespace); doc.addProperty("exported_at", Instant.now().toString());
        JsonArray rows = new JsonArray();
        for (Finding f : findings) {
            JsonObject r = new JsonObject(); r.addProperty("issue_id", f.id()); r.addProperty("scan_id", Finding.s(f.data(), "scan_id"));
            r.addProperty("nightvision_resolution", Finding.s(f.data(), "resolution"));
            r.addProperty("finding", f.title()); r.addProperty("target", f.targetUrl()); r.add("local_validation", annotation(f.id())); rows.add(r);
        }
        doc.add("findings", rows);
        try { Files.writeString(path, Finding.JSON.toJson(doc), StandardCharsets.UTF_8); status.setText("Saved validation export. It includes saved notes, with no API token or raw traffic."); }
        catch (Exception e) { error("Could not write the export file."); }
    }
    private void demo() {
        disconnect();
        try (var input = getClass().getResourceAsStream("/demo-findings.json")) {
            if (input == null) throw new IllegalStateException("Missing demo resource.");
            JsonArray array = JsonParser.parseString(new String(input.readAllBytes(), StandardCharsets.UTF_8)).getAsJsonArray();
            List<JsonObject> rows = new ArrayList<>(); for (JsonElement e : array) rows.add(e.getAsJsonObject());
            setFindings(rows); if (model.getRowCount() > 0) table.setRowSelectionInterval(0, 0);
            status.setText("Offline demo loaded. Example traffic uses example.invalid; no network call was made.");
        } catch (Exception e) { error("Could not load the demo findings."); }
    }
    private void error(String text) { status.setText("Error: " + text); }
    private record ScanChoice(String id, String label) { @Override public String toString() { return label; } }
}
