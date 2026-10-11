package burp2model.ui;

import burp2model.engine.Analysis;
import burp2model.engine.Diff;
import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Query;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/** The burp2model tab: overview, leads, surface, requests, query, changes, roles and settings. */
public final class MainPanel extends JPanel {
    /** What the extension supplies: how to save settings and how to log. */
    public interface Host {
        String get(String key, String def);

        void set(String key, String value);

        void log(String line);

        Session session(String name) throws java.io.IOException;
    }

    private final Host host;
    private Session session;
    private final JLabel status = new JLabel(" ");
    private final JTabbedPane tabs = new JTabbedPane();

    // overview
    private final JTextArea overview = new JTextArea();

    // leads
    private final DefaultTableModel leadsModel = Tables.model("Severity", "Endpoint", "Why", "Next step");
    private final JTable leadsTable = Tables.table(leadsModel);
    private final EvidenceViewer leadsViewer = new EvidenceViewer();
    private List<Analysis.Lead> leads = new ArrayList<>();

    // surface
    private final JComboBox<String> typeBox = new JComboBox<>(new String[] {"endpoint", "route", "script", "third_party", "cookie", "auth", "parameter", "host", "tech", "operation", "role"});
    private final JTextField surfaceFilter = new JTextField(24);
    private final DefaultTableModel surfaceModel = Tables.model("Name", "State", "Statuses", "Roles", "Requests", "Where");
    private final JTable surfaceTable = Tables.table(surfaceModel);
    private final EvidenceViewer surfaceViewer = new EvidenceViewer();
    private final JTextArea surfaceDetail = detail();
    private final List<Model.Node> surfaceRows = new ArrayList<>();

    // requests
    private final DefaultTableModel reqModel = Tables.model("#", "Method", "Host", "Path", "Status", "Role");
    private final JTable reqTable = Tables.table(reqModel);
    private final JTextField reqFilter = new JTextField(24);
    private final EvidenceViewer reqViewer = new EvidenceViewer();

    // query
    private final JTextField queryField = new JTextField();
    private final DefaultTableModel queryModel = Tables.model();
    private final JTable queryTable = Tables.table(queryModel);
    private final JTextArea queryText = detail();
    private final JLabel queryNote = new JLabel(" ");
    private final EvidenceViewer queryViewer = new EvidenceViewer();
    private final List<String> queryHistory = new ArrayList<>();
    private int historyPos;
    private Query.Result lastResult;
    private final JTabbedPane queryOut = new JTabbedPane();

    // changes
    private final DefaultTableModel buildsModel = Tables.model("#", "When (UTC)", "Label", "Nodes", "Edges", "Requests");
    private final JTable buildsTable = Tables.table(buildsModel);
    private final JTextArea diffText = detail();

    // roles
    private final JComboBox<String> lowBox = new JComboBox<>();
    private final JComboBox<String> highBox = new JComboBox<>();
    private final JTextArea rolesText = detail();

    // settings
    private final JTextField nameField = new JTextField(16);
    private final JTextField roleField = new JTextField(14);
    private final JTextField scopeField = new JTextField(30);
    private final JCheckBox replaceRole = new JCheckBox("Replace this role's earlier requests when sending");

    public MainPanel(Host host) {
        super(new BorderLayout());
        this.host = host;
        try {
            this.session = host.session(host.get("app", "burp"));
        } catch (Exception e) {
            host.log("burp2model: could not open the saved model (" + e.getMessage() + ")");
        }
        overview.setEditable(false);
        overview.setFont(Tables.mono());
        overview.setLineWrap(true);
        overview.setWrapStyleWord(true);
        overview.setMargin(new Insets(10, 12, 10, 12));
        tabs.addTab("Overview", new JScrollPane(overview));
        tabs.addTab("To check", leadsTab());
        tabs.addTab("Surface", surfaceTab());
        tabs.addTab("Requests", requestsTab());
        tabs.addTab("Query", queryTab());
        tabs.addTab("Changes", changesTab());
        tabs.addTab("Roles", rolesTab());
        tabs.addTab("Settings", settingsTab());
        add(tabs, BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        add(status, BorderLayout.SOUTH);
        refresh();
    }

    private static JTextArea detail() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(Tables.mono());
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        return a;
    }

    private Model model() {
        return session == null ? null : session.model();
    }

    // ------------------------------------------------------------------ public

    /** Called after a send: reload every view from the session. */
    public void refresh() {
        SwingUtilities.invokeLater(this::refreshNow);
    }

    public Session session() {
        return session;
    }

    public void say(String text) {
        SwingUtilities.invokeLater(() -> status.setText(text));
    }

    public String role() {
        String r = roleField.getText().strip();
        return r.isEmpty() ? null : r;
    }

    public boolean replaceRoleOnSend() {
        return replaceRole.isSelected();
    }

    public List<String> scope() {
        List<String> out = new ArrayList<>();
        for (String s : scopeField.getText().split("[,\\s]+")) {
            if (!s.isBlank()) {
                out.add(s.strip());
            }
        }
        return out;
    }

    private void refreshNow() {
        Model m = model();
        leadsViewer.setModel(m);
        surfaceViewer.setModel(m);
        reqViewer.setModel(m);
        queryViewer.setModel(m);
        overview.setText(overviewText(m));
        overview.setCaretPosition(0);
        fillLeads(m);
        fillSurface();
        fillRequests(m);
        fillBuilds();
        fillRoles(m);
        nameField.setText(host.get("app", "burp"));
        roleField.setText(host.get("role", ""));
        scopeField.setText(host.get("scope", ""));
        replaceRole.setSelected("1".equals(host.get("replace", "0")));
        status.setText(m == null ? "No requests yet. Right-click requests in Burp and choose Send to burp2model."
                : m.name + ": " + m.nodes.size() + " nodes · " + m.edges.size() + " edges · " + m.evidenceLog.size() + " requests · build "
                + session.builds().size());
    }

    // ------------------------------------------------------------------ overview

    @SuppressWarnings("unchecked")
    private String overviewText(Model m) {
        if (m == null) {
            return "burp2model\n\n"
                    + "Right-click requests in Proxy history or Site map and choose \"Send to burp2model\".\n"
                    + "The model builds here, inside Burp: no files to export and no other program to run.\n\n"
                    + "Every claim cites the request that shows it. Values (cookies, tokens, keys, personal data) are masked\n"
                    + "before anything is stored. This is a model builder, not a scanner.";
        }
        Map<String, Object> c = m.counts();
        Map<String, Object> st = (Map<String, Object>) c.get("api_state");
        StringBuilder h = new StringBuilder();
        h.append(m.name).append("\n\n");
        h.append(c.get("endpoints")).append(" API endpoints on ").append(c.get("routes")).append(" pages, from ").append(m.evidenceLog.size())
                .append(" requests.   Scope: ").append(String.join(", ", m.scope)).append("\n\n");
        h.append("Code vs runtime:  ").append(st.getOrDefault("BOTH", 0L)).append(" in both · ").append(st.getOrDefault("RUNTIME_ONLY", 0L))
                .append(" traffic only · ").append(st.getOrDefault("STATIC_ONLY", 0L)).append(" named in code, never called\n\n");
        if (!m.stack.isEmpty()) {
            Map<String, List<String>> byCat = new TreeMap<>();
            for (Map<String, Object> t : m.stack) {
                String v = String.valueOf(t.get("version"));
                byCat.computeIfAbsent(String.valueOf(t.get("category")), k -> new ArrayList<>()).add(t.get("name") + (v.isEmpty() ? "" : " " + v));
            }
            h.append("Technology stack (hints from headers, cookies, pages and hosts):\n");
            byCat.forEach((k, v) -> h.append("  ").append(k).append(": ").append(String.join(", ", v)).append('\n'));
            h.append('\n');
        }
        List<Analysis.Lead> top = Analysis.leads(m);
        h.append("Check these first (").append(top.size()).append(" leads: hypotheses to verify, never findings)\n");
        int n = 1;
        for (Analysis.Lead l : top.subList(0, Math.min(6, top.size()))) {
            h.append("  ").append(n++).append(". ").append(l.endpoint().label).append("  —  ").append(l.signals().get(0).title()).append('\n');
        }
        h.append("\nOpen questions: ").append(c.get("unknowns")).append("   Third parties: ").append(c.get("third_parties"))
                .append("   Cookies: ").append(c.get("cookies")).append("   Masked secrets: ").append(c.get("secrets")).append("\n\n");
        h.append("Browse the surface in Surface, read the requests behind every claim in Requests, ask questions in Query,\n"
                + "and see what changed between sends in Changes.");
        return h.toString();
    }

    // ------------------------------------------------------------------ leads

    private Component leadsTab() {
        leadsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(leadsTable);
            if (i >= 0 && i < leads.size()) {
                Analysis.Lead l = leads.get(i);
                leadsViewer.show(l.endpoint().evidence, l.endpoint().label);
            }
        });
        Tables.widths(leadsTable, 70, 260, 520, 300);
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(leadsTable), leadsViewer);
        sp.setResizeWeight(0.45);
        return sp;
    }

    private void fillLeads(Model m) {
        leads = m == null ? new ArrayList<>() : Analysis.leads(m);
        List<Object[]> rows = new ArrayList<>();
        for (Analysis.Lead l : leads) {
            Analysis.Signal s = l.signals().get(0);
            String sev = l.sev().equals("hot") ? "High" : l.sev().equals("warn") ? "Medium" : "Note";
            rows.add(new Object[] {sev, l.endpoint().label, s.title() + (l.signals().size() > 1 ? " (+" + (l.signals().size() - 1) + " more)" : ""), s.next()});
        }
        Tables.fill(leadsModel, rows);
        leadsViewer.clear();
    }

    // ------------------------------------------------------------------ surface

    private Component surfaceTab() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Show"));
        top.add(typeBox);
        top.add(new JLabel("Filter"));
        top.add(surfaceFilter);
        typeBox.addActionListener(e -> fillSurface());
        surfaceFilter.getDocument().addDocumentListener(new SimpleDoc(() -> Tables.filter(surfaceTable, surfaceFilter.getText())));
        surfaceTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(surfaceTable);
            if (i >= 0 && i < surfaceRows.size()) {
                Model.Node n = surfaceRows.get(i);
                surfaceViewer.show(n.evidence, n.label);
                surfaceDetail.setText(nodeDetail(n));
                surfaceDetail.setCaretPosition(0);
            }
        });
        Tables.widths(surfaceTable, 420, 110, 90, 100, 80, 220);
        JSplitPane lower = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, surfaceViewer, new JScrollPane(surfaceDetail));
        lower.setResizeWeight(0.75);
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(surfaceTable), lower);
        sp.setResizeWeight(0.5);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void fillSurface() {
        Model m = model();
        surfaceRows.clear();
        List<Object[]> rows = new ArrayList<>();
        if (m != null) {
            String type = (String) typeBox.getSelectedItem();
            List<Model.Node> ns = new ArrayList<>();
            for (Model.Node n : m.nodes.values()) {
                if (n.type.equals(type)) {
                    ns.add(n);
                }
            }
            ns.sort(java.util.Comparator.comparing(n -> n.label));
            for (Model.Node n : ns) {
                surfaceRows.add(n);
                Object st = n.attrs.get("api_state");
                Object statuses = n.attrs.get("statuses");
                Object reqs = n.attrs.get("requests");
                rows.add(new Object[] {n.label, st == null ? "" : st, statuses == null ? "" : String.valueOf(statuses).replace("[", "").replace("]", ""),
                        String.join(",", n.roles), reqs == null ? String.valueOf(n.evidence.size()) : String.valueOf(reqs),
                        n.attrs.get("host") == null ? "" : String.valueOf(n.attrs.get("host"))});
            }
        }
        Tables.fill(surfaceModel, rows);
        Tables.filter(surfaceTable, surfaceFilter.getText());
        surfaceViewer.clear();
        surfaceDetail.setText("");
    }

    @SuppressWarnings("unchecked")
    private String nodeDetail(Model.Node n) {
        Model m = model();
        StringBuilder sb = new StringBuilder(n.type).append("  ").append(n.label).append('\n').append("id: ").append(n.id).append('\n');
        for (Map.Entry<String, Object> a : n.attrs.entrySet()) {
            sb.append(a.getKey()).append(": ").append(a.getValue() instanceof Map || a.getValue() instanceof List ? Json.write(a.getValue()) : a.getValue()).append('\n');
        }
        if (!n.roles.isEmpty()) {
            sb.append("roles: ").append(String.join(", ", n.roles)).append('\n');
        }
        if (m != null) {
            sb.append("\nconnections:\n");
            int shown = 0;
            for (Model.Edge e : m.edges) {
                if ((e.src.equals(n.id) || e.dst.equals(n.id)) && shown++ < 40) {
                    Model.Node o = m.nodes.get(e.src.equals(n.id) ? e.dst : e.src);
                    sb.append(e.src.equals(n.id) ? "  → " : "  ← ").append(e.type).append(" (").append(e.state.toLowerCase()).append(") ")
                            .append(o == null ? "?" : o.label).append('\n');
                }
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ requests

    private Component requestsTab() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Filter"));
        top.add(reqFilter);
        reqFilter.getDocument().addDocumentListener(new SimpleDoc(() -> Tables.filter(reqTable, reqFilter.getText())));
        reqTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(reqTable);
            if (i >= 0) {
                int id = (Integer) reqModel.getValueAt(i, 0);
                reqViewer.show(List.of(id), "ev_" + id);
            }
        });
        Tables.widths(reqTable, 50, 70, 220, 420, 60, 80);
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(reqTable), reqViewer);
        sp.setResizeWeight(0.45);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    @SuppressWarnings("unchecked")
    private void fillRequests(Model m) {
        reqModel.setRowCount(0);
        if (m == null) {
            return;
        }
        for (Map<String, Object> ev : m.evidenceLog) {
            Map<String, Object> rq = ev.get("request") instanceof Map<?, ?> r ? (Map<String, Object>) r : Map.of();
            String[] parts = String.valueOf(rq.getOrDefault("line", "")).split(" ");
            reqModel.addRow(new Object[] {((Number) ev.get("id")).intValue(), ev.get("method"), ev.get("host"), parts.length >= 2 ? parts[1] : ev.get("path"),
                    ev.get("status") == null ? "" : String.valueOf(ev.get("status")), ev.get("role") == null ? "" : ev.get("role")});
        }
        Tables.filter(reqTable, reqFilter.getText());
    }

    // ------------------------------------------------------------------ query

    private Component queryTab() {
        JPanel top = new JPanel(new BorderLayout(6, 0));
        top.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JButton run = new JButton("Run");
        JButton help = new JButton("Help");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        buttons.add(run);
        buttons.add(help);
        top.add(new JLabel("Query"), BorderLayout.WEST);
        top.add(queryField, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);
        run.addActionListener(e -> runQuery(queryField.getText()));
        help.addActionListener(e -> runQuery("help"));
        queryField.addActionListener(e -> runQuery(queryField.getText()));
        queryField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_UP && historyPos > 0) {
                    queryField.setText(queryHistory.get(--historyPos));
                } else if (e.getKeyCode() == KeyEvent.VK_DOWN && historyPos < queryHistory.size() - 1) {
                    queryField.setText(queryHistory.get(++historyPos));
                }
            }
        });
        JPanel examples = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        for (String ex : new String[] {"list-apis", "reconcile", "static-only", "req.method:POST AND resp.code.gte:400", "node.type:endpoint AND node.state:STATIC_ONLY",
            "privileged", "auth-surface", "secrets", "unknowns", "third-parties", "stats"}) {
            JButton b = new JButton(ex.length() > 28 ? ex.substring(0, 26) + "…" : ex);
            b.setToolTipText(ex);
            b.setMargin(new Insets(1, 6, 1, 6));
            b.addActionListener(e -> {
                queryField.setText(ex);
                runQuery(ex);
            });
            examples.add(b);
        }
        JPanel head = new JPanel(new BorderLayout());
        head.add(top, BorderLayout.NORTH);
        head.add(examples, BorderLayout.CENTER);
        head.add(queryNote, BorderLayout.SOUTH);
        queryNote.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));

        queryTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || lastResult == null) {
                return;
            }
            int i = Tables.selected(queryTable);
            if (i >= 0 && i < lastResult.rows().size()) {
                Map<String, Object> row = lastResult.rows().get(i);
                List<Integer> evs = evidenceOf(row);
                queryViewer.show(evs, evs.isEmpty() ? "" : "ev_" + evs.get(0));
            }
        });
        queryOut.addTab("Table", new JScrollPane(queryTable));
        queryOut.addTab("Text", new JScrollPane(queryText));
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, queryOut, queryViewer);
        sp.setResizeWeight(0.55);
        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private static List<Integer> evidenceOf(Map<String, Object> row) {
        List<Integer> out = new ArrayList<>();
        for (String key : new String[] {"ev", "evidence"}) {
            Object v = row.get(key);
            List<?> items = v instanceof List<?> l ? l : v == null ? List.of() : List.of(v);
            for (Object o : items) {
                String s = String.valueOf(o);
                if (s.startsWith("ev_") && s.substring(3).matches("\\d+")) {
                    out.add(Integer.parseInt(s.substring(3)));
                }
            }
        }
        return out;
    }

    /** Run a query as if it were typed in the Query tab. */
    public void ask(String text) {
        queryField.setText(text);
        runQuery(text);
    }

    private void runQuery(String text) {
        Model m = model();
        if (m == null) {
            queryNote.setText("Nothing to query yet. Send some requests first.");
            return;
        }
        if (text == null || text.isBlank()) {
            return;
        }
        if (queryHistory.isEmpty() || !queryHistory.get(queryHistory.size() - 1).equals(text)) {
            queryHistory.add(text);
        }
        historyPos = queryHistory.size();
        Query q = new Query(m);
        q.history = id -> session.historyOf(id);
        q.changedSince = ref -> {
            try {
                int older = resolveBuild(ref);
                int newer = session.builds().size();
                if (older == newer) {
                    throw new Query.QueryError("build #" + older + " is the latest; nothing to compare yet");
                }
                return Diff.formatText(session.diff(older, newer));
            } catch (java.io.IOException e) {
                throw new Query.QueryError(e.getMessage());
            }
        };
        try {
            Query.Result r = q.run(text);
            lastResult = r;
            queryNote.setText(r.note().contains("\n") ? "see Text" : r.note());
            queryText.setText(r.kind().equals("text") ? r.note() : "");
            queryText.setCaretPosition(0);
            if (r.kind().equals("text")) {
                queryModel.setRowCount(0);
                queryModel.setColumnCount(0);
                queryOut.setSelectedIndex(1);
            } else {
                queryModel.setColumnCount(0);
                for (String c : r.columns()) {
                    queryModel.addColumn(c);
                }
                queryModel.setRowCount(0);
                for (Map<String, Object> row : r.rows()) {
                    Object[] cells = new Object[r.columns().size()];
                    for (int i = 0; i < cells.length; i++) {
                        Object v = row.get(r.columns().get(i));
                        cells[i] = v instanceof List<?> l ? String.join(",", l.stream().map(String::valueOf).toList()) : v == null ? "" : String.valueOf(v);
                    }
                    queryModel.addRow(cells);
                }
                queryOut.setSelectedIndex(0);
            }
            queryViewer.clear();
        } catch (Query.QueryError e) {
            queryNote.setText("error: " + e.getMessage());
            lastResult = null;
        }
    }

    private int resolveBuild(String ref) {
        List<Session.BuildInfo> bs = session.builds();
        String r = ref.strip().toLowerCase();
        if (r.equals("previous")) {
            if (bs.size() < 2) {
                throw new Query.QueryError("only one build so far");
            }
            return bs.size() - 1;
        }
        if (r.equals("first")) {
            return 1;
        }
        String num = r.startsWith("#") ? r.substring(1) : r;
        if (num.matches("\\d+")) {
            int n = Integer.parseInt(num);
            if (n >= 1 && n <= bs.size()) {
                return n;
            }
            throw new Query.QueryError("no build #" + n);
        }
        for (int i = bs.size() - 1; i >= 0; i--) {
            if (bs.get(i).label().equalsIgnoreCase(ref.strip())) {
                return bs.get(i).id();
            }
        }
        throw new Query.QueryError("no build matches '" + ref + "'");
    }

    // ------------------------------------------------------------------ changes

    private Component changesTab() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton prev = new JButton("What changed since the previous build");
        JButton sel = new JButton("Compare selected build with latest");
        top.add(prev);
        top.add(sel);
        prev.addActionListener(e -> diffBuilds(session == null ? 0 : session.builds().size() - 1, session == null ? 0 : session.builds().size()));
        sel.addActionListener(e -> {
            int i = Tables.selected(buildsTable);
            if (i >= 0) {
                diffBuilds((Integer) buildsModel.getValueAt(i, 0), session.builds().size());
            }
        });
        Tables.widths(buildsTable, 40, 170, 200, 70, 70, 80);
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(buildsTable), new JScrollPane(diffText));
        sp.setResizeWeight(0.25);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void diffBuilds(int older, int newer) {
        if (session == null || older < 1 || newer < 2 || older >= newer) {
            diffText.setText("Send more requests first: a comparison needs two builds.");
            return;
        }
        try {
            diffText.setText(Diff.formatText(session.diff(older, newer)));
            diffText.setCaretPosition(0);
        } catch (Exception e) {
            diffText.setText("could not compare: " + e.getMessage());
        }
    }

    private void fillBuilds() {
        buildsModel.setRowCount(0);
        if (session == null) {
            return;
        }
        for (Session.BuildInfo b : session.builds()) {
            buildsModel.addRow(new Object[] {b.id(), b.builtAt().replace('T', ' ').replace("Z", ""), b.label(), b.nodes(), b.edges(), b.requests()});
        }
        if (session.builds().size() >= 2) {
            diffBuilds(session.builds().size() - 1, session.builds().size());
        } else {
            diffText.setText(session.builds().isEmpty() ? "" : "One build so far. Send more requests and this shows what changed.");
        }
    }

    // ------------------------------------------------------------------ roles

    @SuppressWarnings("unchecked")
    private Component rolesTab() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Lower-privilege role"));
        top.add(lowBox);
        top.add(new JLabel("Higher-privilege role"));
        top.add(highBox);
        JButton go = new JButton("Compare");
        top.add(go);
        go.addActionListener(e -> {
            Model m = model();
            if (m == null || lowBox.getSelectedItem() == null || highBox.getSelectedItem() == null) {
                rolesText.setText("Send requests under at least two roles first (set a role in Settings before each send).");
                return;
            }
            Map<String, Object> r = Analysis.crossRole(m, (String) lowBox.getSelectedItem(), (String) highBox.getSelectedItem());
            StringBuilder sb = new StringBuilder();
            section(sb, "'" + r.get("low") + "' reached privileged-looking endpoints", (List<Object>) r.get("low_reached_privileged"));
            section(sb, "'" + r.get("high") + "' reached, '" + r.get("low") + "' never tried", (List<Object>) r.get("high_only"));
            section(sb, "both roles got 2xx", (List<Object>) r.get("shared_same_success"));
            sb.append("\nEach is a hypothesis, not a finding.");
            rolesText.setText(sb.toString());
            rolesText.setCaretPosition(0);
        });
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(rolesText), BorderLayout.CENTER);
        return p;
    }

    @SuppressWarnings("unchecked")
    private static void section(StringBuilder sb, String title, List<Object> items) {
        sb.append(title).append(" (").append(items.size()).append(")\n");
        for (Object o : items) {
            Map<String, Object> e = (Map<String, Object>) o;
            sb.append("  ").append(e.get("endpoint")).append("   ");
            for (Object ev : (List<Object>) e.get("evidence")) {
                sb.append("ev_").append(ev).append(' ');
            }
            sb.append("  ").append(e.get("statuses")).append("\n      unknown: ").append(e.get("unknown")).append(" · next: ").append(e.get("next")).append('\n');
        }
        sb.append('\n');
    }

    private void fillRoles(Model m) {
        Object low = lowBox.getSelectedItem();
        Object high = highBox.getSelectedItem();
        lowBox.removeAllItems();
        highBox.removeAllItems();
        if (m != null) {
            for (String r : m.roles) {
                lowBox.addItem(r);
                highBox.addItem(r);
            }
            if (low != null) {
                lowBox.setSelectedItem(low);
            }
            if (high != null) {
                highBox.setSelectedItem(high);
            } else if (highBox.getItemCount() > 1) {
                highBox.setSelectedIndex(highBox.getItemCount() - 1);
            }
        }
        if (m == null || m.roles.size() < 2) {
            rolesText.setText("Comparing roles needs requests sent under two roles.\nSet a role in Settings (for example user), send that account's requests, "
                    + "change the role (for example admin), and send the other account's.");
        }
    }

    // ------------------------------------------------------------------ settings

    private Component settingsTab() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 8, 6, 8);
        c.anchor = GridBagConstraints.WEST;
        int row = 0;
        row = line(p, c, row, "Model name", nameField, "Each name is a separate model.");
        row = line(p, c, row, "Role for the next send", roleField, "Optional, for example user or admin. Leave empty for one account.");
        row = line(p, c, row, "In-scope hosts", scopeField, "Optional, comma separated. Default: the busiest host's registrable domain.");
        c.gridx = 1;
        c.gridy = row++;
        p.add(replaceRole, c);
        JButton save = new JButton("Save settings");
        JButton export = new JButton("Export model.json…");
        JButton clear = new JButton("Clear this model");
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btns.add(save);
        btns.add(export);
        btns.add(clear);
        c.gridx = 1;
        c.gridy = row++;
        p.add(btns, c);
        JLabel where = new JLabel(" ");
        c.gridy = row;
        p.add(where, c);
        save.addActionListener(e -> {
            String n = nameField.getText().strip();
            if (!n.matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) {
                status.setText("The model name must be letters, digits, '.', '_' or '-'.");
                return;
            }
            boolean renamed = !n.equals(host.get("app", "burp"));
            host.set("app", n);
            host.set("role", roleField.getText().strip());
            host.set("scope", scopeField.getText().strip());
            host.set("replace", replaceRole.isSelected() ? "1" : "0");
            if (renamed) {
                try {
                    session = host.session(n);
                } catch (Exception ex) {
                    status.setText("could not open " + n + ": " + ex.getMessage());
                }
            }
            if (session != null) {
                session.scope = scope();
            }
            refresh();
        });
        export.addActionListener(e -> {
            Model m = model();
            if (m == null) {
                return;
            }
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new java.io.File(m.name + "-model.json"));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    Files.writeString(fc.getSelectedFile().toPath(), Json.pretty(m.toMap()), StandardCharsets.UTF_8);
                    status.setText("exported " + fc.getSelectedFile());
                } catch (Exception ex) {
                    status.setText("could not export: " + ex.getMessage());
                }
            }
        });
        clear.addActionListener(e -> {
            if (session != null && JOptionPane.showConfirmDialog(this, "Delete everything in the model '" + session.name + "'?", "burp2model",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                try {
                    session.clear();
                } catch (Exception ex) {
                    status.setText("could not clear: " + ex.getMessage());
                }
                refresh();
            }
        });
        if (session != null) {
            where.setText("Stored in " + session.dir());
        }
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(p, BorderLayout.NORTH);
        return outer;
    }

    private static int line(JPanel p, GridBagConstraints c, int row, String label, JTextField f, String hint) {
        c.gridx = 0;
        c.gridy = row;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        p.add(f, c);
        c.gridx = 2;
        JLabel h = new JLabel(hint);
        h.setEnabled(false);
        p.add(h, c);
        return row + 1;
    }

    /** A document listener that calls one runnable. */
    private static final class SimpleDoc implements javax.swing.event.DocumentListener {
        private final Runnable r;

        SimpleDoc(Runnable r) {
            this.r = r;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }
    }
}
