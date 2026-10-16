package burp2model.ui;

import burp2model.engine.Analysis;
import burp2model.engine.ContextPack;
import burp2model.engine.Diff;
import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Query;
import burp2model.engine.Recon;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
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
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/** The burp2model tab. */
public final class MainPanel extends JPanel {
    /** What the extension supplies: settings storage, logging and the saved models. */
    public interface Host {
        String get(String key, String def);

        void set(String key, String value);

        void log(String line);

        Session session(String name) throws java.io.IOException;

        /** Run slow work off the Swing thread; the extension tracks it so unloading waits for it. */
        default void background(String name, Runnable task) {
            Thread t = new Thread(null, task, name, 64L * 1024 * 1024);
            t.setDaemon(true);
            t.start();
        }
    }

    private final Host host;
    private volatile Session session;
    private final JLabel status = new JLabel(" ");
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel modelName = new JLabel(" ");
    private final JPanel pills = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    private final JTextField globalSearch = new JTextField(22);

    private final Dashboard dashboard = new Dashboard();

    // to check
    private final DefaultTableModel leadsModel = Tables.model("Severity", "Endpoint", "Why it matters", "Do next");
    private final JTable leadsTable = Tables.table(leadsModel);
    private final Facts leadsFacts = new Facts();
    private final EvidenceViewer leadsViewer = new EvidenceViewer();
    private List<Analysis.Lead> leads = new ArrayList<>();
    private final DefaultTableModel gapsModel = Tables.model("Value", "Type", "About", "Not known", "Smallest next step");
    private final JTable gapsTable = Tables.table(gapsModel);
    private final JTabbedPane checkTabs = new JTabbedPane();

    // map
    private final GraphPanel graph = new GraphPanel();
    private final Facts graphFacts = new Facts();
    private final EvidenceViewer graphViewer = new EvidenceViewer();

    // surface
    private final JComboBox<String> typeBox = new JComboBox<>(new String[] {"endpoint", "route", "script", "third_party", "cookie", "auth", "parameter",
        "host", "tech", "operation", "role", "all"});
    private final JTextField surfaceFilter = new JTextField(22);
    private final DefaultTableModel surfaceModel = Tables.model("Type", "Name", "State", "Statuses", "Roles", "Requests", "Host");
    private final JTable surfaceTable = Tables.table(surfaceModel);
    private final SiteTree siteTree = new SiteTree();
    private final Facts surfaceFacts = new Facts();
    private final EvidenceViewer surfaceViewer = new EvidenceViewer();
    private final List<Model.Node> surfaceRows = new ArrayList<>();
    private final JPanel surfaceCards = new JPanel(new java.awt.CardLayout());

    // requests
    private final DefaultTableModel reqModel = Tables.model("#", "Method", "Host", "Path", "Status", "Role");
    private final JTable reqTable = Tables.table(reqModel);
    private final JTextField reqFilter = new JTextField(24);
    private final EvidenceViewer reqViewer = new EvidenceViewer();

    // query
    private final JTextField queryField = new JTextField();
    private final DefaultTableModel queryModel = Tables.model();
    private final JTable queryTable = Tables.table(queryModel);
    private final JTextArea queryText = textArea();
    private final JLabel queryNote = new JLabel(" ");
    private final EvidenceViewer queryViewer = new EvidenceViewer();
    private final List<String> queryHistory = new ArrayList<>();
    private int historyPos;
    private Query.Result lastResult;
    private final JTabbedPane queryOut = new JTabbedPane();

    // changes
    private final DefaultTableModel buildsModel = Tables.model("#", "When (UTC)", "Label", "Nodes", "Edges", "Requests");
    private final JTable buildsTable = Tables.table(buildsModel);
    private final DiffView diffView = new DiffView();

    // roles
    private final JComboBox<String> lowBox = new JComboBox<>();
    private final JComboBox<String> highBox = new JComboBox<>();
    private final DefaultTableModel rolesModel = Tables.model("Kind", "Endpoint", "Statuses", "Unknown", "Next");
    private final JTable rolesTable = Tables.table(rolesModel);
    private final JLabel rolesNote = new JLabel(" ");
    private final EvidenceViewer rolesViewer = new EvidenceViewer();
    private final List<List<Integer>> rolesEvidence = new ArrayList<>();

    // recon
    private final JComboBox<String> reconHost = new JComboBox<>();
    private final JTextArea reconText = textArea();
    private final JLabel reconStatus = new JLabel(" ");

    // settings
    private final JTextField nameField = new JTextField(16);
    private final JTextField roleField = new JTextField(14);
    private final JTextField scopeField = new JTextField(30);
    private final JCheckBox replaceRole = new JCheckBox("Replace this role's earlier requests when sending");
    private final JCheckBox autoCapture = new JCheckBox("Capture proxied traffic automatically (only hosts in Burp's target scope)");

    public MainPanel(Host host) {
        super(new BorderLayout());
        this.host = host;
        try {
            this.session = host.session(host.get("app", "burp"));
        } catch (Exception e) {
            host.log("burp2model: could not open the saved model (" + e.getMessage() + ")");
        }
        add(header(), BorderLayout.NORTH);
        tabs.addTab("Overview", dashboard);
        tabs.addTab("To check", checkTab());
        tabs.addTab("Map", mapTab());
        tabs.addTab("Surface", surfaceTab());
        tabs.addTab("Requests", requestsTab());
        tabs.addTab("Query", queryTab());
        tabs.addTab("Changes", changesTab());
        tabs.addTab("Roles", rolesTab());
        tabs.addTab("Recon", reconTab());
        tabs.addTab("Settings", settingsTab());
        tabs.setFont(Theme.font(12f, Font.PLAIN));
        add(tabs, BorderLayout.CENTER);
        tabs.addChangeListener(e -> fillTab(tabs.getSelectedIndex()));
        status.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        status.setFont(Theme.font(11f, Font.PLAIN));
        status.setForeground(Theme.muted());
        add(status, BorderLayout.SOUTH);
        dashboard.onLead(l -> {
            tabs.setSelectedIndex(1);
            checkTabs.setSelectedIndex(0);
            int idx = leads.indexOf(l);
            if (idx >= 0) {
                int v = leadsTable.convertRowIndexToView(idx);
                leadsTable.setRowSelectionInterval(v, v);
                leadsTable.scrollRectToVisible(leadsTable.getCellRect(v, 0, true));
            }
        });
        Facts[] all = {leadsFacts, graphFacts, surfaceFacts};
        for (Facts f : all) {
            f.onNode(this::goToNode);
        }
        // the Settings fields are filled once; refreshes never touch them, so a half-typed value survives live capture
        nameField.setText(host.get("app", "burp"));
        roleField.setText(host.get("role", ""));
        scopeField.setText(host.get("scope", ""));
        replaceRole.setSelected("1".equals(host.get("replace", "0")));
        autoCapture.setSelected("1".equals(host.get("auto", "0")));
        roleField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        scopeField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        replaceRole.addItemListener(e -> updateSettings());
        updateSettings();
        refresh();
        reportProblems();
    }

    /** Say what could not be read when the model was opened; the damaged files are kept beside it. */
    private void reportProblems() {
        Session s = session;
        if (s == null) {
            return;
        }
        for (String p : s.problems()) {
            host.log("burp2model (" + s.name + "): " + p);
            say("burp2model: " + p);
        }
    }

    /** Stop the map's timers; called when the extension unloads. */
    public void dispose() {
        graph.stop();
    }

    private static JTextArea textArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(Theme.mono(12f));
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setMargin(new Insets(10, 14, 10, 14));
        return a;
    }

    private Model model() {
        return session == null ? null : session.model();
    }

    // ------------------------------------------------------------------ public

    public void refresh() {
        SwingUtilities.invokeLater(this::refreshNow);
    }

    public Session session() {
        return session;
    }

    public void say(String text) {
        SwingUtilities.invokeLater(() -> status.setText(text));
    }

    /** What the next send uses: the role, scope and replace choice as typed in Settings (saved or not). */
    public record Settings(String role, List<String> scope, boolean replaceRole) {
        static Settings of(String role, String scope, boolean replaceRole) {
            List<String> out = new ArrayList<>();
            for (String s : scope.split("[,\\s]+")) {
                if (!s.isBlank()) {
                    out.add(s.strip());
                }
            }
            String r = role.strip();
            return new Settings(r.isEmpty() ? null : r, List.copyOf(out), replaceRole);
        }
    }

    private volatile Settings settings = new Settings(null, List.of(), false);

    /** Safe to call from any thread: a copy taken on the Swing thread whenever a field changes. */
    public Settings settings() {
        return settings;
    }

    private void updateSettings() {
        settings = Settings.of(roleField.getText(), scopeField.getText(), replaceRole.isSelected());
    }

    /** Run a query as if it were typed in the Query tab. */
    public void ask(String text) {
        queryField.setText(text);
        runQuery(text);
    }

    /** Tabs whose contents are out of date; each is filled when it is first shown, so a send costs only what is on screen. */
    private final java.util.Set<Integer> stale = new java.util.HashSet<>();
    private Query queryEngine;
    private Model queryEngineFor;

    private void refreshNow() {
        Model m = model();
        leads = m == null ? new ArrayList<>() : Analysis.leads(m);
        dashboard.update(m, leads);
        headerPills(m);
        for (int i = 1; i < tabs.getTabCount(); i++) {
            stale.add(i);
        }
        queryEngine = null;
        fillTab(tabs.getSelectedIndex());
        status.setText(m == null ? "No requests yet. Right-click requests in Burp and choose Send to burp2model."
                : m.nodes.size() + " nodes · " + m.edges.size() + " edges · " + m.evidenceLog.size() + " requests · build " + session.builds().size()
                + " · stored in " + session.dir());
    }

    /** Fill one tab from the current model, if it is out of date. */
    private void fillTab(int idx) {
        if (!stale.remove(idx)) {
            return;
        }
        Model m = model();
        switch (idx) {
            case 1 -> {
                leadsViewer.setModel(m);
                fillLeads(m);
                fillGaps(m);
            }
            case 2 -> {
                graphViewer.setModel(m);
                graph.setModel(m);
            }
            case 3 -> {
                surfaceViewer.setModel(m);
                siteTree.setModel(m);
                fillSurface();
            }
            case 4 -> {
                reqViewer.setModel(m);
                fillRequests(m);
            }
            case 5 -> queryViewer.setModel(m);
            case 6 -> fillBuilds();
            case 7 -> {
                rolesViewer.setModel(m);
                fillRoles(m);
            }
            case 8 -> fillRecon(m);
            default -> {
            }
        }
    }

    // ------------------------------------------------------------------ header

    private Component header() {
        JPanel bar = new JPanel(new BorderLayout(14, 0)) {
            @Override
            protected void paintComponent(java.awt.Graphics g0) {
                java.awt.Graphics2D g = (java.awt.Graphics2D) g0.create();
                g.setColor(Theme.surface());
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(Theme.line());
                g.fillRect(0, getHeight() - 1, getWidth(), 1);
                g.setColor(Theme.ACCENT);
                g.fillRect(0, 0, 4, getHeight());
                g.dispose();
            }
        };
        bar.setBorder(BorderFactory.createEmptyBorder(8, 16, 8, 12));
        JLabel logo = new JLabel("burp2model");
        logo.setFont(Theme.font(16f, Font.BOLD));
        modelName.setFont(Theme.mono(12f));
        modelName.setForeground(Theme.muted());
        pills.setOpaque(false);
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        left.setOpaque(false);
        left.add(logo);
        left.add(modelName);
        left.add(pills);
        globalSearch.putClientProperty("JTextField.placeholderText", "Search endpoints, hosts, params…");
        globalSearch.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Theme.line()), BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        globalSearch.setToolTipText("Search the whole surface (Enter)");
        globalSearch.addActionListener(e -> {
            typeBox.setSelectedItem("all");
            surfaceFilter.setText(globalSearch.getText());
            showSurfaceList(true);
            tabs.setSelectedIndex(3);
        });
        JButton ai = new JButton("Copy for AI  ▾");
        ai.setFocusable(false);
        JPopupMenu menu = new JPopupMenu();
        String[][] opts = {{"methodology", "Hunting methodology", "a recon and hunting plan for this app"}, {"whole", "Whole model", "everything an AI needs, with the rules"},
            {"endpoints", "Endpoints only", "the API surface with parameters and evidence"}, {"open", "Open questions only", "what to test next"}};
        for (String[] o : opts) {
            JMenuItem mi = new JMenuItem("<html><b>" + o[1] + "</b><br><small>" + o[2] + "</small></html>");
            mi.addActionListener(e -> copyForAi(o[0]));
            menu.add(mi);
        }
        ai.addActionListener(e -> menu.show(ai, 0, ai.getHeight()));
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.setOpaque(false);
        right.add(Widgets.muted("Search"));
        right.add(globalSearch);
        right.add(ai);
        bar.add(left, BorderLayout.WEST);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    private void copyForAi(String scope) {
        Model m = model();
        if (m == null) {
            say("Nothing to copy yet. Send some requests first.");
            return;
        }
        Tables.copy(ContextPack.forAi(m, scope));
        say("Copied the " + scope + " package for your own AI (about " + ContextPack.tokens(m) / 1000 + "k tokens). Values are masked; every claim cites a request.");
    }

    private void headerPills(Model m) {
        pills.removeAll();
        modelName.setText(session == null ? "" : session.name);
        if (m != null) {
            Map<String, Object> c = m.counts();
            pills.add(new Widgets.Chip(c.get("endpoints") + " endpoints", Theme.BLUE));
            pills.add(new Widgets.Chip(leads.size() + " to check", Theme.ACCENT));
            pills.add(new Widgets.Chip(m.evidenceLog.size() + " requests", Theme.GRAY));
        }
        pills.revalidate();
        pills.repaint();
    }

    // ------------------------------------------------------------------ layout helpers

    /** Master list over a detail row: facts at the right, the request behind it below. */
    /** Put a split's divider at this share the first time it has a size. */
    private static <T extends JSplitPane> T divide(T sp, double share) {
        sp.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean done;

            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!done && sp.getWidth() > 50 && sp.getHeight() > 50) {
                    done = true;
                    sp.setDividerLocation(share);
                }
            }
        });
        return sp;
    }

    private static JSplitPane masterDetail(Component master, Facts facts, EvidenceViewer viewer, double weight) {
        JSplitPane top = divide(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, master, facts), 0.72);
        top.setResizeWeight(0.72);
        top.setBorder(null);
        top.setDividerSize(5);
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, viewer), weight);
        sp.setResizeWeight(weight);
        sp.setBorder(null);
        sp.setDividerSize(5);
        return sp;
    }

    private static JPanel toolbar() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.line()));
        return p;
    }

    private static JScrollPane scroll(Component c) {
        JScrollPane s = new JScrollPane(c);
        s.setBorder(null);
        if (c instanceof JTable t) {
            s.setColumnHeaderView(t.getTableHeader());          // set now, not when the pane is first shown
        }
        return s;
    }

    // ------------------------------------------------------------------ to check

    private Component checkTab() {
        leadsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(leadsTable);
            if (i >= 0 && i < leads.size()) {
                Analysis.Lead l = leads.get(i);
                leadsFacts.showLead(l);
                leadsViewer.show(l.endpoint().evidence, l.endpoint().label);
            }
        });
        Tables.render(leadsTable, "Severity", Renderers.severity());
        Tables.render(leadsTable, "Endpoint", Renderers.path());
        Tables.widths(leadsTable, 90, 340, 360, 360);
        checkTabs.addTab("Leads", masterDetail(scroll(leadsTable), leadsFacts, leadsViewer, 0.5));
        Tables.render(gapsTable, "Value", Renderers.ids());
        Tables.render(gapsTable, "About", Renderers.path());
        Tables.widths(gapsTable, 60, 230, 300, 320, 360);
        JPanel gaps = new JPanel(new BorderLayout());
        JLabel note = Widgets.muted("Open questions ranked by how much resolving each improves the picture. Absence is a gap in observation, never a statement about the target.");
        note.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        gaps.add(note, BorderLayout.NORTH);
        gaps.add(scroll(gapsTable), BorderLayout.CENTER);
        checkTabs.addTab("Open questions", gaps);
        return checkTabs;
    }

    private void fillLeads(Model m) {
        List<Object[]> rows = new ArrayList<>();
        for (Analysis.Lead l : leads) {
            Analysis.Signal s = l.signals().get(0);
            String sev = l.sev().equals("hot") ? "High" : l.sev().equals("warn") ? "Medium" : "Note";
            rows.add(new Object[] {sev, l.endpoint().label, s.title() + (l.signals().size() > 1 ? "  (+" + (l.signals().size() - 1) + " more)" : ""), s.next()});
        }
        Tables.fill(leadsModel, rows);
        leadsViewer.clear();
        leadsFacts.clear("Select a lead to see why it matters.");
    }

    private void fillGaps(Model m) {
        List<Object[]> rows = new ArrayList<>();
        if (m != null) {
            for (Map<String, Object> g : Analysis.gaps(m)) {
                rows.add(new Object[] {String.valueOf(g.get("leverage")), g.get("type"), g.get("entity"), g.get("unknown"), g.get("next")});
            }
        }
        Tables.fill(gapsModel, rows);
    }

    // ------------------------------------------------------------------ map

    private Component mapTab() {
        graph.onSelect(n -> {
            graphFacts.show(n, model());
            graphViewer.show(n.evidence, n.label);
        });
        graph.onOpen(n -> goToNode(n.id));
        JSplitPane top = divide(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, graph, graphFacts), 0.74);
        top.setResizeWeight(0.74);
        top.setBorder(null);
        top.setDividerSize(5);
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, graphViewer), 0.68);
        sp.setResizeWeight(0.68);
        sp.setBorder(null);
        sp.setDividerSize(5);
        return sp;
    }

    // ------------------------------------------------------------------ surface

    private Component surfaceTab() {
        JPanel top = toolbar();
        top.add(new JLabel("Show"));
        top.add(typeBox);
        top.add(new JLabel("Filter"));
        top.add(surfaceFilter);
        JToggleButton list = new JToggleButton("List", true);
        JToggleButton tree = new JToggleButton("Site map");
        ButtonGroup bg = new ButtonGroup();
        bg.add(list);
        bg.add(tree);
        list.setFocusable(false);
        tree.setFocusable(false);
        list.addActionListener(e -> showSurfaceList(true));
        tree.addActionListener(e -> showSurfaceList(false));
        top.add(list);
        top.add(tree);
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
                surfaceFacts.show(n, model());
            }
        });
        siteTree.onSelect(nodes -> {
            if (nodes.size() == 1) {
                surfaceFacts.show(nodes.get(0), model());
                surfaceViewer.show(nodes.get(0).evidence, nodes.get(0).label);
            } else if (!nodes.isEmpty()) {
                java.util.Set<Integer> ev = new java.util.TreeSet<>();
                nodes.forEach(n -> ev.addAll(n.evidence));
                surfaceFacts.showText(nodes.size() + " things under this path", "Pick one to see its facts. The requests behind all of them are listed below.");
                surfaceViewer.show(new ArrayList<>(ev).subList(0, Math.min(300, ev.size())), nodes.size() + " things");
            }
        });
        Tables.render(surfaceTable, "Type", Renderers.type());
        Tables.render(surfaceTable, "Name", Renderers.path());
        Tables.render(surfaceTable, "State", Renderers.state());
        Tables.widths(surfaceTable, 100, 420, 120, 90, 90, 80, 200);
        surfaceCards.add(scroll(surfaceTable), "list");
        surfaceCards.add(siteTree, "tree");
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(masterDetail(surfaceCards, surfaceFacts, surfaceViewer, 0.5), BorderLayout.CENTER);
        return p;
    }

    private void showSurfaceList(boolean list) {
        ((java.awt.CardLayout) surfaceCards.getLayout()).show(surfaceCards, list ? "list" : "tree");
    }

    private void fillSurface() {
        Model m = model();
        surfaceRows.clear();
        List<Object[]> rows = new ArrayList<>();
        if (m != null) {
            String type = (String) typeBox.getSelectedItem();
            List<Model.Node> ns = new ArrayList<>();
            for (Model.Node n : m.nodes.values()) {
                if ("all".equals(type) ? !n.type.equals("parameter") || surfaceFilter.getText().length() > 1 : n.type.equals(type)) {
                    ns.add(n);
                }
            }
            java.util.List<String> order = java.util.List.of("host", "route", "endpoint", "script", "third_party", "cookie", "auth", "role", "operation", "tech", "parameter");
            ns.sort(java.util.Comparator.comparingInt((Model.Node n) -> order.indexOf(n.type)).thenComparing(n -> n.label));
            for (Model.Node n : ns) {
                surfaceRows.add(n);
                Object st = n.attrs.get("api_state");
                Object statuses = n.attrs.get("statuses");
                Object reqs = n.attrs.get("requests");
                rows.add(new Object[] {n.type, n.label, st == null ? "" : st, statuses == null ? "" : String.valueOf(statuses).replace("[", "").replace("]", ""),
                        String.join(",", n.roles), reqs == null ? String.valueOf(n.evidence.size()) : String.valueOf(reqs),
                        n.attrs.get("host") == null ? "" : String.valueOf(n.attrs.get("host"))});
            }
        }
        Tables.fill(surfaceModel, rows);
        Tables.filter(surfaceTable, surfaceFilter.getText());
        surfaceViewer.clear();
        surfaceFacts.clear("Select a row, or switch to Site map to browse by path.");
    }

    /** Jump to a node from another tab (a connection link in a facts card). */
    private void goToNode(String id) {
        Model m = model();
        if (m == null || !m.nodes.containsKey(id)) {
            return;
        }
        Model.Node n = m.nodes.get(id);
        typeBox.setSelectedItem(n.type);
        surfaceFilter.setText("");
        showSurfaceList(true);
        tabs.setSelectedIndex(3);
        for (int i = 0; i < surfaceRows.size(); i++) {
            if (surfaceRows.get(i).id.equals(id)) {
                int v = surfaceTable.convertRowIndexToView(i);
                surfaceTable.setRowSelectionInterval(v, v);
                surfaceTable.scrollRectToVisible(surfaceTable.getCellRect(v, 0, true));
                break;
            }
        }
    }

    // ------------------------------------------------------------------ requests

    private Component requestsTab() {
        JPanel top = toolbar();
        top.add(new JLabel("Filter"));
        top.add(reqFilter);
        top.add(Widgets.muted("method, host, path, status or role"));
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
        Tables.render(reqTable, "Method", Renderers.method());
        Tables.render(reqTable, "Status", Renderers.status());
        Tables.render(reqTable, "Path", Renderers.path());
        Tables.widths(reqTable, 50, 90, 220, 480, 80, 90);
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll(reqTable), reqViewer), 0.45);
        sp.setResizeWeight(0.45);
        sp.setBorder(null);
        sp.setDividerSize(5);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void fillRequests(Model m) {
        reqModel.setRowCount(0);
        if (m == null) {
            return;
        }
        List<Object[]> rows = new ArrayList<>(m.evidenceLog.size());
        for (int i = 0; i < m.evidenceLog.size(); i++) {
            Map<String, Object> ev = m.evidenceLog.meta(i);
            String p = m.evidenceLog.path(i);
            rows.add(new Object[] {((Number) ev.get("id")).intValue(), ev.get("method"), ev.get("host"), p.isEmpty() ? ev.get("path") : p,
                    ev.get("status") == null ? "" : String.valueOf(ev.get("status")), ev.get("role") == null ? "" : ev.get("role")});
        }
        Tables.fill(reqModel, rows);
        Tables.filter(reqTable, reqFilter.getText());
    }

    // ------------------------------------------------------------------ query

    private Component queryTab() {
        JPanel top = new JPanel(new BorderLayout(8, 0));
        top.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));
        queryField.setFont(Theme.mono(13f));
        queryField.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Theme.line()), BorderFactory.createEmptyBorder(5, 8, 5, 8)));
        JButton run = new JButton("Run");
        run.setFont(Theme.font(12f, Font.BOLD));
        JButton help = new JButton("Help");
        JButton copy = new JButton("Copy results");
        JButton csv = new JButton("Save CSV…");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JButton b : new JButton[] {run, help, copy, csv}) {
            b.setFocusable(false);
            buttons.add(b);
        }
        top.add(queryField, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);
        run.addActionListener(e -> runQuery(queryField.getText()));
        help.addActionListener(e -> runQuery("help"));
        copy.addActionListener(e -> {
            Tables.copy(resultTsv());
            say("Copied " + queryModel.getRowCount() + " rows.");
        });
        csv.addActionListener(e -> saveCsv());
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
        examples.add(Widgets.muted("Try"));
        for (String ex : new String[] {"list-apis", "reconcile", "static-only", "req.method:POST AND resp.code.gte:400", "node.type:endpoint AND node.state:STATIC_ONLY",
            "privileged", "auth-surface", "secrets", "unknowns", "third-parties", "changed-since previous", "stats"}) {
            JButton b = new JButton(ex.length() > 30 ? ex.substring(0, 28) + "…" : ex);
            b.setToolTipText(ex);
            b.setFont(Theme.font(11f, Font.PLAIN));
            b.setMargin(new Insets(1, 7, 1, 7));
            b.setFocusable(false);
            b.addActionListener(e -> ask(ex));
            examples.add(b);
        }
        JPanel head = new JPanel(new BorderLayout());
        head.add(top, BorderLayout.NORTH);
        head.add(examples, BorderLayout.CENTER);
        queryNote.setBorder(BorderFactory.createEmptyBorder(2, 12, 6, 12));
        queryNote.setFont(Theme.font(11f, Font.PLAIN));
        head.add(queryNote, BorderLayout.SOUTH);

        queryTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || lastResult == null) {
                return;
            }
            int i = Tables.selected(queryTable);
            if (i >= 0 && i < lastResult.rows().size()) {
                List<Integer> evs = evidenceOf(lastResult.rows().get(i));
                queryViewer.show(evs, evs.isEmpty() ? "" : "ev_" + evs.get(0));
            }
        });
        queryOut.addTab("Table", scroll(queryTable));
        queryOut.addTab("Text", scroll(queryText));
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, queryOut, queryViewer), 0.5);
        sp.setResizeWeight(0.55);
        sp.setBorder(null);
        sp.setDividerSize(5);
        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private String resultTsv() {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < queryModel.getColumnCount(); c++) {
            sb.append(c > 0 ? "\t" : "").append(queryModel.getColumnName(c));
        }
        for (int r = 0; r < queryModel.getRowCount(); r++) {
            sb.append('\n');
            for (int c = 0; c < queryModel.getColumnCount(); c++) {
                sb.append(c > 0 ? "\t" : "").append(queryModel.getValueAt(r, c));
            }
        }
        return sb.toString();
    }

    private void saveCsv() {
        if (queryModel.getRowCount() == 0) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("burp2model-query.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            StringBuilder sb = new StringBuilder();
            for (String line : resultTsv().split("\n")) {
                List<String> cells = new ArrayList<>();
                for (String c : line.split("\t", -1)) {
                    cells.add("\"" + c.replace("\"", "\"\"") + "\"");
                }
                sb.append(String.join(",", cells)).append('\n');
            }
            try {
                Files.writeString(fc.getSelectedFile().toPath(), sb.toString(), StandardCharsets.UTF_8);
                say("Saved " + fc.getSelectedFile());
            } catch (Exception ex) {
                say("could not save: " + ex.getMessage());
            }
        }
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

    private void runQuery(String text) {
        Model m = model();
        if (m == null) {
            queryNote.setForeground(Theme.muted());
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
        if (queryEngine == null || queryEngineFor != m) {
            queryEngine = new Query(m);
            queryEngineFor = m;
        }
        Query q = queryEngine;
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
            queryNote.setForeground(Theme.muted());
            queryNote.setText(r.kind().equals("text") ? "text answer" : r.note());
            queryText.setText(r.kind().equals("text") ? r.note() : "");
            queryText.setCaretPosition(0);
            queryModel.setRowCount(0);
            queryModel.setColumnCount(0);
            if (!r.kind().equals("text")) {
                for (String c : r.columns()) {
                    queryModel.addColumn(c);
                }
                for (Map<String, Object> row : r.rows()) {
                    Object[] cells = new Object[r.columns().size()];
                    for (int i = 0; i < cells.length; i++) {
                        Object v = row.get(r.columns().get(i));
                        cells[i] = v instanceof List<?> l ? String.join(",", l.stream().map(String::valueOf).toList()) : v == null ? "" : String.valueOf(v);
                    }
                    queryModel.addRow(cells);
                }
                for (String col : new String[] {"method"}) {
                    Tables.render(queryTable, col, Renderers.method());
                }
                Tables.render(queryTable, "status", Renderers.status());
                Tables.render(queryTable, "state", Renderers.state());
                Tables.render(queryTable, "type", Renderers.type());
                Tables.render(queryTable, "ev", Renderers.ids());
                Tables.render(queryTable, "evidence", Renderers.ids());
                for (String col : new String[] {"label", "path", "endpoint", "from", "to", "src", "dst", "url"}) {
                    Tables.render(queryTable, col, Renderers.path());
                }
            }
            queryOut.setSelectedIndex(r.kind().equals("text") ? 1 : 0);
            queryViewer.clear();
        } catch (Query.QueryError e) {
            queryNote.setForeground(Theme.RED);
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
        JPanel top = toolbar();
        JButton prev = new JButton("What changed since the previous build");
        JButton sel = new JButton("Compare the selected build with the latest");
        prev.setFocusable(false);
        sel.setFocusable(false);
        top.add(prev);
        top.add(sel);
        top.add(Widgets.muted("Every send is a build. Drift is a change in the surface to understand, never a finding."));
        prev.addActionListener(e -> diffBuilds(session == null ? 0 : session.builds().size() - 1, session == null ? 0 : session.builds().size()));
        sel.addActionListener(e -> {
            int i = Tables.selected(buildsTable);
            if (i >= 0) {
                diffBuilds((Integer) buildsModel.getValueAt(i, 0), session.builds().size());
            }
        });
        Tables.widths(buildsTable, 40, 170, 220, 70, 70, 80);
        buildsTable.setPreferredScrollableViewportSize(new java.awt.Dimension(400, 120));
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll(buildsTable), diffView), 0.2);
        sp.setResizeWeight(0.18);
        sp.setBorder(null);
        sp.setDividerSize(5);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void diffBuilds(int older, int newer) {
        if (session == null || older < 1 || newer < 2 || older >= newer) {
            diffView.show("Send more requests first: a comparison needs two builds.");
            return;
        }
        try {
            diffView.show(Diff.formatText(session.diff(older, newer)));
        } catch (Exception e) {
            diffView.show("could not compare: " + e.getMessage());
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
            diffView.show(session.builds().isEmpty() ? "" : "One build so far. Send more requests and this shows what changed.");
        }
    }

    // ------------------------------------------------------------------ roles

    private Component rolesTab() {
        JPanel top = toolbar();
        top.add(new JLabel("Lower-privilege role"));
        top.add(lowBox);
        top.add(new JLabel("Higher-privilege role"));
        top.add(highBox);
        JButton go = new JButton("Compare");
        go.setFocusable(false);
        top.add(go);
        go.addActionListener(e -> compareRoles());
        rolesTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(rolesTable);
            if (i >= 0 && i < rolesEvidence.size()) {
                rolesViewer.show(rolesEvidence.get(i), String.valueOf(rolesModel.getValueAt(i, 1)));
            }
        });
        Tables.render(rolesTable, "Endpoint", Renderers.path());
        Tables.widths(rolesTable, 200, 340, 160, 300, 340);
        rolesNote.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        rolesNote.setForeground(Theme.muted());
        JPanel head = new JPanel(new BorderLayout());
        head.add(top, BorderLayout.NORTH);
        head.add(rolesNote, BorderLayout.SOUTH);
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll(rolesTable), rolesViewer), 0.45);
        sp.setResizeWeight(0.45);
        sp.setBorder(null);
        sp.setDividerSize(5);
        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    @SuppressWarnings("unchecked")
    private void compareRoles() {
        Model m = model();
        rolesModel.setRowCount(0);
        rolesEvidence.clear();
        if (m == null || lowBox.getSelectedItem() == null || highBox.getSelectedItem() == null || m.roles.size() < 2) {
            rolesNote.setText("Send requests under at least two roles first: set a role in Settings before each send.");
            return;
        }
        Map<String, Object> r = Analysis.crossRole(m, (String) lowBox.getSelectedItem(), (String) highBox.getSelectedItem());
        String[][] sections = {{"low_reached_privileged", "Low role reached a privileged-looking path"}, {"high_only", "Only the high role reached it"},
            {"shared_same_success", "Both roles got 2xx"}};
        int n = 0;
        for (String[] s : sections) {
            for (Object o : (List<Object>) r.get(s[0])) {
                Map<String, Object> e = (Map<String, Object>) o;
                rolesModel.addRow(new Object[] {s[1], e.get("endpoint"), String.valueOf(e.get("statuses")), e.get("unknown"), e.get("next")});
                List<Integer> ev = new ArrayList<>();
                for (Object x : (List<Object>) e.get("evidence")) {
                    ev.add(((Number) x).intValue());
                }
                rolesEvidence.add(ev);
                n++;
            }
        }
        rolesNote.setText(n + " things to compare. Each is a hypothesis to verify, not a finding.");
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
            rolesNote.setText("Comparing roles needs requests sent under two roles. Set a role in Settings (for example user), send that account's requests, "
                    + "change it (for example admin), and send the other account's.");
        } else {
            compareRoles();
        }
    }

    // ------------------------------------------------------------------ recon

    private Component reconTab() {
        JPanel top = toolbar();
        top.add(new JLabel("Host"));
        reconHost.setEditable(true);
        reconHost.setPreferredSize(new java.awt.Dimension(280, 26));
        top.add(reconHost);
        JButton run = new JButton("Run light recon…");
        run.setFocusable(false);
        top.add(run);
        top.add(reconStatus);
        run.addActionListener(e -> runRecon());
        reconText.setText("Light, passive recon on one host: DNS, the TLS certificate, the front page's headers, robots.txt and security.txt, and mail policy.\n\n"
                + "It sends a handful of ordinary requests to the host, so run it only on targets you are authorised to test. "
                + "Nothing is run until you press the button.");
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(scroll(reconText), BorderLayout.CENTER);
        return p;
    }

    private void fillRecon(Model m) {
        Object cur = reconHost.getEditor().getItem();
        reconHost.removeAllItems();
        if (m != null) {
            for (Model.Node n : m.nodes.values()) {
                if (n.type.equals("host")) {
                    reconHost.addItem(n.label);
                }
            }
        }
        if (cur != null && !String.valueOf(cur).isBlank()) {
            reconHost.setSelectedItem(cur);
        }
    }

    private void runRecon() {
        String h = String.valueOf(reconHost.getEditor().getItem()).strip().toLowerCase();
        if (h.isEmpty() || !h.matches("[a-z0-9.\\-]+")) {
            reconStatus.setText("enter a host name");
            return;
        }
        int ok = JOptionPane.showConfirmDialog(this, "Run light recon against " + h + "?\n\nThis sends a few ordinary requests (DNS, a TLS handshake, GETs for /, robots.txt,\n"
                + "security.txt and sitemap.xml). Only do this for targets you are authorised to test.", "burp2model recon", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        reconStatus.setText("running…");
        host.background("burp2model-recon", () -> {
            try {
                Map<String, Object> r = Recon.run(h, s -> SwingUtilities.invokeLater(() -> reconStatus.setText("running: " + s)));
                String text = Recon.format(r);
                if (session != null) {
                    Files.writeString(session.dir().resolve("recon-" + h + ".json"), Json.pretty(r), StandardCharsets.UTF_8);
                }
                SwingUtilities.invokeLater(() -> {
                    reconText.setText(text);
                    reconText.setCaretPosition(0);
                    reconStatus.setText("done");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> reconStatus.setText("failed: " + t.getMessage()));
            }
        });
    }

    // ------------------------------------------------------------------ settings

    private Component settingsTab() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(14, 18, 14, 18));
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
        c.gridx = 1;
        c.gridy = row++;
        p.add(autoCapture, c);
        JButton save = new JButton("Save settings");
        JButton export = new JButton("Export model.json…");
        JButton summaryBtn = new JButton("Export summary (Markdown)…");
        JButton importBtn = new JButton("Import HAR or Burp export…");
        JButton clear = new JButton("Clear this model");
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        for (JButton b : new JButton[] {save, importBtn, export, summaryBtn, clear}) {
            b.setFocusable(false);
            btns.add(b);
        }
        c.gridx = 1;
        c.gridy = row++;
        p.add(btns, c);
        JTextArea about = new JTextArea("""
                burp2model builds an evidence-cited model of one web app from the requests you send it. Every line cites the request that shows it.
                Cookies, tokens, keys and personal data are masked before anything is stored; only names and shapes are kept.
                It is a model builder, never a scanner: leads are hypotheses to verify in an authorised session.

                Models live in ~/.burp2model/models/<name>/.  Nothing is sent anywhere unless you run Recon or paste a package into your own AI.

                burp2model extension """ + burp2model.engine.Version.EXTENSION + "  ·  https://github.com/falc0n-researcher/burp2model");
        about.setEditable(false);
        about.setOpaque(false);
        about.setFont(Theme.font(12f, Font.PLAIN));
        about.setForeground(Theme.muted());
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 3;
        c.insets = new Insets(22, 8, 6, 8);
        p.add(about, c);
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
            host.set("auto", autoCapture.isSelected() ? "1" : "0");
            if (renamed) {
                try {
                    session = host.session(n);
                    reportProblems();
                } catch (Exception ex) {
                    status.setText("could not open " + n + ": " + ex.getMessage());
                }
            }
            if (session != null) {
                session.scope = settings().scope();
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
        importBtn.addActionListener(e -> importFile());
        summaryBtn.addActionListener(e -> {
            Model m = model();
            if (m == null) {
                return;
            }
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new java.io.File(m.name + "-summary.md"));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    Files.writeString(fc.getSelectedFile().toPath(), burp2model.engine.Markdown.summary(m), StandardCharsets.UTF_8);
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
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(p, BorderLayout.NORTH);
        return outer;
    }

    /** Add the requests in a HAR file (browser DevTools, Hetty, mitmproxy, ZAP) or a Burp "Save items" export to the model. */
    private void importFile() {
        if (session == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import a HAR file or a Burp export");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File f = fc.getSelectedFile();
        status.setText("importing " + f.getName() + "…");
        final Settings set = settings();
        host.background("burp2model-import", () -> {
            try {
                List<burp2model.engine.Parse.Raw> raws = burp2model.engine.Har.looksLike(f) ? burp2model.engine.Har.readRaw(f) : burp2model.engine.BurpXml.readRaw(f);
                int unreadable = 0;
                List<burp2model.engine.Parse.Raw> ok = new ArrayList<>();
                for (burp2model.engine.Parse.Raw r : raws) {
                    if (r == null) {
                        unreadable++;
                    } else {
                        ok.add(r);
                    }
                }
                Session target = session;
                target.scope = set.scope();
                Session.AddResult r = target.add(ok, set.role(), f.getName(), set.replaceRole());
                refresh();
                say("imported " + f.getName() + ": added " + r.added() + (r.duplicates() > 0 ? ", " + r.duplicates() + " already in the model" : "")
                        + (r.skipped() + unreadable > 0 ? ", " + (r.skipped() + unreadable) + " could not be read" : "") + ".");
            } catch (Throwable t) {
                say("could not import " + f.getName() + ": " + t.getMessage());
            }
        });
    }

    private static int line(JPanel p, GridBagConstraints c, int row, String label, JTextField f, String hint) {
        c.gridx = 0;
        c.gridy = row;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        p.add(f, c);
        c.gridx = 2;
        JLabel h = Widgets.muted(hint);
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
