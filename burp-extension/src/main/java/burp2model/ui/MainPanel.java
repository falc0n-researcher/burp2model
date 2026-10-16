package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Analysis;
import burp2model.engine.ContextPack;
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
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/** The burp2model tab. */
public final class MainPanel extends JPanel {
    private static final long serialVersionUID = 1L;
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
    private final JPanel pills = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    private final JTextField globalSearch = new JTextField(22);

    private final Dashboard dashboard = new Dashboard();
    private List<Analysis.Lead> leads = new ArrayList<>();

    // settings
    private final JTextField nameField = new JTextField(16);
    private final JTextField roleField = new JTextField(14);
    private final JTextField scopeField = new JTextField(30);
    private final JCheckBox replaceRole = new JCheckBox("Replace this role's earlier requests when sending");
    private final JCheckBox autoCapture = new JCheckBox("Capture proxied traffic automatically (only hosts in Burp's target scope)");

    public MainPanel(Host host) {
        super(new BorderLayout());
        this.host = host;
        add(header(), BorderLayout.NORTH);
        leadsTab = new LeadsTab(this);
        mapTab = new MapTab(this);
        surfaceTab = new SurfaceTab(this);
        queryTab = new QueryTab(this);
        tabs.addTab("Overview", dashboard);
        addTab("To check", leadsTab);
        addTab("Map", mapTab);
        addTab("Surface", surfaceTab);
        addTab("Requests", new RequestsTab(this));
        addTab("Query", queryTab);
        addTab("Changes", new ChangesTab(this));
        addTab("Roles", new RolesTab(this));
        addTab("Recon", new ReconTab(this));
        settingsView = settingsTab();
        tabs.addTab("Settings", settingsView);
        tabs.setFont(Theme.font(12f, Font.PLAIN));
        welcome = new Welcome(welcomeActions(), burp2model.engine.Version.EXTENSION);
        center.add(welcome, "welcome");
        center.add(tabs, "tabs");
        add(center, BorderLayout.CENTER);
        // first run: the welcome page until the model has something in it (decided again once the model opens)
        showWelcome(!"1".equals(host.get("welcome.seen", "0")) || "1".equals(host.get("welcome.show", "0")));
        tabs.addChangeListener(e -> {
            Component now = tabs.getSelectedComponent();
            if (lastTab != null && lastTab != now && !goingBack) {
                history.push(lastTab);
                while (history.size() > 30) {
                    history.removeLast();
                }
            }
            lastTab = now;
            fillTab(now);
        });
        shortcuts();
        status.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 12));
        status.setFont(Theme.font(11f, Font.PLAIN));
        status.setForeground(Theme.MUTED);
        status.setIconTextGap(6);
        busyBar.setIndeterminate(true);
        busyBar.setPreferredSize(new java.awt.Dimension(70, 8));
        busyBar.setVisible(false);
        JPanel south = new JPanel(new BorderLayout());
        JPanel busyBox = new JPanel(new java.awt.GridBagLayout());
        busyBox.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        busyBox.add(busyBar);
        south.add(busyBox, BorderLayout.WEST);
        south.add(status, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);
        revert.setRepeats(false);
        dashboard.onWelcome(() -> showWelcome(true));
        dashboard.onLead(l -> {
            select(leadsTab);
            leadsTab.selectLead(l);
        });
        // the Settings fields are filled once; refreshes never touch them, so a half-typed value survives live capture
        nameField.setText(appName());
        roleField.setText(host.get("role", ""));
        scopeField.setText(host.get("scope", ""));
        replaceRole.setSelected("1".equals(host.get("replace", "0")));
        autoCapture.setSelected("1".equals(host.get("auto", "0")));
        roleField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        scopeField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        replaceRole.addItemListener(e -> {
            updateSettings();
            host.set("replace", replaceRole.isSelected() ? "1" : "0");
        });
        autoCapture.addItemListener(e -> {
            host.set("auto", autoCapture.isSelected() ? "1" : "0");
            showLive();
        });
        // role and scope are kept as soon as the field is left; only a new model name needs Save (it opens another model)
        java.awt.event.FocusAdapter keep = new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                host.set("role", roleField.getText().strip());
                host.set("scope", scopeField.getText().strip());
            }
        };
        roleField.addFocusListener(keep);
        scopeField.addFocusListener(keep);
        updateSettings();
        openSession(appName(), false);
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing() && refreshPending) {
                refreshPending = false;
                refreshNow();
            }
        });
        refresh();
    }

    // ------------------------------------------------------------------ background work

    private final javax.swing.JProgressBar busyBar = new javax.swing.JProgressBar();
    private final java.util.concurrent.atomic.AtomicInteger busy = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.CountDownLatch opened = new java.util.concurrent.CountDownLatch(1);

    /** Show the busy indicator (from any thread); pair each call with idle(). */
    public void working(String what) {
        busy.incrementAndGet();
        SwingUtilities.invokeLater(() -> {
            busyBar.setVisible(busy.get() > 0);
            if (what != null) {
                setStatus(what, Level.INFO);
            }
        });
    }

    public void idle() {
        busy.updateAndGet(n -> Math.max(0, n - 1));
        SwingUtilities.invokeLater(() -> busyBar.setVisible(busy.get() > 0));
    }

    /**
     * Run slow work off the Swing thread, with the busy indicator on, so Burp never freezes; `done` gets the
     * result back on the Swing thread, and a failure is shown in the status line.
     */
    <T> void async(String what, java.util.concurrent.Callable<T> work, java.util.function.Consumer<T> done) {
        async(what, work, done, t -> sayError((what == null ? "failed" : what.replace("…", "")) + ": " + messageOf(t)));
    }

    <T> void async(String what, java.util.concurrent.Callable<T> work, java.util.function.Consumer<T> done,
                           java.util.function.Consumer<Throwable> failed) {
        working(what);
        host.background("burp2model-ui", () -> {
            try {
                T r = work.call();
                SwingUtilities.invokeLater(() -> {
                    idle();
                    done.accept(r);
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    idle();
                    failed.accept(t);
                });
            }
        });
    }

    static String messageOf(Throwable t) {
        return t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
    }

    /** Open (or switch to) a model off the Swing thread; a large one takes a second or more to read and rebuild. */
    private void openSession(String name, boolean applyScope) {
        async("Opening the model '" + name + "'…", () -> {
            Session s = host.session(name);
            if (OLD_DEFAULT.equals(name) && s.requestCount() == 0 && s.builds().isEmpty()) {
                s = host.session(SAMPLE);                       // the old empty default: open the sample instead
            }
            if (SAMPLE.equals(s.name)) {
                fillSample(s);                                  // before it is shown, so the first look is a full model
            }
            return s;
        }, s -> {
            if (applyScope) {
                s.scope = settings().scope();
            }
            if (!s.name.equals(name)) {
                host.set("app", s.name);
                nameField.setText(s.name);
            }
            session = s;
            opened.countDown();
            revert.stop();                                      // "Opening the model…" gives way to its summary at once
            refresh();
            reportProblems();
        }, t -> {
            opened.countDown();
            host.log("burp2model: could not open the model '" + name + "' (" + messageOf(t) + ")");
            sayError("could not open the model '" + name + "': " + messageOf(t));
        });
    }

    /** The open model, waiting up to `ms` for the first one to finish opening (a send right after Burp starts). */
    public Session awaitSession(long ms) {
        try {
            opened.await(ms, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return session;
    }

    /** Say what could not be read when the model was opened; the damaged files are kept beside it. */
    private void reportProblems() {
        Session s = session;
        if (s == null) {
            return;
        }
        for (String p : s.problems()) {
            host.log("burp2model (" + s.name + "): " + p);
            sayError("burp2model: " + p);
        }
    }

    // ------------------------------------------------------------------ welcome page

    private final java.awt.CardLayout cards = new java.awt.CardLayout();
    private final JPanel center = new JPanel(cards);
    private final Welcome welcome;
    private boolean welcomeShowing;
    /** Requests in the model when it was last shown; the welcome page steps aside when the first ones arrive. */
    private int lastRequests = -1;

    private void showWelcome(boolean on) {
        welcomeShowing = on;
        if (on) {
            welcome.update("1".equals(host.get("auto", "0")), "1".equals(host.get("welcome.show", "0")));
        }
        cards.show(center, on ? "welcome" : "tabs");
    }

    /** Called on each refresh: an empty model shows the welcome page, and the first requests take it away. */
    private void welcomeFor(Model m) {
        int n = m == null ? 0 : m.evidenceLog.size();
        if (session != null && n == 0 && !welcomeShowing) {
            showWelcome(true);
        } else if (welcomeShowing && n > 0 && lastRequests == 0) {
            host.set("welcome.seen", "1");
            showWelcome(false);
        }
        lastRequests = session == null ? -1 : n;
    }

    private Welcome.Actions welcomeActions() {
        return new Welcome.Actions() {
            @Override
            public void sample() {
                loadSample();
            }

            @Override
            public void importFile() {
                MainPanel.this.importFile();
            }

            @Override
            public void liveCapture() {
                autoCapture.setSelected(true);
                host.set("auto", "1");
                welcome.update(true, "1".equals(host.get("welcome.show", "0")));
                setStatus("Live capture is on: in-scope Proxy traffic (Burp's target scope) joins the model every few seconds.", Level.OK);
            }

            @Override
            public void settings() {
                host.set("welcome.seen", "1");
                showWelcome(false);
                tabs.setSelectedComponent(settingsView);
            }

            @Override
            public void getStarted(boolean showOnStart) {
                host.set("welcome.seen", "1");
                host.set("welcome.show", showOnStart ? "1" : "0");
                showWelcome(false);
            }
        };
    }

    /** The model that opens when none was chosen: the demo shop, so a first look has something in it. */
    static final String SAMPLE = "sample";
    /** What 1.1 opened by default, an empty model nobody asked for. */
    private static final String OLD_DEFAULT = "burp";

    /** The model to open: the one chosen in Settings, or the sample. An empty model from the old default gives way to it. */
    private String appName() {
        return host.get("app", SAMPLE);
    }

    /** Fill an empty sample model with the bundled demo shop (a user and an admin, so Roles has something to compare). */
    private static void fillSample(Session s) throws Exception {
        if (s.requestCount() > 0) {
            return;
        }
        for (String[] part : new String[][] {{"/sample/shop-user.xml", "user"}, {"/sample/shop-admin.xml", "admin"}}) {
            try (var in = MainPanel.class.getResourceAsStream(part[0])) {
                if (in == null) {
                    throw new java.io.IOException("the sample is missing from the jar");
                }
                s.add(burp2model.engine.BurpXml.readRaw(in), part[1], "sample (" + part[1] + ")", false);
            }
        }
    }

    /** Switch to the sample model (filling it if it is empty). The user's own models are untouched; the switcher goes back. */
    private void loadSample() {
        async("Loading the sample model…", () -> {
            Session s = host.session(SAMPLE);
            fillSample(s);
            return s;
        }, s -> {
            session = s;
            host.set("app", SAMPLE);
            nameField.setText(SAMPLE);
            listModels();
            host.set("welcome.seen", "1");
            showWelcome(false);
            lastRequests = s.requestCount();
            refresh();
            setStatus("This is the sample model: a small demo shop seen as a user and as an admin. Your own model is untouched; "
                    + "switch back in Settings.", Level.OK);
        });
    }

    /** Stop the map's timers; called when the extension unloads. */
    public void dispose() {
        mapTab.stop();
    }

    Model model() {
        return session == null ? null : session.model();
    }

    // ------------------------------------------------------------------ public

    /** Set when a refresh arrived while the tab was hidden; done when it is shown again. */
    private boolean refreshPending;

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            // live capture refreshes every few seconds; while another Burp tab is in front, wait until this one is shown
            if (isDisplayable() && !isShowing()) {
                refreshPending = true;
            } else {
                refreshNow();
            }
        });
    }

    public Session session() {
        return session;
    }

    enum Level { INFO, OK, ERROR }

    /** What the status line shows when no message is: the model summary. */
    private String summary = " ";
    private final javax.swing.Timer revert = new javax.swing.Timer(10_000, e -> setStatus(summary, null));

    public void say(String text) {
        SwingUtilities.invokeLater(() -> setStatus(text, Level.INFO));
    }

    public void sayError(String text) {
        SwingUtilities.invokeLater(() -> setStatus(text, Level.ERROR));
    }

    /** A message with a coloured dot (errors red); it goes back to the model summary after a while. */
    void setStatus(String text, Level level) {
        status.setText(text);
        status.setIcon(level == null ? null : new Dot(level == Level.ERROR ? Theme.RED : level == Level.OK ? Theme.GREEN : Theme.BLUE));
        status.setForeground(level == Level.ERROR ? Theme.readable(Theme.RED, Theme.bg()) : Theme.MUTED);
        if (level == null) {
            revert.stop();
        } else {
            revert.setInitialDelay(level == Level.ERROR ? 20_000 : 10_000);
            revert.restart();
        }
    }

    private static final class Dot implements javax.swing.Icon {
        private final java.awt.Color c;

        Dot(java.awt.Color c) {
            this.c = c;
        }

        @Override
        public void paintIcon(Component comp, java.awt.Graphics g0, int x, int y) {
            java.awt.Graphics2D g = (java.awt.Graphics2D) g0.create();
            Theme.quality(g);
            g.setColor(c);
            g.fillOval(x, y + 1, 7, 7);
            g.dispose();
        }

        @Override
        public int getIconWidth() {
            return 7;
        }

        @Override
        public int getIconHeight() {
            return 9;
        }
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
        queryTab.ask(text);
    }

    // ------------------------------------------------------------------ tabs

    private final LeadsTab leadsTab;
    private final MapTab mapTab;
    private final SurfaceTab surfaceTab;
    private final QueryTab queryTab;
    private Component settingsView;
    /** The tabs filled from the model, by their component in the tabbed pane. */
    private final Map<Component, Tab> byView = new java.util.HashMap<>();
    /** Tabs whose contents are out of date; each is filled when it is first shown, so a send costs only what is on screen. */
    private final java.util.Set<Tab> stale = new java.util.HashSet<>();

    private void addTab(String title, Tab t) {
        tabs.addTab(title, t.view());
        byView.put(t.view(), t);
    }

    // ------------------------------------------------------------------ keyboard

    private final java.util.ArrayDeque<Component> history = new java.util.ArrayDeque<>();
    private Component lastTab;
    private boolean goingBack;

    /** Alt+Left: the tab shown before (after a jump from a lead, a search or a connection). */
    private void back() {
        Component prev = history.poll();
        if (prev != null) {
            goingBack = true;
            try {
                showWelcome(false);
                tabs.setSelectedComponent(prev);
                lastTab = prev;
            } finally {
                goingBack = false;
            }
        }
    }

    /**
     * Shortcuts, active while focus is anywhere in the tab (never elsewhere in Burp): Cmd/Ctrl+1..9 and 0 for the
     * tabs, Cmd/Ctrl+F to search, Cmd/Ctrl+L for the query box, Cmd/Ctrl+Shift+C for Copy for AI, Alt+Left to go back.
     */
    private void shortcuts() {
        int menu = menuMask();
        javax.swing.InputMap im = getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        javax.swing.ActionMap am = getActionMap();
        for (int i = 0; i <= 9; i++) {
            int index = i == 0 ? tabs.getTabCount() - 1 : i - 1;
            bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_0 + i, menu), "tab" + i, () -> {
                if (index < tabs.getTabCount()) {
                    showWelcome(false);
                    tabs.setSelectedIndex(index);
                }
            });
        }
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_F, menu), "search", () -> {
            globalSearch.requestFocusInWindow();
            globalSearch.selectAll();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_L, menu), "query", () -> {
            select(queryTab);
            queryTab.focusField();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_C, menu | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "copyForAi", () -> copyForAi("whole"));
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, java.awt.event.InputEvent.ALT_DOWN_MASK), "back", this::back);
    }

    /** Cmd on a Mac, Ctrl elsewhere (asked of the toolkit, which a headless JVM cannot answer). */
    static int menuMask() {
        try {
            return java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        } catch (java.awt.HeadlessException e) {
            return System.getProperty("os.name", "").toLowerCase().contains("mac") ? java.awt.event.InputEvent.META_DOWN_MASK
                    : java.awt.event.InputEvent.CTRL_DOWN_MASK;
        }
    }

    private static void bind(javax.swing.InputMap im, javax.swing.ActionMap am, javax.swing.KeyStroke k, String name, Runnable r) {
        im.put(k, name);
        am.put(name, new javax.swing.AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                r.run();
            }
        });
    }

    /** Bring a tab to the front (filling it first if it is out of date). */
    void select(Tab t) {
        showWelcome(false);
        tabs.setSelectedComponent(t.view());
    }

    /** The leads the Overview and To check show, worked out once per refresh. */
    List<Analysis.Lead> leads() {
        return leads;
    }

    Host host() {
        return host;
    }

    /** Jump to a node from anywhere (a connection in a facts card, Open on the map): Surface, with it selected. */
    void goToNode(String id) {
        Model m = model();
        if (m == null || !m.nodes.containsKey(id)) {
            return;
        }
        select(surfaceTab);
        surfaceTab.show(id);
    }

    private void refreshNow() {
        Model m = model();
        welcomeFor(m);
        leads = m == null ? new ArrayList<>() : Analysis.leads(m);
        dashboard.update(m, leads);
        headerPills(m);
        stale.addAll(byView.values());
        fillTab(tabs.getSelectedComponent());
        Session s = session;
        summary = s == null ? "Opening the model…" : m == null ? "No requests yet. Right-click requests in Burp and choose Send to burp2model."
                : m.nodes.size() + " nodes · " + m.edges.size() + " edges · " + m.evidenceLog.size() + " requests · build " + s.builds().size()
                + " · stored in " + s.dir().getFileName();
        status.setToolTipText(s == null ? null : s.dir().toString());
        if (!revert.isRunning()) {
            setStatus(summary, null);
        }
    }

    /** Fill one tab from the current model, if it is out of date. */
    private void fillTab(Component view) {
        Tab t = byView.get(view);
        if (t != null && stale.remove(t)) {
            t.fill(model());
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
        models.setFont(Theme.mono(12f));
        models.setToolTipText("The open model; pick another, or make a new one");
        models.getAccessibleContext().setAccessibleName("Model");
        models.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                listModels();
            }

            @Override
            public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {
            }
        });
        models.addActionListener(e -> {
            if (!listingModels && models.getSelectedItem() != null) {
                switchModel(String.valueOf(models.getSelectedItem()));
            }
        });
        live.setToolTipText("Live capture: add in-scope Proxy traffic to the model every few seconds. Click to turn it on or off.");
        live.addActionListener(e -> setLive(!"1".equals(host.get("auto", "0"))));
        pills.setOpaque(false);
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        left.setOpaque(false);
        left.add(logo);
        left.add(models);
        left.add(live);
        left.add(pills);
        globalSearch.putClientProperty("JTextField.placeholderText", "Search endpoints, hosts, params…");
        globalSearch.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Theme.LINE), BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        globalSearch.setToolTipText("Search the whole surface (Enter)");
        globalSearch.addActionListener(e -> {
            select(surfaceTab);
            surfaceTab.search(globalSearch.getText());
        });
        JButton ai = new JButton("Copy for AI  ▾");
        JPopupMenu menu = new JPopupMenu();
        String[][] opts = {{"methodology", "Hunting methodology", "a recon and hunting plan for this app"}, {"whole", "Whole model", "everything an AI needs, with the rules"},
            {"endpoints", "Endpoints only", "the API surface with parameters and evidence"}, {"open", "Open questions only", "what to test next"}};
        for (String[] o : opts) {
            JMenuItem mi = new Widgets.TwoLineItem(o[1], o[2]);
            mi.addActionListener(e -> copyForAi(o[0]));
            menu.add(mi);
        }
        ai.addActionListener(e -> menu.show(ai, 0, ai.getHeight()));
        JButton more = new JButton("⋯");
        more.setToolTipText("Import, export and settings");
        more.getAccessibleContext().setAccessibleName("More actions");
        JPopupMenu moreMenu = new JPopupMenu();
        JMenuItem imp = new JMenuItem("Import HAR or Burp export…");
        imp.addActionListener(e -> importFile());
        JMenuItem expJson = new JMenuItem("Export model.json…");
        expJson.addActionListener(e -> exportModel());
        JMenuItem expMd = new JMenuItem("Export summary (Markdown)…");
        expMd.addActionListener(e -> exportSummary());
        JMenuItem set = new JMenuItem("Settings");
        set.addActionListener(e -> {
            showWelcome(false);
            tabs.setSelectedComponent(settingsView);
        });
        for (JMenuItem mi : new JMenuItem[] {imp, expJson, expMd}) {
            moreMenu.add(mi);
        }
        moreMenu.addSeparator();
        moreMenu.add(set);
        more.addActionListener(e -> moreMenu.show(more, 0, more.getHeight()));
        JButton about = new JButton("?");
        about.setToolTipText("About burp2model: the welcome page");
        about.getAccessibleContext().setAccessibleName("About burp2model");
        about.addActionListener(e -> showWelcome(!welcomeShowing));
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.setOpaque(false);
        right.add(globalSearch);
        right.add(ai);
        right.add(more);
        right.add(about);
        bar.add(left, BorderLayout.WEST);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    // ------------------------------------------------------------------ header: model switcher and live capture

    private final JComboBox<String> models = new JComboBox<>();
    private final JButton live = new JButton();
    private boolean listingModels;
    private static final String NEW_MODEL = "New model…";

    /** Fill the switcher with the models saved on this machine, the open one selected. */
    private void listModels() {
        Session s = session;
        listingModels = true;
        try {
            Object keep = s == null ? null : s.name;
            models.removeAllItems();
            java.util.TreeSet<String> names = new java.util.TreeSet<>();
            if (s != null) {
                names.add(s.name);
                try (var dirs = Files.list(s.dir().getParent())) {
                    // a folder with nothing saved in it (an empty model) is not offered; one with requests always is
                    dirs.filter(Files::isDirectory).filter(d -> Files.exists(d.resolve("inputs.jsonl.gz")) || Files.exists(d.resolve("session.json")))
                            .forEach(d -> names.add(d.getFileName().toString()));
                } catch (java.io.IOException ignored) {
                    // the folder is unreadable: the open model is still listed
                }
            }
            names.forEach(models::addItem);
            models.addItem(NEW_MODEL);
            if (keep != null) {
                models.setSelectedItem(keep);
            }
        } finally {
            listingModels = false;
        }
    }

    private void showModelName() {
        Session s = session;
        if (s != null && !s.name.equals(models.getSelectedItem())) {
            listModels();
        }
    }

    /** Open another model (or make a new one), as Settings does when its name changes. */
    private void switchModel(String picked) {
        String name = picked;
        if (NEW_MODEL.equals(name)) {
            String n = JOptionPane.showInputDialog(this, "Name of the new model (letters, digits, '.', '_' or '-'):", "New model", JOptionPane.PLAIN_MESSAGE);
            listModels();
            if (n == null || n.isBlank()) {
                return;
            }
            name = n.strip();
        }
        if (!name.matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) {
            setStatus("The model name must be letters, digits, '.', '_' or '-'.", Level.ERROR);
            return;
        }
        if (session != null && name.equals(session.name)) {
            return;
        }
        nameField.setText(name);
        host.set("app", name);
        openSession(name, true);
    }

    private void setLive(boolean on) {
        host.set("auto", on ? "1" : "0");
        autoCapture.setSelected(on);
        showLive();
        setStatus(on ? "Live capture is on: in-scope Proxy traffic (Burp's target scope) joins the model every few seconds." : "Live capture is off.", Level.OK);
    }

    private void showLive() {
        boolean on = "1".equals(host.get("auto", "0"));
        live.setText(on ? "● Live" : "Live: off");
        live.setForeground(on ? Theme.readable(Theme.GREEN, Theme.surface()) : Theme.MUTED);
        live.getAccessibleContext().setAccessibleName(on ? "Live capture is on" : "Live capture is off");
    }

    private void copyForAi(String scope) {
        Model m = model();
        if (m == null) {
            say("Nothing to copy yet. Send some requests first.");
            return;
        }
        async("Packing the " + scope + " package…", () -> new String[] {ContextPack.forAi(m, scope), String.valueOf(ContextPack.tokens(m) / 1000)}, r -> {
            Tables.copy(r[0]);
            setStatus("Copied the " + scope + " package for your own AI (about " + r[1] + "k tokens). Values are masked; every claim cites a request.", Level.OK);
        });
    }

    /** The header shows the open model and whether live capture is on; the counts are on the Overview. */
    private void headerPills(Model m) {
        showModelName();
        showLive();
    }

    // ------------------------------------------------------------------ layout helpers

    // ------------------------------------------------------------------ to check

    // ------------------------------------------------------------------ map


    // ------------------------------------------------------------------ surface





    // ------------------------------------------------------------------ requests



    // ------------------------------------------------------------------ query









    // ------------------------------------------------------------------ changes




    // ------------------------------------------------------------------ roles




    // ------------------------------------------------------------------ recon




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
        JButton aboutBtn = new JButton("About burp2model");
        aboutBtn.addActionListener(e -> showWelcome(true));
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        for (JButton b : new JButton[] {save, importBtn, export, summaryBtn, clear, aboutBtn}) {
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
        about.setForeground(Theme.MUTED);
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 3;
        c.insets = new Insets(22, 8, 6, 8);
        p.add(about, c);
        save.addActionListener(e -> {
            String n = nameField.getText().strip();
            if (!n.matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) {
                setStatus("The model name must be letters, digits, '.', '_' or '-'.", Level.ERROR);
                return;
            }
            boolean renamed = !n.equals(appName());
            host.set("app", n);
            host.set("role", roleField.getText().strip());
            host.set("scope", scopeField.getText().strip());
            host.set("replace", replaceRole.isSelected() ? "1" : "0");
            host.set("auto", autoCapture.isSelected() ? "1" : "0");
            if (renamed) {
                openSession(n, true);
            } else if (session != null) {
                session.scope = settings().scope();
            }
            setStatus("Settings saved.", Level.OK);
            refresh();
        });
        export.addActionListener(e -> exportModel());
        importBtn.addActionListener(e -> importFile());
        summaryBtn.addActionListener(e -> exportSummary());
        clear.addActionListener(e -> {
            if (session != null && JOptionPane.showConfirmDialog(this, "Delete everything in the model '" + session.name + "'?", "burp2model",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                Session s = session;
                async("Clearing the model…", () -> {
                    s.clear();
                    return s;
                }, x -> {
                    setStatus("Cleared the model '" + s.name + "'.", Level.OK);
                    refresh();
                }, t -> sayError("could not clear: " + messageOf(t)));
            }
        });
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(p, BorderLayout.NORTH);
        return outer;
    }

    /** Save the whole model as JSON (in the background). */
    private void exportModel() {
        Model m = model();
        if (m == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(m.name + "-model.json"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            java.nio.file.Path to = fc.getSelectedFile().toPath();
            async("Exporting the model…", () -> Files.writeString(to, Json.pretty(m.toMap()), StandardCharsets.UTF_8),
                    x -> setStatus("exported " + to, Level.OK), t -> sayError("could not export: " + messageOf(t)));
        }
    }

    /** Save a Markdown summary of the model (in the background). */
    private void exportSummary() {
        Model m = model();
        if (m == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(m.name + "-summary.md"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            java.nio.file.Path to = fc.getSelectedFile().toPath();
            async("Writing the summary…", () -> Files.writeString(to, burp2model.engine.Markdown.summary(m), StandardCharsets.UTF_8),
                    x -> setStatus("exported " + to, Level.OK), t -> sayError("could not export: " + messageOf(t)));
        }
    }

    /** Add the requests in a HAR file (browser DevTools, Hetty, mitmproxy, ZAP) or a Burp "Save items" export to the model. */
    void importFile() {
        if (session == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import a HAR file or a Burp export");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File f = fc.getSelectedFile();
        final Settings set = settings();
        working("Importing " + f.getName() + "…");
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
                idle();
                say("imported " + f.getName() + ": added " + r.added() + (r.duplicates() > 0 ? ", " + r.duplicates() + " already in the model" : "")
                        + (r.skipped() + unreadable > 0 ? ", " + (r.skipped() + unreadable) + " could not be read" : "") + ".");
            } catch (Throwable t) {
                idle();
                sayError("could not import " + f.getName() + ": " + t.getMessage());
            }
        });
    }



}
