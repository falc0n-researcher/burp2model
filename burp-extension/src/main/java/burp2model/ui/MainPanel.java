package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Analysis;
import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Query;
import burp2model.engine.Recon;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
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

        /** Whether a model of this name has a folder yet (asking must not create one). */
        default boolean hasModel(String name) {
            return true;
        }

        /** Delete a model and everything saved in it; the extension also forgets its open copy. */
        default void deleteModel(String name) throws java.io.IOException {
        }

        /** Burp's own message editors, inside Burp; null elsewhere (then requests show in burp2model's own panes). */
        default MessageEditors editors() {
            return null;
        }

        /** Run slow work off the Swing thread; the extension tracks it so unloading waits for it. */
        default void background(String name, Runnable task) {
            Thread t = new Thread(null, task, name, 64L * 1024 * 1024);
            t.setDaemon(true);
            t.start();
        }
    }

    final Host host;
    volatile Session session;
    private final JLabel status = new JLabel(" ");
    final JTabbedPane tabs = new JTabbedPane();

    private final Dashboard dashboard = new Dashboard();
    final SettingsTab settingsTab = new SettingsTab(this);
    final HeaderBar header = new HeaderBar(this);
    private List<Analysis.Lead> leads = new ArrayList<>();

    // settings

    public MainPanel(Host host) {
        super(new BorderLayout());
        this.host = host;
        add(header.build(), BorderLayout.NORTH);
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
        settingsView = settingsTab.build();
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
        applyMessageEditor();
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
        settingsTab.nameField.setText(appName());
        settingsTab.roleField.setText(host.get("role", ""));
        settingsTab.scopeField.setText(host.get("scope", ""));
        settingsTab.replaceRole.setSelected("1".equals(host.get("replace", "0")));
        settingsTab.autoCapture.setSelected("1".equals(host.get("auto", "0")));
        settingsTab.roleField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        settingsTab.scopeField.getDocument().addDocumentListener(new SimpleDoc(this::updateSettings));
        settingsTab.replaceRole.addItemListener(e -> {
            updateSettings();
            host.set("replace", settingsTab.replaceRole.isSelected() ? "1" : "0");
        });
        settingsTab.autoCapture.addItemListener(e -> {
            host.set("auto", settingsTab.autoCapture.isSelected() ? "1" : "0");
            header.showLive();
        });
        // role and scope are kept as soon as the field is left; only a new model name needs Save (it opens another model)
        java.awt.event.FocusAdapter keep = new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                host.set("role", settingsTab.roleField.getText().strip());
                host.set("scope", settingsTab.scopeField.getText().strip());
            }
        };
        settingsTab.roleField.addFocusListener(keep);
        settingsTab.scopeField.addFocusListener(keep);
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
    /** The last "…ing" message shown while busy; when the work ends and it is still showing, the summary comes back. */
    private volatile String workingText;

    public void working(String what) {
        busy.incrementAndGet();
        if (what != null) {
            workingText = what;
        }
        SwingUtilities.invokeLater(() -> {
            busyBar.setVisible(busy.get() > 0);
            if (what != null) {
                setStatus(what, Level.INFO);
            }
        });
    }

    public void idle() {
        busy.updateAndGet(n -> Math.max(0, n - 1));
        SwingUtilities.invokeLater(() -> {
            busyBar.setVisible(busy.get() > 0);
            if (busy.get() == 0 && workingText != null && workingText.equals(status.getText())) {
                setStatus(summary, null);                       // "Comparing builds…" must not outlive the comparison
            }
        });
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
    void openSession(String name, boolean applyScope) {
        async("Opening the model '" + name + "'…", () -> {
            Session s;
            if (OLD_DEFAULT.equals(name) && !host.hasModel(name)) {
                s = host.session(SAMPLE);                       // the old default, gone: open the sample, never re-create it
            } else {
                s = host.session(name);
                if (OLD_DEFAULT.equals(name) && s.requestCount() == 0 && s.builds().isEmpty()) {
                    host.deleteModel(name);                     // the old empty default: remove it, open the sample instead
                    s = host.session(SAMPLE);
                }
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
                settingsTab.nameField.setText(s.name);
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
    boolean welcomeShowing;
    /** Requests in the model when it was last shown; the welcome page steps aside when the first ones arrive. */
    private int lastRequests = -1;

    void showWelcome(boolean on) {
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
                settingsTab.autoCapture.setSelected(true);
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
    String appName() {
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
            settingsTab.nameField.setText(SAMPLE);
            header.listModels();
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

    volatile Settings settings = new Settings(null, List.of(), false);

    /** Safe to call from any thread: a copy taken on the Swing thread whenever a field changes. */
    public Settings settings() {
        return settings;
    }

    private void updateSettings() {
        settings = Settings.of(settingsTab.roleField.getText(), settingsTab.scopeField.getText(), settingsTab.replaceRole.isSelected());
    }

    /** Run a query as if it were typed in the Query tab. */
    public void ask(String text) {
        queryTab.ask(text);
    }

    // ------------------------------------------------------------------ tabs

    private final LeadsTab leadsTab;
    private final MapTab mapTab;
    final SurfaceTab surfaceTab;
    private final QueryTab queryTab;
    Component settingsView;
    /** The tabs filled from the model, by their component in the tabbed pane. */
    private final Map<Component, Tab> byView = new java.util.HashMap<>();
    /** Tabs whose contents are out of date; each is filled when it is first shown, so a send costs only what is on screen. */
    private final java.util.Set<Tab> stale = new java.util.HashSet<>();

    /** Requests show in Burp's message editor inside Burp, unless it is turned off in Settings. */
    boolean burpEditorOn() {
        return host.editors() != null && !"0".equals(host.get("editor.burp", "1"));
    }

    /** Point every request and response viewer at Burp's editor or burp2model's own panes, as the setting says. */
    void applyMessageEditor() {
        MessageEditors e = burpEditorOn() ? host.editors() : null;
        for (EvidenceViewer v : viewers(this, new ArrayList<>())) {
            v.useEditors(e);
        }
    }

    private static List<EvidenceViewer> viewers(java.awt.Container c, List<EvidenceViewer> out) {
        for (Component k : c.getComponents()) {
            if (k instanceof EvidenceViewer v) {
                out.add(v);
            } else if (k instanceof java.awt.Container kc) {
                viewers(kc, out);
            }
        }
        return out;
    }

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
            header.globalSearch.requestFocusInWindow();
            header.globalSearch.selectAll();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_L, menu), "query", () -> {
            select(queryTab);
            queryTab.focusField();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_C, menu | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "copyForAi", () -> header.copyForAi("whole"));
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

    // ------------------------------------------------------------------ header: model switcher and live capture

    /** Delete the open model (after asking) and open the sample; deleting the sample itself just empties and refills it. */
    void deleteModel() {
        Session s = session;
        if (s == null) {
            return;
        }
        int ok = JOptionPane.showConfirmDialog(this, "Delete the model '" + s.name + "' and every request saved in it?\n\nThis cannot be undone.",
                "Delete model", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        String name = s.name;
        async("Deleting the model '" + name + "'…", () -> {
            host.deleteModel(name);
            Session next = host.session(SAMPLE);
            fillSample(next);
            return next;
        }, next -> {
            session = next;
            host.set("app", SAMPLE);
            settingsTab.nameField.setText(SAMPLE);
            header.listModels();
            refresh();
            setStatus("Deleted the model '" + name + "'. The sample model is open.", Level.OK);
        }, t -> sayError("could not delete '" + name + "': " + messageOf(t)));
    }

    /** The header shows the open model and whether live capture is on; the counts are on the Overview. */
    private void headerPills(Model m) {
        header.showModelName();
        header.showLive();
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




    /** Save the whole model as JSON (in the background). */
    void exportModel() {
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
    void exportSummary() {
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
