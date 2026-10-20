package burp2model.ui;

import burp2model.engine.Analysis;
import burp2model.engine.Model;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/**
 * The burp2model tab: the header, the tabs, the welcome page and the status line, wired together. The parts live in
 * their own classes: Models (which model is open), DataActions (import and export), Shortcuts (keys and going back),
 * WelcomeFlow, StatusBar, HeaderBar, SettingsTab and one class per tab.
 */
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
    final JTabbedPane tabs = new JTabbedPane();
    final StatusBar statusBar = new StatusBar();
    final Models models = new Models(this);
    final DataActions data = new DataActions(this);
    private final Shortcuts keys = new Shortcuts(this);

    private final Dashboard dashboard = new Dashboard();
    final SettingsTab settingsTab = new SettingsTab(this);
    final HeaderBar header = new HeaderBar(this);
    private List<Analysis.Lead> leads = new ArrayList<>();
    private final LeadsTab leadsTab;
    private final MapTab mapTab;
    final SurfaceTab surfaceTab;
    final QueryTab queryTab;
    Component settingsView;
    final WelcomeFlow welcome;
    /** The tabs filled from the model, by their component in the tabbed pane. */
    private final Map<Component, Tab> byView = new java.util.HashMap<>();
    /** Tabs whose contents are out of date; each is filled when it is first shown, so a send costs only what is on screen. */
    private final java.util.Set<Tab> stale = new java.util.HashSet<>();

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
        welcome = new WelcomeFlow(this, tabs);
        add(welcome.center, BorderLayout.CENTER);
        add(statusBar, BorderLayout.SOUTH);
        // first run: the welcome page until the model has something in it (decided again once the model opens)
        showWelcome(!"1".equals(host.get("welcome.seen", "0")) || "1".equals(host.get("welcome.show", "0")));
        tabs.addChangeListener(e -> {
            Component now = tabs.getSelectedComponent();
            keys.shown(now);
            fillTab(now);
        });
        keys.install();
        applyMessageEditor();
        dashboard.onWelcome(() -> showWelcome(true));
        dashboard.onLead(l -> {
            select(leadsTab);
            leadsTab.selectLead(l);
        });
        settingsTab.load();
        models.open(models.appName(), false);
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing() && refreshPending) {
                refreshPending = false;
                refreshNow();
            }
        });
        refresh();
    }

    private void addTab(String title, Tab t) {
        tabs.addTab(title, t.view());
        byView.put(t.view(), t);
    }

    // ------------------------------------------------------------------ background work and the status line

    /** Show the busy indicator (from any thread); pair each call with idle(). */
    public void working(String what) {
        statusBar.working(what);
    }

    public void idle() {
        statusBar.idle();
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

    enum Level { INFO, OK, ERROR }

    public void say(String text) {
        SwingUtilities.invokeLater(() -> setStatus(text, Level.INFO));
    }

    public void sayError(String text) {
        SwingUtilities.invokeLater(() -> setStatus(text, Level.ERROR));
    }

    /** A message with a coloured dot (errors red); it goes back to the model summary after a while. */
    void setStatus(String text, Level level) {
        statusBar.set(text, level);
    }

    // ------------------------------------------------------------------ the model

    /** The open model, waiting up to `ms` for the first one to finish opening (a send right after Burp starts). */
    public Session awaitSession(long ms) {
        return models.awaitSession(ms);
    }

    public Session session() {
        return session;
    }

    Model model() {
        return session == null ? null : session.model();
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

    /** Kept by SettingsTab as the fields change. */
    volatile Settings settings = new Settings(null, List.of(), false);

    /** Safe to call from any thread: a copy taken on the Swing thread whenever a field changes. */
    public Settings settings() {
        return settings;
    }

    Host host() {
        return host;
    }

    /** The leads the Overview and To check show, worked out once per refresh. */
    List<Analysis.Lead> leads() {
        return leads;
    }

    /** Stop the map's timers; called when the extension unloads. */
    public void dispose() {
        mapTab.stop();
    }

    // ------------------------------------------------------------------ refresh

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

    private void refreshNow() {
        Model m = model();
        welcome.forModel(m);
        leads = m == null ? new ArrayList<>() : Analysis.leads(m);
        dashboard.update(m, leads);
        // the header shows the open model and whether live capture is on; the counts are on the Overview
        header.showModelName();
        header.showLive();
        stale.addAll(byView.values());
        fillTab(tabs.getSelectedComponent());
        Session s = session;
        statusBar.summary(s == null ? "Opening the model…" : m == null ? "No requests yet. Right-click requests in Burp and choose Send to burp2model."
                : m.nodes.size() + " nodes · " + m.edges.size() + " edges · " + m.evidenceLog.size() + " requests · build " + s.builds().size()
                + " · stored in " + s.dir().getFileName(), s == null ? null : s.dir().toString());
    }

    /** Fill one tab from the current model, if it is out of date. */
    private void fillTab(Component view) {
        Tab t = byView.get(view);
        if (t != null && stale.remove(t)) {
            t.fill(model());
        }
    }

    // ------------------------------------------------------------------ navigation

    void showWelcome(boolean on) {
        welcome.show(on);
    }

    /** Bring a tab to the front (filling it first if it is out of date). */
    void select(Tab t) {
        showWelcome(false);
        tabs.setSelectedComponent(t.view());
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

    /** Run a query as if it were typed in the Query tab. */
    public void ask(String text) {
        queryTab.ask(text);
    }

    // ------------------------------------------------------------------ request viewers

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
}
