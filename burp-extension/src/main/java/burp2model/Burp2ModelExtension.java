package burp2model;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import burp2model.ui.MainPanel;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * burp2model inside Burp: right-click requests, Send to burp2model, and the model builds right here with
 * every claim tied to the request that shows it. Nothing is sent anywhere and nothing else needs to run.
 */
public class Burp2ModelExtension implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private Preferences prefs;
    private MainPanel panel;
    private Path home;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    /** Live capture waits here: at most 5,000 requests or 256 MB, whichever comes first. */
    private final LiveQueue live = new LiveQueue(5000, 256L * 1024 * 1024);
    private LiveCapture capture;
    private volatile boolean auto;
    private long autoCheckedAt;
    private ScheduledExecutorService flusher;
    /** Sends, imports and recon: tracked so unloading can wait for them instead of cutting a save short. */
    private final ExecutorService workers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(null, r, "burp2model-work", 64L * 1024 * 1024);
        t.setDaemon(true);
        return t;
    });
    private volatile boolean unloading;
    private burp2model.ui.MessageEditors editors;
    private BurpHistory history;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.prefs = api.persistence().preferences();
        api.extension().setName("burp2model");
        home = Path.of(System.getProperty("user.home"), ".burp2model", "models");
        try {
            Files.createDirectories(home);
            Redact.setKey(loadKey(home.getParent().resolve("key")));
        } catch (Exception e) {
            api.logging().logToError("burp2model: could not prepare " + home + " (" + e.getMessage() + ")");
        }
        editors = new BurpEditors(api);
        history = new BurpHistory(api);
        MainPanel.Host host = new MainPanel.Host() {
            @Override
            public String get(String key, String def) {
                String v = prefs.getString(key);
                return v == null || v.isBlank() ? def : v;
            }

            @Override
            public void set(String key, String value) {
                prefs.setString(key, value);
            }

            @Override
            public void log(String line) {
                api.logging().logToOutput(line);
            }

            @Override
            public Session session(String name) throws java.io.IOException {
                try {
                    // one Session per model folder, however often the name is switched back and forth
                    return sessions.computeIfAbsent(name, n -> {
                        try {
                            Session s = new Session(home, n);
                            s.lock();
                            return s;
                        } catch (java.io.IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    });
                } catch (java.io.UncheckedIOException e) {
                    throw e.getCause();
                }
            }

            @Override
            public boolean hasModel(String name) {
                return Files.isDirectory(home.resolve(name));
            }

            @Override
            public void deleteModel(String name) throws java.io.IOException {
                Session s = sessions.remove(name);
                if (s != null) {
                    s.clear();
                    s.close();
                }
                Path dir = home.resolve(name).normalize();
                if (!dir.startsWith(home) || dir.equals(home)) {
                    throw new java.io.IOException("not a model folder: " + name);
                }
                if (Files.exists(dir)) {
                    try (var walk = Files.walk(dir)) {
                        for (Path p : (Iterable<Path>) walk.sorted(java.util.Comparator.reverseOrder())::iterator) {
                            Files.deleteIfExists(p);
                        }
                    }
                }
            }

            @Override
            public void background(String name, Runnable task) {
                workers.execute(task);
            }

            @Override
            public burp2model.ui.MessageEditors editors() {
                return editors;
            }

            @Override
            public byte[][] captured(Session s, int id) {
                return history.find(s, id);
            }
        };
        // Swing components belong on the Swing thread; the model itself opens in the background
        try {
            if (javax.swing.SwingUtilities.isEventDispatchThread()) {
                panel = new MainPanel(host);
            } else {
                javax.swing.SwingUtilities.invokeAndWait(() -> panel = new MainPanel(host));
            }
        } catch (Exception e) {
            throw new IllegalStateException("burp2model: could not build the tab", e);
        }
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("burp2model", panel);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.http().registerHttpHandler(new Capture());
        flusher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(null, r, "burp2model-live", 64L * 1024 * 1024);
            t.setDaemon(true);
            return t;
        });
        capture = new LiveCapture(live, () -> panel.session(), () -> panel.settings().role(), () -> panel.settings().scope(), System::currentTimeMillis,
                new LiveCapture.Out() {
                    @Override
                    public void refresh() {
                        panel.refresh();
                    }

                    @Override
                    public void say(String text) {
                        panel.say(text);
                    }

                    @Override
                    public void error(String text) {
                        api.logging().logToError(text);
                    }
                });
        flusher.scheduleWithFixedDelay(capture::flush, 5, 5, TimeUnit.SECONDS);
        api.extension().registerUnloadingHandler(this::unload);
        api.logging().logToOutput("burp2model ready. Right-click requests and choose Send to burp2model; the model is in the burp2model tab.");
    }

    /**
     * Burp is unloading the extension: let a running save finish (never interrupt it), add what live capture
     * still holds, wait for sends and imports, then release the threads, timers, locks and caches so nothing
     * keeps the old extension in memory.
     */
    private void unload() {
        unloading = true;
        flusher.shutdown();
        try {
            if (!flusher.awaitTermination(15, TimeUnit.SECONDS)) {
                api.logging().logToError("burp2model: live capture was still saving after 15 seconds");
            }
            for (int i = 0; i < 10 && !live.isEmpty(); i++) {
                capture.flush();
            }
            workers.shutdown();
            if (!workers.awaitTermination(15, TimeUnit.SECONDS)) {
                api.logging().logToError("burp2model: a send or import was still running after 15 seconds");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        live.clear();
        javax.swing.SwingUtilities.invokeLater(panel::dispose);
        sessions.values().forEach(Session::close);
        Session.shutdownPool();
        Parse.clearCache();
    }

    /** One random key per user, kept outside the models: fingerprints of the same value stay comparable across sessions. */
    private static byte[] loadKey(Path p) throws java.io.IOException {
        if (Files.exists(p)) {
            return Files.readAllBytes(p);
        }
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        Files.write(p, k);
        try {
            Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignored) {
            // not a POSIX file system
        }
        return k;
    }

    // ------------------------------------------------------------------ live capture

    /** Whether the Settings checkbox is on; read from the stored setting at most every two seconds. */
    private boolean autoOn() {
        long now = System.currentTimeMillis();
        if (now - autoCheckedAt > 2000) {
            autoCheckedAt = now;
            auto = "1".equals(prefs.getString("auto"));
        }
        return auto;
    }

    private static final java.util.regex.Pattern STATIC = java.util.regex.Pattern.compile(
            "\\.(?:png|jpe?g|gif|svg|ico|webp|avif|bmp|css|woff2?|ttf|otf|eot|map|mp4|webm|mp3|wav)$", java.util.regex.Pattern.CASE_INSENSITIVE);

    /** Watches Proxy traffic; in-scope requests wait in a queue and are added to the model every few seconds. */
    private final class Capture implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) {
            return RequestToBeSentAction.continueWith(r);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
            try {
                if (unloading || !autoOn() || !r.toolSource().isFromTool(ToolType.PROXY)) {
                    return ResponseReceivedAction.continueWith(r);
                }
                HttpRequest rq = r.initiatingRequest();
                String path = rq.path();
                int q = path.indexOf('?');
                // the cheap checks first: static assets are most of the traffic, the scope lookup is not free
                if (!STATIC.matcher(q < 0 ? path : path.substring(0, q)).find() && api.scope().isInScope(rq.url())) {
                    live.offer(new Parse.Raw(rq.method(), rq.httpService().host(), rq.httpService().port(), rq.httpService().secure() ? "https" : "http",
                            rq.path(), (int) r.statusCode(), "", rq.toByteArray().getBytes(), r.toByteArray().getBytes(), false));
                }
            } catch (Throwable ignored) {
                // never let capture interfere with the traffic
            }
            return ResponseReceivedAction.continueWith(r);
        }
    }

    // ------------------------------------------------------------------ menu

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> picked = new ArrayList<>(event.selectedRequestResponses());
        if (picked.isEmpty()) {
            event.messageEditorRequestResponse().ifPresent(m -> picked.add(m.requestResponse()));
        }
        if (picked.isEmpty()) {
            return List.of();
        }
        JMenuItem add = new JMenuItem("Send " + picked.size() + " to burp2model");
        add.addActionListener(e -> {
            if (!unloading) {
                workers.execute(() -> send(picked));
            }
        });
        return List.of(add);
    }

    private void send(List<HttpRequestResponse> picked) {
        Session s = panel.awaitSession(60_000);
        if (s == null) {
            api.logging().raiseErrorEvent("burp2model: no model is open; check the burp2model tab's Settings.");
            return;
        }
        panel.working("burp2model: building from " + picked.size() + " request(s)…");
        try {
            List<Parse.Raw> raws = new ArrayList<>();
            for (HttpRequestResponse rr : picked) {
                raws.add(toRaw(rr));
            }
            MainPanel.Settings set = panel.settings();
            s.scope = set.scope();
            Session.AddResult r = s.add(raws, set.role(), null, set.replaceRole());
            panel.refresh();
            String msg = "burp2model: added " + r.added() + (r.duplicates() > 0 ? ", " + r.duplicates() + " already in the model" : "")
                    + (r.skipped() > 0 ? ", " + r.skipped() + " could not be read" : "")
                    + (r.build() == null ? "." : " · build " + r.build().id() + ": " + r.build().nodes() + " nodes, " + r.build().edges() + " edges.");
            api.logging().logToOutput(msg);
            panel.say(msg);
        } catch (Throwable t) {
            api.logging().raiseErrorEvent("burp2model: " + t);
            panel.sayError("burp2model: failed: " + t);
        } finally {
            panel.idle();
        }
    }

    private static Parse.Raw toRaw(HttpRequestResponse rr) {
        HttpRequest rq = rr.request();
        HttpResponse rs = rr.hasResponse() ? rr.response() : null;
        return new Parse.Raw(rq.method(), rq.httpService().host(), rq.httpService().port(), rq.httpService().secure() ? "https" : "http",
                rq.path(), rs == null ? null : (int) rs.statusCode(), "", rq.toByteArray().getBytes(),
                rs == null ? new byte[0] : rs.toByteArray().getBytes(), false);
    }
}
