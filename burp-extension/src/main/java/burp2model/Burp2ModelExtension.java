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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
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
    private final Map<String, Session> sessions = new HashMap<>();
    private final ConcurrentLinkedQueue<Parse.Raw> live = new ConcurrentLinkedQueue<>();
    private volatile boolean auto;
    private long autoCheckedAt;
    private int sinceSnapshot;
    private long lastSnapshot = System.currentTimeMillis();
    private ScheduledExecutorService flusher;

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
        panel = new MainPanel(new MainPanel.Host() {
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
                Session s = sessions.get(name);
                if (s == null) {
                    s = new Session(home, name);
                    sessions.put(name, s);
                }
                return s;
            }
        });
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("burp2model", panel);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.http().registerHttpHandler(new Capture());
        flusher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(null, r, "burp2model-live", 64L * 1024 * 1024);
            t.setDaemon(true);
            return t;
        });
        flusher.scheduleWithFixedDelay(this::flushLive, 5, 5, TimeUnit.SECONDS);
        api.extension().registerUnloadingHandler(() -> flusher.shutdownNow());
        api.logging().logToOutput("burp2model ready. Right-click requests and choose Send to burp2model; the model is in the burp2model tab.");
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
                if (autoOn() && r.toolSource().isFromTool(ToolType.PROXY) && api.scope().isInScope(r.initiatingRequest().url())
                        && !STATIC.matcher(r.initiatingRequest().path().split("\\?", 2)[0]).find() && live.size() < 5000) {
                    HttpRequest rq = r.initiatingRequest();
                    live.add(new Parse.Raw(rq.method(), rq.httpService().host(), rq.httpService().port(), rq.httpService().secure() ? "https" : "http",
                            rq.path(), (int) r.statusCode(), "", rq.toByteArray().getBytes(), r.toByteArray().getBytes(), false));
                }
            } catch (Throwable ignored) {
                // never let capture interfere with the traffic
            }
            return ResponseReceivedAction.continueWith(r);
        }
    }

    private void flushLive() {
        try {
            Session s = panel == null ? null : panel.session();
            if (s == null || live.isEmpty()) {
                return;
            }
            List<Parse.Raw> raws = drain(live, 500);
            MainPanel.Settings set = panel.settings();
            s.scope = set.scope();
            Session.AddResult res = s.add(raws, set.role(), "live capture", false, false);
            sinceSnapshot += res.added();
            if (snapshotDue(sinceSnapshot, System.currentTimeMillis() - lastSnapshot)) {
                s.snapshot("live capture");
                sinceSnapshot = 0;
                lastSnapshot = System.currentTimeMillis();
            }
            if (res.added() > 0) {
                panel.refresh();
                panel.say("burp2model live: +" + res.added() + " requests · " + s.requestCount() + " in the model");
            }
        } catch (Throwable t) {
            api.logging().logToError("burp2model live capture: " + t);
        }
    }

    /** Take up to max items off the queue; the size is checked before polling, so nothing is taken and then dropped. */
    static <T> List<T> drain(java.util.Queue<T> q, int max) {
        List<T> out = new ArrayList<>();
        T r;
        while (out.size() < max && (r = q.poll()) != null) {
            out.add(r);
        }
        return out;
    }

    /** Live capture records a build every 40 new requests, or after three minutes once anything new arrived; duplicates never count. */
    static boolean snapshotDue(int newSinceLast, long msSinceLast) {
        return newSinceLast >= 40 || (newSinceLast > 0 && msSinceLast > 180_000);
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
        add.addActionListener(e -> new Thread(null, () -> send(picked), "burp2model-send", 64L * 1024 * 1024).start());
        return List.of(add);
    }

    private void send(List<HttpRequestResponse> picked) {
        Session s = panel.session();
        if (s == null) {
            api.logging().raiseErrorEvent("burp2model: no model is open; check the burp2model tab's Settings.");
            return;
        }
        panel.say("burp2model: building from " + picked.size() + " request(s)…");
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
            panel.say("burp2model: failed: " + t);
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
