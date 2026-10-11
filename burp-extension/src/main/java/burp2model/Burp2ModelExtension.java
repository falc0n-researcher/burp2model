package burp2model;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
            s.scope = panel.scope();
            Session.AddResult r = s.add(raws, panel.role(), null, panel.replaceRoleOnSend());
            panel.refresh();
            String msg = "burp2model: added " + r.added() + (r.duplicates() > 0 ? ", " + r.duplicates() + " already in the model" : "")
                    + (r.skipped() > 0 ? ", " + r.skipped() + " could not be read" : "") + " · build " + r.build().id() + ": "
                    + r.build().nodes() + " nodes, " + r.build().edges() + " edges.";
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

    static String unused() {
        return new String(new byte[0], StandardCharsets.UTF_8);
    }
}
