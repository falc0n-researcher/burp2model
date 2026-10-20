package burp2model.ui;

import burp2model.engine.Session;

/** Which model is open: opening or switching one off the Swing thread, the bundled sample, deleting a model. */
final class Models {
    /** The model that opens when none was chosen: the demo shop, so a first look has something in it. */
    static final String SAMPLE = "sample";
    /** What 1.1 opened by default, an empty model nobody asked for. */
    private static final String OLD_DEFAULT = "burp";

    private final MainPanel app;
    private final java.util.concurrent.CountDownLatch opened = new java.util.concurrent.CountDownLatch(1);

    Models(MainPanel app) {
        this.app = app;
    }

    /** The model to open: the one chosen in Settings, or the sample. An empty model from the old default gives way to it. */
    String appName() {
        return app.host.get("app", SAMPLE);
    }

    /** Open (or switch to) a model off the Swing thread; a large one takes a second or more to read and rebuild. */
    void open(String name, boolean applyScope) {
        MainPanel.Host host = app.host;
        app.async("Opening the model '" + name + "'…", () -> {
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
                s.scope = app.settings().scope();
            }
            if (!s.name.equals(name)) {
                host.set("app", s.name);
                app.settingsTab.nameField.setText(s.name);
            }
            app.session = s;
            opened.countDown();
            app.statusBar.dropMessage();                        // "Opening the model…" gives way to its summary at once
            app.refresh();
            reportProblems();
        }, t -> {
            opened.countDown();
            host.log("burp2model: could not open the model '" + name + "' (" + MainPanel.messageOf(t) + ")");
            app.sayError("could not open the model '" + name + "': " + MainPanel.messageOf(t));
        });
    }

    /** The open model, waiting up to `ms` for the first one to finish opening (a send right after Burp starts). */
    Session awaitSession(long ms) {
        try {
            opened.await(ms, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return app.session;
    }

    /** Say what could not be read when the model was opened; the damaged files are kept beside it. */
    private void reportProblems() {
        Session s = app.session;
        if (s == null) {
            return;
        }
        for (String p : s.problems()) {
            app.host.log("burp2model (" + s.name + "): " + p);
            app.sayError("burp2model: " + p);
        }
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
    void loadSample() {
        app.async("Loading the sample model…", () -> {
            Session s = app.host.session(SAMPLE);
            fillSample(s);
            return s;
        }, s -> {
            app.session = s;
            app.host.set("app", SAMPLE);
            app.settingsTab.nameField.setText(SAMPLE);
            app.header.listModels();
            app.welcome.leave(s.requestCount());
            app.refresh();
            app.setStatus("This is the sample model: a small demo shop seen as a user and as an admin. Your own model is untouched; "
                    + "switch back in Settings.", MainPanel.Level.OK);
        });
    }

    /** Delete the open model (after asking) and open the sample; deleting the sample itself just empties and refills it. */
    void delete() {
        Session s = app.session;
        if (s == null) {
            return;
        }
        int ok = javax.swing.JOptionPane.showConfirmDialog(app, "Delete the model '" + s.name + "' and every request saved in it?\n\nThis cannot be undone.",
                "Delete model", javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.WARNING_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        String name = s.name;
        app.async("Deleting the model '" + name + "'…", () -> {
            app.host.deleteModel(name);
            Session next = app.host.session(SAMPLE);
            fillSample(next);
            return next;
        }, next -> {
            app.session = next;
            app.host.set("app", SAMPLE);
            app.settingsTab.nameField.setText(SAMPLE);
            app.header.listModels();
            app.refresh();
            app.setStatus("Deleted the model '" + name + "'. The sample model is open.", MainPanel.Level.OK);
        }, t -> app.sayError("could not delete '" + name + "': " + MainPanel.messageOf(t)));
    }
}
