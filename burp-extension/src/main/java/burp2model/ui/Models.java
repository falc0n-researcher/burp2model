package burp2model.ui;

import burp2model.engine.Session;

/** Which model is open: opening or switching one off the Swing thread, the bundled sample, deleting a model. */
final class Models {
    /** The demo shop, opened only when asked for (Try the sample model, or the header's switcher). */
    static final String SAMPLE = "sample";
    /** The model sends go to when none was chosen. */
    static final String DEFAULT = "default";

    private final MainPanel app;
    private final java.util.concurrent.CountDownLatch opened = new java.util.concurrent.CountDownLatch(1);

    Models(MainPanel app) {
        this.app = app;
    }

    /** The model to open: the one chosen in Settings, or "default". The sample never opens by itself. */
    String appName() {
        String a = app.host.get("app", DEFAULT);
        return a.isBlank() || SAMPLE.equals(a) ? DEFAULT : a;
    }

    /** Open (or switch to) a model off the Swing thread; a large one takes a second or more to read and rebuild. */
    void open(String name, boolean applyScope) {
        MainPanel.Host host = app.host;
        app.async("Opening the model '" + name + "'…", () -> {
            Session s = host.session(name);
            if (SAMPLE.equals(s.name)) {
                fillSample(s);                                  // switched to the sample: before it is shown, so it is full
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
            // the sample is not remembered as the model to open: the next start opens the user's own model again
            app.session = s;
            app.settingsTab.nameField.setText(SAMPLE);
            app.header.listModels();
            app.welcome.leave(s.requestCount());
            app.refresh();
            app.setStatus("This is the sample model: a small demo shop seen as a user and as an admin. Your own model is untouched; "
                    + "switch back with the model switcher in the header.", MainPanel.Level.OK);
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
            return app.host.session(DEFAULT);                   // an empty default model (deleting "default" empties it)
        }, next -> {
            app.session = next;
            app.host.set("app", next.name);
            app.settingsTab.nameField.setText(next.name);
            app.header.listModels();
            app.refresh();
            app.setStatus("Deleted the model '" + name + "'. The model '" + next.name + "' is open.", MainPanel.Level.OK);
        }, t -> app.sayError("could not delete '" + name + "': " + MainPanel.messageOf(t)));
    }
}
