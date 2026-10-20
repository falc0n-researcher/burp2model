package burp2model.ui;

import burp2model.engine.Model;
import burp2model.engine.Session;
import java.awt.Component;
import javax.swing.JPanel;

/** When the welcome page shows instead of the tabs: every time Burp starts, and for an empty model until the first requests arrive. */
final class WelcomeFlow {
    private final MainPanel app;
    private final java.awt.CardLayout cards = new java.awt.CardLayout();
    /** The welcome page or the tabs, one at a time. */
    final JPanel center = new JPanel(cards);
    private final Welcome page;
    private boolean showing;
    /** Requests in the model when it was last shown; the welcome page steps aside when the first ones arrive. */
    private int lastRequests = -1;

    WelcomeFlow(MainPanel app, Component tabs) {
        this.app = app;
        page = new Welcome(actions(), burp2model.engine.Version.EXTENSION);
        center.add(page, "welcome");
        center.add(tabs, "tabs");
    }

    boolean showing() {
        return showing;
    }

    void show(boolean on) {
        boolean appearing = on && !showing;
        showing = on;
        if (appearing) {
            page.focusStart();
        }
        if (on) {
            Session s = app.session;
            page.update("1".equals(app.host.get("auto", "0")), s == null ? null : s.name, s == null ? 0 : s.requestCount());
        }
        cards.show(center, on ? "welcome" : "tabs");
    }

    /** Leave the welcome page (a model with `requests` in it is open). */
    void leave(int requests) {
        show(false);
        lastRequests = requests;
    }

    /** Called on each refresh: an empty model shows the welcome page, and the first requests take it away. */
    void forModel(Model m) {
        int n = m == null ? 0 : m.evidenceLog.size();
        if (app.session != null && n == 0 && !showing) {
            show(true);
        } else if (showing && n > 0 && lastRequests == 0) {
            show(false);                                        // the first requests arrived: show them
        } else if (showing) {
            show(true);                                         // keep the open model's name and size current
        }
        lastRequests = app.session == null ? -1 : n;
    }

    Welcome.Actions actions() {
        MainPanel.Host host = app.host;
        return new Welcome.Actions() {
            @Override
            public void sample() {
                app.models.loadSample();
            }

            @Override
            public void importFile() {
                app.data.importFile();
            }

            @Override
            public void liveCapture() {
                app.settingsTab.autoCapture.setSelected(true);
                host.set("auto", "1");
                show(true);
                app.setStatus("Live capture is on: in-scope Proxy traffic (Burp's target scope) joins the model every few seconds.", MainPanel.Level.OK);
            }

            @Override
            public void settings() {
                show(false);
                app.tabs.setSelectedComponent(app.settingsView);
            }

            @Override
            public void getStarted() {
                show(false);
            }
        };
    }
}
