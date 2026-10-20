package burp2model.ui;

import burp2model.engine.Model;
import java.awt.Component;
import javax.swing.JPanel;

/** When the welcome page shows instead of the tabs: on first run and for an empty model, until the first requests arrive. */
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
        showing = on;
        if (on) {
            page.update("1".equals(app.host.get("auto", "0")), "1".equals(app.host.get("welcome.show", "0")));
        }
        cards.show(center, on ? "welcome" : "tabs");
    }

    /** Leave the welcome page for good (a model with `requests` in it is open). */
    void leave(int requests) {
        app.host.set("welcome.seen", "1");
        show(false);
        lastRequests = requests;
    }

    /** Called on each refresh: an empty model shows the welcome page, and the first requests take it away. */
    void forModel(Model m) {
        int n = m == null ? 0 : m.evidenceLog.size();
        if (app.session != null && n == 0 && !showing) {
            show(true);
        } else if (showing && n > 0 && lastRequests == 0) {
            app.host.set("welcome.seen", "1");
            show(false);
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
                page.update(true, "1".equals(host.get("welcome.show", "0")));
                app.setStatus("Live capture is on: in-scope Proxy traffic (Burp's target scope) joins the model every few seconds.", MainPanel.Level.OK);
            }

            @Override
            public void settings() {
                host.set("welcome.seen", "1");
                show(false);
                app.tabs.setSelectedComponent(app.settingsView);
            }

            @Override
            public void getStarted(boolean showOnStart) {
                host.set("welcome.seen", "1");
                host.set("welcome.show", showOnStart ? "1" : "0");
                show(false);
            }
        };
    }
}
