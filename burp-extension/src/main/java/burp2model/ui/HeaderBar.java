package burp2model.ui;

import burp2model.engine.ContextPack;
import burp2model.engine.Model;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.nio.file.Files;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;

/** The header: the logo, the model switcher, the Live button, search, Copy for AI, ⋯ and ?. */
final class HeaderBar {
    private final MainPanel app;

    HeaderBar(MainPanel app) {
        this.app = app;
    }

    Component build() {
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
        live.addActionListener(e -> setLive(!"1".equals(app.host().get("auto", "0"))));
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
            app.select(app.surfaceTab);
            app.surfaceTab.search(globalSearch.getText());
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
        imp.addActionListener(e -> app.data.importFile());
        JMenuItem expJson = new JMenuItem("Export model.json…");
        expJson.addActionListener(e -> app.data.exportModel());
        JMenuItem expMd = new JMenuItem("Export summary (Markdown)…");
        expMd.addActionListener(e -> app.data.exportSummary());
        JMenuItem del = new JMenuItem("Delete this model…");
        del.addActionListener(e -> app.models.delete());
        JMenuItem set = new JMenuItem("Settings");
        set.addActionListener(e -> {
            app.showWelcome(false);
            app.tabs.setSelectedComponent(app.settingsView);
        });
        for (JMenuItem mi : new JMenuItem[] {imp, expJson, expMd}) {
            moreMenu.add(mi);
        }
        moreMenu.addSeparator();
        moreMenu.add(del);
        moreMenu.addSeparator();
        moreMenu.add(set);
        more.addActionListener(e -> moreMenu.show(more, 0, more.getHeight()));
        JButton about = new JButton("?");
        about.setToolTipText("About burp2model: the welcome page");
        about.getAccessibleContext().setAccessibleName("About burp2model");
        about.addActionListener(e -> app.showWelcome(!app.welcome.showing()));
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

    final JComboBox<String> models = new JComboBox<>();

    final JButton live = new JButton();

    boolean listingModels;

    static final String NEW_MODEL = "New model…";

    /** Fill the switcher with the models saved on this machine, the open one selected. */
    void listModels() {
        Session s = app.session();
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

    void showModelName() {
        Session s = app.session();
        if (s != null && !s.name.equals(models.getSelectedItem())) {
            listModels();
        }
    }

    /** Open another model (or make a new one), as Settings does when its name changes. */
    void switchModel(String picked) {
        String name = picked;
        if (NEW_MODEL.equals(name)) {
            String n = JOptionPane.showInputDialog(app, "Name of the new model (letters, digits, '.', '_' or '-'):", "New model", JOptionPane.PLAIN_MESSAGE);
            listModels();
            if (n == null || n.isBlank()) {
                return;
            }
            name = n.strip();
        }
        if (!name.matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) {
            app.setStatus("The model name must be letters, digits, '.', '_' or '-'.", MainPanel.Level.ERROR);
            return;
        }
        if (app.session() != null && name.equals(app.session().name)) {
            return;
        }
        app.settingsTab.nameField.setText(name);
        app.host().set("app", name);
        app.models.open(name, true);
    }

    void setLive(boolean on) {
        app.host().set("auto", on ? "1" : "0");
        app.settingsTab.autoCapture.setSelected(on);
        showLive();
        app.setStatus(on ? "Live capture is on: in-scope Proxy traffic (Burp's target scope) joins the model every few seconds." : "Live capture is off.", MainPanel.Level.OK);
    }

    void showLive() {
        boolean on = "1".equals(app.host().get("auto", "0"));
        live.setText(on ? "● Live" : "Live: off");
        live.setForeground(on ? Theme.readable(Theme.GREEN, Theme.surface()) : Theme.MUTED);
        live.getAccessibleContext().setAccessibleName(on ? "Live capture is on" : "Live capture is off");
    }

    void copyForAi(String scope) {
        Model m = app.model();
        if (m == null) {
            app.say("Nothing to copy yet. Send some requests first.");
            return;
        }
        app.async("Packing the " + scope + " package…", () -> new String[] {ContextPack.forAi(m, scope), String.valueOf(ContextPack.tokens(m) / 1000)}, r -> {
            Tables.copy(r[0]);
            app.setStatus("Copied the " + scope + " package for your own AI (about " + r[1] + "k tokens). Values are masked; every claim cites a request.", MainPanel.Level.OK);
        });
    }

    final JPanel pills = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

    final JTextField globalSearch = new JTextField(22);

}
