package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Model;
import burp2model.engine.Recon;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/** Settings: the model, the next send, live capture, the request viewer, data and about, as cards whose fields keep their width. */
final class SettingsTab {
    private final MainPanel app;

    SettingsTab(MainPanel app) {
        this.app = app;
    }

    final JTextField nameField = new JTextField(16);

    final JTextField roleField = new JTextField(14);

    final JTextField scopeField = new JTextField(30);

    final JCheckBox replaceRole = new JCheckBox("Replace this role's earlier requests when sending");

    final JCheckBox autoCapture = new JCheckBox("Capture proxied traffic automatically (only hosts in Burp's target scope)");

    final JCheckBox burpEditor = new JCheckBox("Show requests and responses in Burp's message editor");

    final JCheckBox realValues = new JCheckBox("Show real cookies and tokens, as Burp captured them");

    Component build() {
        // a column of cards, at most 760 wide: a form whose fields keep their width whatever the pane does
        JPanel col = new JPanel();
        col.setLayout(new javax.swing.BoxLayout(col, javax.swing.BoxLayout.Y_AXIS));
        col.setBorder(BorderFactory.createEmptyBorder(18, 22, 22, 22));

        JPanel model = formCard("Model");
        formRow(model, 0, "Name", nameField, "Each name is a separate model; the header's switcher changes it too. Save to open it.");
        col.add(model);
        col.add(javax.swing.Box.createVerticalStrut(12));

        JPanel send = formCard("Next send");
        formRow(send, 0, "Role", roleField, "Optional, for example user or admin. Leave empty for one account.");
        formRow(send, 2, "In-scope hosts", scopeField, "Optional, comma separated. Default: the busiest host's registrable domain.");
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1;
        c.gridy = 4;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(8, 0, 0, 0);
        send.add(replaceRole, c);
        col.add(send);
        col.add(javax.swing.Box.createVerticalStrut(12));

        JPanel liveCard = formCard("Live capture");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.WEST;
        liveCard.add(autoCapture, c);
        c.gridy = 1;
        c.insets = new Insets(4, 24, 0, 0);
        liveCard.add(Widgets.muted("In-scope Proxy traffic joins the model every few seconds; a few samples of each request shape are kept."), c);
        col.add(liveCard);
        col.add(javax.swing.Box.createVerticalStrut(12));

        JPanel viewCard = formCard("Requests and responses");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.anchor = GridBagConstraints.WEST;
        viewCard.add(burpEditor, c);
        c.gridy = 1;
        c.insets = new Insets(4, 24, 0, 0);
        boolean inBurp = app.host().editors() != null;
        viewCard.add(Widgets.muted(inBurp
                ? "Burp's Pretty, Raw, Hex and Inspector views, over the same masked text burp2model stores. Off: burp2model's own coloured view."
                : "Only inside Burp. Here requests show in burp2model's own view."), c);
        burpEditor.setEnabled(inBurp);
        burpEditor.setSelected(app.burpEditorOn());
        burpEditor.addActionListener(e -> {
            app.host().set("editor.burp", burpEditor.isSelected() ? "1" : "0");
            app.applyMessageEditor();
        });
        c.gridy = 2;
        c.insets = new Insets(10, 0, 0, 0);
        viewCard.add(realValues, c);
        c.gridy = 3;
        c.insets = new Insets(4, 24, 0, 0);
        viewCard.add(Widgets.muted("Read from Burp's own copy when you open a request, never saved. Saved models, exports and Copy for AI stay masked."), c);
        realValues.setSelected(app.realValuesOn());
        realValues.addActionListener(e -> {
            app.host().set("viewer.real", realValues.isSelected() ? "1" : "0");
            app.applyMessageEditor();
        });
        col.add(viewCard);
        col.add(javax.swing.Box.createVerticalStrut(12));

        JButton save = new JButton("Save settings");
        JButton export = new JButton("Export model.json…");
        JButton summaryBtn = new JButton("Export summary (Markdown)…");
        JButton importBtn = new JButton("Import HAR or Burp export…");
        JButton clear = new JButton("Clear this model");
        JButton deleteBtn = new JButton("Delete this model…");
        deleteBtn.addActionListener(e -> app.models.delete());
        JButton aboutBtn = new JButton("Welcome page");
        aboutBtn.addActionListener(e -> app.showWelcome(true));
        JPanel saveRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        saveRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveRow.add(save);
        col.add(saveRow);
        col.add(javax.swing.Box.createVerticalStrut(18));

        JPanel data = formCard("Data");
        JPanel btns = new JPanel(new java.awt.GridLayout(0, 2, 8, 8));
        btns.setOpaque(false);
        for (JButton b : new JButton[] {importBtn, export, summaryBtn, clear, deleteBtn, aboutBtn}) {
            btns.add(b);
        }
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        data.add(btns, c);
        col.add(data);
        col.add(javax.swing.Box.createVerticalStrut(12));

        JPanel aboutCard = formCard("About");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        aboutCard.add(Widgets.wrapText("burp2model builds an evidence-cited model of one web app from the requests you send it; every line cites the "
                + "request that shows it. Cookies, tokens, keys and personal data are masked before anything is stored. It is a model "
                + "builder, never a scanner: leads are hypotheses to verify in an authorised session.\n\nModels live in "
                + "~/.burp2model/models/<name>/. Nothing is sent anywhere unless you run Recon or paste a package into your own AI.\n\n"
                + "Extension " + burp2model.engine.Version.EXTENSION + "  ·  github.com/falc0n-researcher/burp2model",
                Theme.font(12f, Font.PLAIN), Theme.MUTED), c);
        col.add(aboutCard);
        save.addActionListener(e -> {
            String n = nameField.getText().strip();
            if (!n.matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) {
                app.setStatus("The model name must be letters, digits, '.', '_' or '-'.", MainPanel.Level.ERROR);
                return;
            }
            boolean renamed = !n.equals(app.models.appName());
            app.host().set("app", n);
            app.host().set("role", roleField.getText().strip());
            app.host().set("scope", scopeField.getText().strip());
            app.host().set("replace", replaceRole.isSelected() ? "1" : "0");
            app.host().set("auto", autoCapture.isSelected() ? "1" : "0");
            if (renamed) {
                app.models.open(n, true);
            } else if (app.session() != null) {
                app.session().scope = app.settings().scope();
            }
            app.setStatus("Settings saved.", MainPanel.Level.OK);
            app.refresh();
        });
        export.addActionListener(e -> app.data.exportModel());
        importBtn.addActionListener(e -> app.data.importFile());
        summaryBtn.addActionListener(e -> app.data.exportSummary());
        clear.addActionListener(e -> {
            if (app.session() != null && JOptionPane.showConfirmDialog(app, "Delete everything in the model '" + app.session().name + "'?", "burp2model",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                Session s = app.session();
                app.async("Clearing the model…", () -> {
                    s.clear();
                    return s;
                }, x -> {
                    app.setStatus("Cleared the model '" + s.name + "'.", MainPanel.Level.OK);
                    app.refresh();
                }, t -> app.sayError("could not clear: " + MainPanel.messageOf(t)));
            }
        });
        JPanel holder = new JPanel(new BorderLayout()) {
            private static final long serialVersionUID = 1L;

            @Override
            public java.awt.Dimension getPreferredSize() {
                java.awt.Dimension d = super.getPreferredSize();
                return new java.awt.Dimension(Math.min(d.width, Math.round(760 * Theme.uiScale())), d.height);
            }
        };
        holder.add(col, BorderLayout.NORTH);
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.add(holder);
        javax.swing.JScrollPane sp = new javax.swing.JScrollPane(left);
        sp.setBorder(null);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    /**
     * Fill the fields from the saved settings, once: refreshes never touch them, so a half-typed value survives live
     * capture. Role, scope and replace update what the next send uses as they change, and are kept as soon as the field
     * is left; only a new model name needs Save (it opens another model).
     */
    void load() {
        MainPanel.Host host = app.host();
        nameField.setText(app.models.appName());
        roleField.setText(host.get("role", ""));
        scopeField.setText(host.get("scope", ""));
        replaceRole.setSelected("1".equals(host.get("replace", "0")));
        autoCapture.setSelected("1".equals(host.get("auto", "0")));
        roleField.getDocument().addDocumentListener(new SimpleDoc(this::typed));
        scopeField.getDocument().addDocumentListener(new SimpleDoc(this::typed));
        replaceRole.addItemListener(e -> {
            typed();
            host.set("replace", replaceRole.isSelected() ? "1" : "0");
        });
        autoCapture.addItemListener(e -> {
            host.set("auto", autoCapture.isSelected() ? "1" : "0");
            app.header.showLive();
        });
        java.awt.event.FocusAdapter keep = new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                host.set("role", roleField.getText().strip());
                host.set("scope", scopeField.getText().strip());
            }
        };
        roleField.addFocusListener(keep);
        scopeField.addFocusListener(keep);
        typed();
    }

    /** What the next send uses, from the fields as typed (saved or not). */
    private void typed() {
        app.settings = MainPanel.Settings.of(roleField.getText(), scopeField.getText(), replaceRole.isSelected());
    }

    /** A titled card for one group of settings; rows go in with formRow. */
    static JPanel formCard(String title) {
        JPanel card = new JPanel(new GridBagLayout()) {
            private static final long serialVersionUID = 1L;

            @Override
            protected void paintComponent(java.awt.Graphics g0) {
                java.awt.Graphics2D g = (java.awt.Graphics2D) g0.create();
                Theme.quality(g);
                g.setColor(Theme.surface());
                g.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g.setColor(Theme.line());
                g.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g.dispose();
            }
        };
        card.setOpaque(false);
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0),
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(30, 16, 14, 16), title, javax.swing.border.TitledBorder.LEFT,
                        javax.swing.border.TitledBorder.TOP, Theme.font(12f, Font.BOLD))));
        return card;
    }

    /** A label, its field filling the rest of the row, and a muted hint under the field. */
    static void formRow(JPanel card, int row, String label, JTextField field, String hint) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = row;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(row == 0 ? 0 : 10, 0, 0, 12);
        JLabel l = new JLabel(label);
        l.setPreferredSize(new java.awt.Dimension(Math.round(120 * Theme.uiScale()), l.getPreferredSize().height));
        card.add(l, c);
        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(row == 0 ? 0 : 10, 0, 0, 0);
        field.setMinimumSize(new java.awt.Dimension(Math.round(240 * Theme.uiScale()), field.getPreferredSize().height));
        card.add(field, c);
        c.gridy = row + 1;
        c.insets = new Insets(4, 0, 0, 0);
        card.add(Widgets.muted(hint), c);
    }

}
