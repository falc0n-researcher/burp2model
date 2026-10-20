package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Recon;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/** Recon: light, passive recon on one host, only when asked, shown as cards; the last run per host is kept with the model. */
final class ReconTab implements Tab {
    private final MainPanel app;
    private final JComboBox<String> reconHost = new JComboBox<>();
    private final JLabel reconStatus = new JLabel(" ");
    private final JButton copy = new JButton("Copy as text");
    private final java.awt.CardLayout cards = new java.awt.CardLayout();
    private final JPanel body = new JPanel(cards);
    private final JPanel result = new JPanel();
    private final Component view;
    private Map<String, Object> shown;

    ReconTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        fillRecon(m);
    }

    private Component build() {
        JPanel top = toolbar();
        top.add(new JLabel("Host"));
        reconHost.setEditable(true);
        reconHost.setPreferredSize(new java.awt.Dimension(280, 26));
        top.add(reconHost);
        JButton run = new JButton("Run light recon…");
        run.setFont(Theme.font(12f, Font.BOLD));
        top.add(run);
        top.add(copy);
        reconStatus.setForeground(Theme.MUTED);
        reconStatus.setFont(Theme.font(11f, Font.PLAIN));
        top.add(reconStatus);
        run.addActionListener(e -> runRecon());
        copy.setEnabled(false);
        copy.addActionListener(e -> {
            if (shown != null) {
                Tables.copy(Recon.format(shown));
                app.say("Copied the recon for " + shown.get("host") + ".");
            }
        });
        reconHost.addActionListener(e -> showSaved());

        Widgets.Card intro = new Widgets.Card(16);
        JPanel introText = new JPanel();
        introText.setOpaque(false);
        introText.setLayout(new BoxLayout(introText, BoxLayout.Y_AXIS));
        introText.add(Widgets.heading("Light, passive recon on one host"));
        introText.add(Widgets.wrapText("DNS records, the TLS certificate, the front page's status and security headers, robots.txt, "
                + "security.txt and sitemap.xml, and mail policy (SPF and DMARC).\n\nIt sends a handful of ordinary requests to the "
                + "host, so run it only on targets you are authorised to test. Nothing runs until you press the button, and each "
                + "run is kept with the model.", Theme.font(12f, Font.PLAIN), Theme.MUTED));
        intro.add(introText, BorderLayout.CENTER);
        JPanel introWrap = new JPanel(new BorderLayout());
        introWrap.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        introWrap.add(intro, BorderLayout.NORTH);

        result.setLayout(new BoxLayout(result, BoxLayout.Y_AXIS));
        result.setBorder(BorderFactory.createEmptyBorder(14, 16, 16, 16));
        JPanel resultWrap = new FitWidth();
        resultWrap.add(result, BorderLayout.NORTH);
        // chips wrap to the width they are given, so a new width means new heights: lay out again once it is known
        resultWrap.addComponentListener(new java.awt.event.ComponentAdapter() {
            private int width = -1;

            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (resultWrap.getWidth() != width) {
                    width = resultWrap.getWidth();
                    SwingUtilities.invokeLater(ReconTab.this::relayout);
                }
            }
        });
        body.add(introWrap, "intro");
        body.add(scroll(resultWrap), "result");
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(body, BorderLayout.CENTER);
        return p;
    }

    private void fillRecon(Model m) {
        Object cur = reconHost.getEditor().getItem();
        reconHost.removeAllItems();
        if (m != null) {
            for (Model.Node n : m.nodes.values()) {
                if (n.type.equals("host")) {
                    reconHost.addItem(n.label);
                }
            }
        }
        if (cur != null && !String.valueOf(cur).isBlank()) {
            reconHost.setSelectedItem(cur);
        }
        showSaved();
    }

    private String host() {
        return String.valueOf(reconHost.getEditor().getItem()).strip().toLowerCase();
    }

    private Path savedFile(String h) {
        return app.session() == null || h.isEmpty() || !h.matches("[a-z0-9.\\-]+") ? null : app.session().dir().resolve("recon-" + h + ".json");
    }

    /** The last run for the chosen host, if one was kept with the model. */
    @SuppressWarnings("unchecked")
    private void showSaved() {
        Path f = savedFile(host());
        if (f != null && Files.isRegularFile(f)) {
            try {
                showResult((Map<String, Object>) Json.parse(Files.readString(f, StandardCharsets.UTF_8)));
                reconStatus.setText("last run kept with the model");
                return;
            } catch (Exception ignored) {
                // a damaged file is just not shown
            }
        }
        shown = null;
        copy.setEnabled(false);
        reconStatus.setText(" ");
        cards.show(body, "intro");
    }

    private void runRecon() {
        String h = host();
        if (h.isEmpty() || !h.matches("[a-z0-9.\\-]+")) {
            reconStatus.setText("enter a host name");
            return;
        }
        int ok = JOptionPane.showConfirmDialog(app, "Run light recon against " + h + "?\n\nThis sends a few ordinary requests (DNS, a TLS handshake, GETs for /, robots.txt,\n"
                + "security.txt and sitemap.xml). Only do this for targets you are authorised to test.", "burp2model recon", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        reconStatus.setText("running…");
        app.host().background("burp2model-recon", () -> {
            try {
                Map<String, Object> r = Recon.run(h, s -> SwingUtilities.invokeLater(() -> reconStatus.setText("running: " + s)));
                Path f = savedFile(h);
                if (f != null) {
                    Files.writeString(f, Json.pretty(r), StandardCharsets.UTF_8);
                }
                SwingUtilities.invokeLater(() -> {
                    showResult(r);
                    reconStatus.setText("done");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> reconStatus.setText("failed: " + t.getMessage()));
            }
        });
    }

    // ------------------------------------------------------------------ the result as cards

    @SuppressWarnings("unchecked")
    void showResult(Map<String, Object> r) {
        shown = r;
        copy.setEnabled(true);
        result.removeAll();
        JLabel title = new JLabel(String.valueOf(r.get("host")));
        title.setFont(Theme.font(20f, Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        result.add(title);
        JLabel sub = Widgets.muted("Run " + String.valueOf(r.getOrDefault("generated_at", "")).replace('T', ' ').replace("Z", " UTC")
                + "   ·   observations only, nothing here is a vulnerability");
        sub.setAlignmentX(Component.LEFT_ALIGNMENT);
        result.add(sub);
        result.add(Box.createVerticalStrut(12));

        JPanel grid = new JPanel(new GridLayout(0, 2, 12, 12));
        grid.setOpaque(false);
        grid.setAlignmentX(Component.LEFT_ALIGNMENT);
        grid.add(dnsCard((Map<String, Object>) r.getOrDefault("dns", Map.of())));
        grid.add(tlsCard((Map<String, Object>) r.getOrDefault("tls", Map.of())));
        grid.add(httpCard((Map<String, Object>) r.getOrDefault("http", Map.of())));
        grid.add(filesCard((Map<String, Object>) r.getOrDefault("well_known", Map.of())));
        grid.add(mailCard((Map<String, Object>) r.getOrDefault("mail", Map.of())));
        result.add(grid);
        cards.show(body, "result");
        relayout();
        SwingUtilities.invokeLater(this::relayout);
    }

    private void relayout() {
        invalidateTree(result);
        result.revalidate();
        result.repaint();
    }

    private static void invalidateTree(java.awt.Container c) {
        c.invalidate();
        for (Component k : c.getComponents()) {
            if (k instanceof java.awt.Container cc) {
                invalidateTree(cc);
            }
        }
    }

    /** Follows the scroll pane's width (the cards wrap their text) and scrolls only up and down. */
    private static final class FitWidth extends JPanel implements javax.swing.Scrollable {
        private static final long serialVersionUID = 1L;

        FitWidth() {
            super(new BorderLayout());
        }

        @Override
        public java.awt.Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle r, int o, int d) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle r, int o, int d) {
            return Math.max(16, r.height - 32);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /** A card: a heading, then rows of a muted label and its value. */
    private static final class Section extends Widgets.Card {
        private static final long serialVersionUID = 1L;
        private final JPanel rows = new JPanel(new GridBagLayout());
        private int row;
        private final int labelWidth;

        Section(String heading) {
            this(heading, 96);
        }

        Section(String heading, int labelWidth) {
            super(12);
            this.labelWidth = labelWidth;
            add(Widgets.heading(heading), BorderLayout.NORTH);
            rows.setOpaque(false);
            JPanel top = new JPanel(new BorderLayout());
            top.setOpaque(false);
            top.add(rows, BorderLayout.NORTH);
            add(top, BorderLayout.CENTER);
        }

        Section line(String label, JComponent value) {
            GridBagConstraints c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = row;
            c.anchor = GridBagConstraints.NORTHWEST;
            c.insets = new Insets(row == 0 ? 0 : 6, 0, 0, 12);
            JLabel l = new JLabel(label);
            l.setFont(Theme.font(11f, Font.PLAIN));
            l.setForeground(Theme.MUTED);
            l.setPreferredSize(new java.awt.Dimension(Math.round(labelWidth * Theme.uiScale()), l.getPreferredSize().height));
            rows.add(l, c);
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(row == 0 ? 0 : 6, 0, 0, 0);
            rows.add(value, c);
            row++;
            return this;
        }

        Section line(String label, String value) {
            return line(label, text(value));
        }
    }

    private static JComponent text(String s) {
        return Widgets.wrapText(s == null || s.isBlank() ? "—" : s, Theme.mono(12f), Theme.fg());
    }

    private static JComponent chips(List<?> items, Color color) {
        JPanel p = Widgets.wrapFlow(4);
        p.setBorder(BorderFactory.createEmptyBorder(-4, -4, 0, 0));
        for (Object o : items) {
            p.add(new Widgets.Chip(String.valueOf(o), color));
        }
        if (items.isEmpty()) {
            p.add(Widgets.muted("none"));
        }
        return p;
    }

    private static JComponent chip(String s, Color color) {
        return chips(List.of(s), color);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> m, String k) {
        return m.get(k) instanceof List<?> l ? (List<Object>) l : List.of();
    }

    private static JComponent dnsCard(Map<String, Object> d) {
        Section s = new Section("DNS");
        s.line("Addresses", String.join(", ", list(d, "addresses").stream().map(String::valueOf).toList()));
        for (String k : new String[] {"MX", "NS", "TXT"}) {
            if (d.containsKey(k)) {
                s.line(k, String.join("\n", list(d, k).stream().map(String::valueOf).toList()));
            }
        }
        return s;
    }

    private static JComponent tlsCard(Map<String, Object> t) {
        Section s = new Section("TLS certificate");
        if (t.containsKey("error")) {
            return s.line("Status", chip("could not connect", Theme.AMBER)).line("Error", String.valueOf(t.get("error")));
        }
        long days = t.get("days_left") instanceof Number n ? n.longValue() : 0;
        Color c = days < 0 ? Theme.RED : days <= 30 ? Theme.AMBER : Theme.GREEN;
        return s.line("Expires", chip(String.valueOf(t.get("expires")).replace('T', ' ').replace("Z", "") + "  ·  " + (days < 0 ? "expired" : days + " days left"), c))
                .line("Protocol", String.valueOf(t.get("version")))
                .line("Issuer", String.valueOf(t.get("issuer")))
                .line("Names", String.join(", ", list(t, "names").stream().map(String::valueOf).toList()));
    }

    private static JComponent httpCard(Map<String, Object> h) {
        Section s = new Section("Front page");
        if (h.containsKey("error")) {
            return s.line("Status", chip("could not fetch", Theme.AMBER)).line("Error", String.valueOf(h.get("error")));
        }
        int code = h.get("status") instanceof Number n ? n.intValue() : 0;
        return s.line("Status", chip(String.valueOf(code), Theme.status(code)))
                .line("Server", String.valueOf(h.getOrDefault("server", "")))
                .line("Headers set", chips(list(h, "security_headers_present"), Theme.GREEN))
                .line("Missing", chips(list(h, "security_headers_missing"), Theme.AMBER));
    }

    @SuppressWarnings("unchecked")
    private static JComponent filesCard(Map<String, Object> files) {
        Section s = new Section("Well-known files", 190);
        files.forEach((k, v) -> {
            Map<String, Object> f = v instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
            boolean present = Boolean.TRUE.equals(f.get("present"));
            String what = present ? "present" + (f.containsKey("disallow_rules") ? "  ·  " + f.get("disallow_rules") + " Disallow rules" : "") : "not found";
            s.line(k, chip(what, present ? Theme.GREEN : Theme.GRAY));
        });
        return s;
    }

    private static JComponent mailCard(Map<String, Object> m) {
        Section s = new Section("Mail policy");
        for (String k : new String[] {"spf", "dmarc"}) {
            String v = String.valueOf(m.getOrDefault(k, "none"));
            s.line(k.toUpperCase(), "none".equals(v) ? chip("none published", Theme.AMBER) : text(v));
        }
        return s;
    }
}
