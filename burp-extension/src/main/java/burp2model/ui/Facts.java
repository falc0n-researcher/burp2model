package burp2model.ui;

import burp2model.engine.Analysis;
import burp2model.engine.Json;
import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/** The facts about one thing, laid out as a card: what it is, its key properties, what it connects to. */
final class Facts extends JPanel {
    /** A column that is always as wide as the scroll pane, so wrapped text wraps. */
    private static final class Column extends JPanel implements javax.swing.Scrollable {
        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle r, int o, int d) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle r, int o, int d) {
            return 80;
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

    private final JPanel body = new Column();
    private final JScrollPane scroll;
    private java.util.function.Consumer<String> onNode = id -> { };

    Facts() {
        super(new BorderLayout());
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));
        scroll = new JScrollPane(body);
        scroll.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Theme.LINE));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
        clear("Select something to see its facts.");
    }

    void onNode(java.util.function.Consumer<String> c) {
        onNode = c;
    }

    void clear(String hint) {
        body.removeAll();
        JLabel l = Widgets.muted(hint);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(l);
        body.revalidate();
        body.repaint();
    }

    @SuppressWarnings("unchecked")
    void show(Model.Node n, Model m) {
        body.removeAll();
        JLabel title = new JLabel("<html>" + escape(n.label) + "</html>");
        title.setFont(Theme.mono(13f).deriveFont(Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(title);
        body.add(Box.createVerticalStrut(6));
        JPanel chips = Widgets.flow(4);
        chips.setAlignmentX(Component.LEFT_ALIGNMENT);
        chips.add(new Widgets.Chip(n.type.replace('_', ' '), Theme.type(n.type)));
        Object st = n.attrs.get("api_state");
        if (st != null) {
            chips.add(new Widgets.Chip(String.valueOf(st).replace('_', ' ').toLowerCase(), Theme.state(String.valueOf(st))));
        }
        for (String r : n.roles) {
            chips.add(new Widgets.Chip("role " + r, Theme.PURPLE));
        }
        body.add(chips);
        body.add(Box.createVerticalStrut(8));

        JPanel grid = new JPanel(new GridBagLayout());
        grid.setOpaque(false);
        grid.setAlignmentX(Component.LEFT_ALIGNMENT);
        int row = 0;
        for (Map.Entry<String, Object> a : n.attrs.entrySet()) {
            Object v = a.getValue();
            if (a.getKey().equals("api_state") || v == null || (v instanceof List<?> l && l.isEmpty()) || (v instanceof Map<?, ?> mm && mm.isEmpty())) {
                continue;
            }
            String text = v instanceof Map || v instanceof List ? Json.write(v).replace("\"", "") : String.valueOf(v);
            row = kv(grid, row, a.getKey().replace('_', ' '), text);
        }
        row = kv(grid, row, "requests behind it", String.valueOf(n.evidence.size()));
        body.add(grid);

        if (m != null) {
            JLabel h = Widgets.heading("Connections");
            h.setBorder(BorderFactory.createEmptyBorder(12, 0, 4, 0));
            h.setAlignmentX(Component.LEFT_ALIGNMENT);
            body.add(h);
            int shown = 0;
            int total = 0;
            for (int at : incident(m, n.id)) {
                Model.Edge e = m.edges.get(at);
                boolean out = e.src.equals(n.id);
                total++;
                if (shown >= 24) {
                    continue;
                }
                Model.Node o = m.nodes.get(out ? e.dst : e.src);
                if (o == null) {
                    continue;
                }
                shown++;
                body.add(link(out ? "→" : "←", e.type.toLowerCase().replace('_', ' '), e.state, o));
            }
            if (total > shown) {
                JLabel more = Widgets.muted("… " + (total - shown) + " more");
                more.setAlignmentX(Component.LEFT_ALIGNMENT);
                body.add(more);
            }
            if (total == 0) {
                JLabel none = Widgets.muted("none");
                none.setAlignmentX(Component.LEFT_ALIGNMENT);
                body.add(none);
            }
        }
        done();
    }

    void showLead(Analysis.Lead l) {
        body.removeAll();
        JLabel title = new JLabel("<html>" + escape(l.endpoint().label) + "</html>");
        title.setFont(Theme.mono(13f).deriveFont(Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(title);
        body.add(Box.createVerticalStrut(8));
        for (Analysis.Signal s : l.signals()) {
            JPanel card = new JPanel(new BorderLayout());
            card.setOpaque(false);
            card.setAlignmentX(Component.LEFT_ALIGNMENT);
            card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, Theme.severity(s.sev())),
                    BorderFactory.createEmptyBorder(2, 10, 8, 4)));
            JLabel t = new JLabel(s.title());
            t.setFont(Theme.font(12f, Font.BOLD));
            JTextArea why = text(s.why());
            JTextArea next = text("Do next: " + s.next());
            next.setForeground(Theme.MUTED);
            JPanel col = new JPanel();
            col.setOpaque(false);
            col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
            col.add(t);
            col.add(why);
            col.add(next);
            card.add(col, BorderLayout.CENTER);
            body.add(card);
        }
        done();
    }

    void showText(String heading, String text) {
        body.removeAll();
        JLabel t = new JLabel(heading);
        t.setFont(Theme.font(13f, Font.BOLD));
        t.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(t);
        body.add(Box.createVerticalStrut(8));
        JTextArea a = text(text);
        a.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(a);
        done();
    }

    private void done() {
        body.add(Box.createVerticalGlue());
        body.revalidate();
        body.repaint();
        javax.swing.SwingUtilities.invokeLater(() -> scroll.getVerticalScrollBar().setValue(0));
    }

    private static JTextArea text(String s) {
        JTextArea a = new JTextArea(s);
        a.setEditable(false);
        a.setOpaque(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setFont(Theme.font(12f, Font.PLAIN));
        a.setBorder(null);
        a.setAlignmentX(Component.LEFT_ALIGNMENT);
        return a;
    }

    private int kv(JPanel grid, int row, String k, String v) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = row;
        c.insets = new Insets(1, 0, 1, 10);
        c.anchor = GridBagConstraints.NORTHWEST;
        JLabel key = Widgets.muted(k);
        c.gridx = 0;
        grid.add(key, c);
        JTextArea val = text(v.length() > 400 ? v.substring(0, 400) + "…" : v);
        val.setFont(Theme.mono(11f));
        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        grid.add(val, c);
        return row + 1;
    }

    private javax.swing.JComponent link(String arrow, String edge, String state, Model.Node o) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 1));
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel a = new JLabel(arrow);
        a.setForeground(Theme.MUTED);
        JLabel e = Widgets.muted(edge + (state.equals("OBSERVED") ? "" : " (" + state.toLowerCase() + ")"));
        JLabel dot = new JLabel("●");
        dot.setForeground(Theme.type(o.type));
        dot.setFont(Theme.font(9f, Font.PLAIN));
        String hex = Theme.hex(Theme.readable(Theme.BLUE, Theme.surface()));
        JLabel name = new JLabel("<html><font color='" + hex + "'><u>" + escape(o.label.length() > 60 ? o.label.substring(0, 59) + "…" : o.label) + "</u></font></html>");
        name.setFont(Theme.mono(11f));
        name.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        name.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                onNode.accept(o.id);
            }
        });
        p.add(a);
        p.add(e);
        p.add(dot);
        p.add(name);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        return p;
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }


    private Model indexed;
    private Map<String, List<Integer>> byNode = Map.of();

    /** The positions of the edges touching a node, in edge order; indexed once per model instead of scanning every edge per click. */
    private List<Integer> incident(Model m, String id) {
        if (indexed != m) {
            Map<String, List<Integer>> idx = new java.util.HashMap<>();
            for (int i = 0; i < m.edges.size(); i++) {
                Model.Edge e = m.edges.get(i);
                idx.computeIfAbsent(e.src, k -> new java.util.ArrayList<>()).add(i);
                if (!e.dst.equals(e.src)) {
                    idx.computeIfAbsent(e.dst, k -> new java.util.ArrayList<>()).add(i);
                }
            }
            byNode = idx;
            indexed = m;
        }
        return byNode.getOrDefault(id, List.of());
    }
}
