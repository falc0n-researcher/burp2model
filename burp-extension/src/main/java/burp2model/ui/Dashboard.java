package burp2model.ui;

import burp2model.engine.Analysis;
import burp2model.engine.Model;
import burp2model.engine.Stack;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/** The first screen: numbers, code versus runtime, response mix, the technology stack and the leads to open first. */
final class Dashboard extends JPanel {
    /** The page tracks the pane's width: long lines are cut short with "…" instead of scrolling sideways. */
    private final JPanel content = new Fit();

    private static final class Fit extends JPanel implements javax.swing.Scrollable {
        private static final long serialVersionUID = 1L;

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle r, int o, int d) {
            return 18;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle r, int o, int d) {
            return o == javax.swing.SwingConstants.VERTICAL ? r.height - 36 : r.width;
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
    private final JScrollPane scroll;
    private Consumer<Analysis.Lead> onLead = l -> { };
    private Runnable onWelcome = () -> { };
    private Model shown;
    private List<Analysis.Lead> shownLeads = List.of();
    private int columns = 6;

    Dashboard() {
        super(new BorderLayout());
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(16, 20, 20, 20));
        scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(18);
        add(scroll, BorderLayout.CENTER);
        // the tiles and the stack reflow with the width: six tiles in a row when there is room, then three, then two
        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                int c = columnsFor(getWidth());
                if (c != columns) {
                    columns = c;
                    update(shown, shownLeads);
                }
            }
        });
    }

    private static int columnsFor(int width) {
        return width <= 0 || width >= 900 ? 6 : width >= 520 ? 3 : 2;
    }

    void onWelcome(Runnable r) {
        onWelcome = r;
    }

    void onLead(Consumer<Analysis.Lead> c) {
        onLead = c;
    }

    @SuppressWarnings("unchecked")
    void update(Model m, List<Analysis.Lead> leads) {
        shown = m;
        shownLeads = leads == null ? List.of() : leads;
        content.removeAll();
        if (m == null) {
            empty();
            return;
        }
        Map<String, Object> c = m.counts();
        Map<String, Object> st = (Map<String, Object>) c.get("api_state");

        JLabel name = new JLabel(m.name);
        name.setFont(Theme.font(24f, Font.BOLD));
        name.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel sub = new JLabel(summary(m, c, st));
        sub.setFont(Theme.font(13f, Font.PLAIN));
        sub.setForeground(Theme.MUTED);
        sub.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(name);
        content.add(Box.createVerticalStrut(4));
        content.add(sub);
        content.add(Box.createVerticalStrut(16));

        int rows = (6 + columns - 1) / columns;
        JPanel tiles = new JPanel(new GridLayout(rows, columns, 10, 10));
        tiles.setOpaque(false);
        tiles.setAlignmentX(Component.LEFT_ALIGNMENT);
        tiles.setMaximumSize(new Dimension(Integer.MAX_VALUE, Math.round(rows * 86 * Theme.uiScale())));
        tile(tiles, "API endpoints", c.get("endpoints"), null);
        tile(tiles, "Requests", m.evidenceLog.size(), null);
        tile(tiles, "Pages", c.get("routes"), null);
        tile(tiles, "To check", leads.size(), Theme.ACCENT);
        tile(tiles, "Open questions", c.get("unknowns"), null);
        tile(tiles, "Third parties", c.get("third_parties"), null);
        content.add(tiles);
        content.add(Box.createVerticalStrut(14));

        boolean narrow = columns < 6;
        JPanel row = new JPanel(new GridLayout(narrow ? 2 : 1, narrow ? 1 : 2, 14, 14));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, Math.round((narrow ? 260 : 130) * Theme.uiScale())));
        row.add(codeVsRuntime(st));
        row.add(responses(m));
        content.add(row);
        content.add(Box.createVerticalStrut(14));

        if (!m.stack.isEmpty()) {
            content.add(stack(m));
            content.add(Box.createVerticalStrut(14));
        }
        content.add(leadsCard(leads));
        content.add(Box.createVerticalStrut(14));
        content.add(hygiene(m));
        content.add(Box.createVerticalGlue());
        content.revalidate();
        content.repaint();
        scroll.getVerticalScrollBar().setValue(0);
    }

    private static String summary(Model m, Map<String, Object> c, Map<String, Object> st) {
        long code = ((Number) st.getOrDefault("STATIC_ONLY", 0L)).longValue();
        return c.get("endpoints") + " API endpoints on " + c.get("routes") + " pages, from " + m.evidenceLog.size() + " requests"
                + (code > 0 ? ". " + code + " are named in the code but never called" : "") + ".   Scope: " + String.join(", ", m.scope);
    }

    private static void tile(JPanel row, String label, Object value, Color accent) {
        Widgets.Tile t = new Widgets.Tile(label, accent);
        t.set(value);
        row.add(t);
    }

    private JComponent codeVsRuntime(Map<String, Object> st) {
        Widgets.Card card = new Widgets.Card(12);
        card.add(Widgets.heading("What the code names vs what ran"), BorderLayout.NORTH);
        Widgets.Bar bar = new Widgets.Bar();
        bar.set(List.of(new Widgets.Bar.Seg("Both", num(st.get("BOTH")), Theme.GREEN),
                new Widgets.Bar.Seg("Traffic only", num(st.get("RUNTIME_ONLY")), Theme.BLUE),
                new Widgets.Bar.Seg("Code only", num(st.get("STATIC_ONLY")), Theme.ACCENT)));
        card.add(bar, BorderLayout.CENTER);
        return card;
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    @SuppressWarnings("unchecked")
    private JComponent responses(Model m) {
        Widgets.Card card = new Widgets.Card(12);
        card.add(Widgets.heading("Responses"), BorderLayout.NORTH);
        long[] by = new long[6];
        for (Map<String, Object> ev : m.evidenceLog.metas()) {
            Object s = ev.get("status");
            by[s instanceof Number n ? Math.min(5, n.intValue() / 100) : 0]++;
        }
        Widgets.Bar bar = new Widgets.Bar();
        bar.set(List.of(new Widgets.Bar.Seg("2xx", by[2], Theme.GREEN), new Widgets.Bar.Seg("3xx", by[3], Theme.BLUE),
                new Widgets.Bar.Seg("4xx", by[4], Theme.AMBER), new Widgets.Bar.Seg("5xx", by[5], Theme.RED),
                new Widgets.Bar.Seg("none", by[0] + by[1], Theme.GRAY)));
        card.add(bar, BorderLayout.CENTER);
        return card;
    }

    @SuppressWarnings("unchecked")
    private JComponent stack(Model m) {
        Widgets.Card card = new Widgets.Card(12);
        card.add(Widgets.heading("Technology stack"), BorderLayout.NORTH);
        // two columns of categories when the pane is wide, so the card does not leave half its width empty
        JPanel list = new JPanel(new GridLayout(0, columns >= 6 ? 2 : 1, 12, 0));
        list.setOpaque(false);
        Map<String, List<Map<String, Object>>> byCat = new LinkedHashMap<>();
        for (String cat : Stack.categories()) {
            byCat.put(cat, new ArrayList<>());
        }
        for (Map<String, Object> t : m.stack) {
            byCat.computeIfAbsent(String.valueOf(t.get("category")), k -> new ArrayList<>()).add(t);
        }
        byCat.forEach((cat, items) -> {
            if (items.isEmpty()) {
                return;
            }
            JPanel line = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
            line.setOpaque(false);
            JLabel l = Widgets.muted(cat.toUpperCase());
            l.setPreferredSize(new Dimension(Math.round(150 * Theme.uiScale()), l.getPreferredSize().height + 6));
            line.add(l);
            for (Map<String, Object> t : items) {
                String v = String.valueOf(t.get("version"));
                line.add(new Widgets.Chip(t.get("name") + (v.isEmpty() ? "" : " " + v), catColor(cat)));
            }
            line.setAlignmentX(Component.LEFT_ALIGNMENT);
            list.add(line);
        });
        card.add(list, BorderLayout.CENTER);
        card.add(Widgets.muted("Hints from headers, cookies, pages and the hosts the app talks to; not a version scan."), BorderLayout.SOUTH);
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        return card;
    }

    private static Color catColor(String cat) {
        return switch (cat) {
            case "Edge & CDN" -> Theme.ACCENT;
            case "Web server" -> Theme.GREEN;
            case "Language & framework" -> Theme.BLUE;
            case "Frontend" -> Theme.PURPLE;
            case "CMS & platform" -> Theme.AMBER;
            default -> Theme.GRAY;
        };
    }

    private JComponent leadsCard(List<Analysis.Lead> leads) {
        Widgets.Card card = new Widgets.Card(12);
        card.add(Widgets.heading("Check these first  ·  " + leads.size() + " leads to verify, never findings"), BorderLayout.NORTH);
        JPanel list = new JPanel();
        list.setOpaque(false);
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        int n = 0;
        for (Analysis.Lead l : leads) {
            if (n++ == 6) {
                break;
            }
            list.add(leadRow(n, l));
        }
        if (leads.isEmpty()) {
            list.add(Widgets.muted("Nothing stands out yet. Send more requests."));
        }
        card.add(list, BorderLayout.CENTER);
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        return card;
    }

    private JComponent leadRow(int n, Analysis.Lead l) {
        boolean[] hover = {false};
        JPanel row = new JPanel(new BorderLayout(10, 0)) {
            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                Theme.quality(g);
                if (hover[0]) {
                    g.setColor(Theme.surface2());
                    g.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                }
                g.setColor(Theme.severity(l.sev()));
                g.fillRoundRect(0, 4, 3, getHeight() - 8, 3, 3);
                g.dispose();
                super.paintComponent(g0);
            }
        };
        row.setOpaque(false);
        row.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 6));
        JLabel rank = new JLabel(String.valueOf(n));
        rank.setFont(Theme.font(12f, Font.BOLD));
        rank.setForeground(Theme.severity(l.sev()));
        rank.setPreferredSize(new Dimension(Math.round(18 * Theme.uiScale()), rank.getPreferredSize().height + 4));
        JPanel text = new JPanel(new GridLayout(2, 1));
        text.setOpaque(false);
        String label = l.endpoint().label;
        JLabel path = new JLabel(label.startsWith("* ") ? "any " + label.substring(2) : label);
        path.setFont(Theme.mono(13f));
        JLabel why = new JLabel(l.signals().get(0).title() + (l.signals().size() > 1 ? "   +" + (l.signals().size() - 1) + " more" : "")
                + "   ·   next: " + l.signals().get(0).next());
        why.setFont(Theme.font(11f, Font.PLAIN));
        why.setForeground(Theme.MUTED);
        text.add(path);
        text.add(why);
        row.add(rank, BorderLayout.WEST);
        row.add(text, BorderLayout.CENTER);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, Math.round(52 * Theme.uiScale())));
        row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        row.setToolTipText("Open this lead in To check");
        // the whole row opens the lead (keyboard too: Tab to it, Enter); it lights up under the pointer
        row.setFocusable(true);
        row.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                onLead.accept(l);
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                hover[0] = true;
                row.repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hover[0] = false;
                row.repaint();
            }
        });
        row.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(java.awt.event.KeyEvent e) {
                if (e.getKeyCode() == java.awt.event.KeyEvent.VK_ENTER || e.getKeyCode() == java.awt.event.KeyEvent.VK_SPACE) {
                    onLead.accept(l);
                }
            }
        });
        row.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                hover[0] = true;
                row.repaint();
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                hover[0] = false;
                row.repaint();
            }
        });
        return row;
    }

    /** Cookie and credential facts at a glance. */
    private JComponent hygiene(Model m) {
        Widgets.Card card = new Widgets.Card(12);
        card.add(Widgets.heading("Cookies and credentials"), BorderLayout.NORTH);
        int cookies = 0;
        int noHttpOnly = 0;
        int noSecure = 0;
        Map<String, Integer> auth = new TreeMap<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("cookie")) {
                cookies++;
                if (!Boolean.TRUE.equals(n.attrs.get("httponly"))) {
                    noHttpOnly++;
                }
                if (!Boolean.TRUE.equals(n.attrs.get("secure"))) {
                    noSecure++;
                }
            } else if (n.type.equals("auth")) {
                auth.merge(n.label, 1, Integer::sum);
            }
        }
        JPanel chips = Widgets.flow(6);
        chips.add(new Widgets.Chip(cookies + " cookies", Theme.GRAY));
        chips.add(new Widgets.Chip(noHttpOnly + " without HttpOnly", noHttpOnly > 0 ? Theme.AMBER : Theme.GREEN));
        chips.add(new Widgets.Chip(noSecure + " without Secure", noSecure > 0 ? Theme.AMBER : Theme.GREEN));
        for (String a : auth.keySet()) {
            chips.add(new Widgets.Chip(a, Theme.BLUE));
        }
        if (m.roles.isEmpty()) {
            chips.add(new Widgets.Chip("no roles tagged", Theme.GRAY));
        } else {
            for (String r : m.roles) {
                chips.add(new Widgets.Chip("role: " + r, Theme.PURPLE));
            }
        }
        card.add(chips, BorderLayout.CENTER);
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        return card;
    }

    private void empty() {
        JPanel box = new JPanel();
        box.setOpaque(false);
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        JLabel t = new JLabel("Build a model of the app from your Burp traffic");
        t.setFont(Theme.font(20f, Font.BOLD));
        t.setAlignmentX(Component.LEFT_ALIGNMENT);
        JTextArea how = new JTextArea("""
                1.  In Proxy history or Site map, select requests.
                2.  Right-click, then Send to burp2model.
                3.  This tab fills in: the surface, the leads to check first, every request behind every claim.

                Everything happens inside Burp. Values (cookies, tokens, keys, personal data) are masked before anything is stored,
                and every line cites the request that shows it. This is a model builder, not a scanner.""");
        how.setEditable(false);
        how.setOpaque(false);
        how.setFont(Theme.font(13f, Font.PLAIN));
        how.setAlignmentX(Component.LEFT_ALIGNMENT);
        box.add(t);
        box.add(Box.createVerticalStrut(12));
        box.add(how);
        box.add(Box.createVerticalStrut(14));
        JButton welcome = new JButton("Show the welcome page");
        welcome.setAlignmentX(Component.LEFT_ALIGNMENT);
        welcome.addActionListener(e -> onWelcome.run());
        box.add(welcome);
        Widgets.Card card = new Widgets.Card(22);
        card.add(box, BorderLayout.CENTER);
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setMaximumSize(new Dimension(Math.round(760 * Theme.uiScale()), Math.round(290 * Theme.uiScale())));
        content.add(card);
        content.revalidate();
        content.repaint();
    }
}
