package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.Timer;

/** The map: the model as a network. Force-directed, zoomable, draggable; solid lines were seen in traffic, dashed ones found in code. */
final class GraphPanel extends JPanel {
    private static final class V {
        final Model.Node node;
        double x;
        double y;
        double vx;
        double vy;
        int degree;
        boolean pinned;
        double r;
        final List<V> nbrs = new ArrayList<>();

        V(Model.Node n) {
            this.node = n;
        }
    }

    private record E(V a, V b, String state, String type) {}

    private static final String[][] GROUPS = {
        {"Hosts", "host"}, {"Pages", "route"}, {"Scripts", "script"}, {"Endpoints", "endpoint,operation"}, {"Parameters", "parameter"},
        {"Third parties", "third_party"}, {"Trust", "cookie,auth,role"}, {"Tech", "tech"}};

    private final Canvas canvas = new Canvas();
    private final Map<String, JCheckBox> toggles = new LinkedHashMap<>();
    private final JTextField search = new JTextField(16);
    private final JLabel info = new JLabel(" ");
    private Model model;
    private final List<V> vs = new ArrayList<>();
    private final List<E> es = new ArrayList<>();
    private final Map<String, V> byId = new HashMap<>();
    private V selected;
    private V hover;
    private V focus;
    private Consumer<Model.Node> onSelect = n -> { };
    private final Timer sim;
    private int steps;
    private double scale = 1;
    private double ox;
    private double oy;
    private boolean fitted;

    GraphPanel() {
        super(new BorderLayout());
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        for (String[] g : GROUPS) {
            JCheckBox c = new JCheckBox(g[0], !g[0].equals("Parameters") && !g[0].equals("Tech"));
            c.setFocusable(false);
            c.addActionListener(e -> rebuild());
            toggles.put(g[1], c);
            bar.add(c);
        }
        bar.add(new JLabel("Find"));
        bar.add(search);
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                find();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                find();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                find();
            }
        });
        javax.swing.JButton fit = new javax.swing.JButton("Fit");
        fit.setFocusable(false);
        fit.addActionListener(e -> fit());
        javax.swing.JButton relayout = new javax.swing.JButton("Re-layout");
        relayout.setFocusable(false);
        relayout.addActionListener(e -> {
            for (V v : vs) {
                v.pinned = false;
            }
            seed();
            start();
        });
        bar.add(fit);
        bar.add(relayout);
        info.setForeground(Theme.muted());
        info.setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
        add(bar, BorderLayout.NORTH);
        add(canvas, BorderLayout.CENTER);
        add(info, BorderLayout.SOUTH);
        sim = new Timer(16, e -> tick());
    }

    void onSelect(Consumer<Model.Node> c) {
        onSelect = c;
    }

    void setModel(Model m) {
        this.model = m;
        selected = null;
        focus = null;
        fitted = false;
        rebuild();
    }

    // ------------------------------------------------------------------ data

    private void rebuild() {
        vs.clear();
        es.clear();
        byId.clear();
        if (model == null) {
            canvas.repaint();
            return;
        }
        Set<String> types = new HashSet<>();
        toggles.forEach((k, c) -> {
            if (c.isSelected()) {
                for (String t : k.split(",")) {
                    types.add(t);
                }
            }
        });
        for (Model.Node n : model.nodes.values()) {
            if (types.contains(n.type)) {
                V v = new V(n);
                vs.add(v);
                byId.put(n.id, v);
            }
        }
        for (Model.Edge e : model.edges) {
            V a = byId.get(e.src);
            V b = byId.get(e.dst);
            if (a != null && b != null) {
                es.add(new E(a, b, e.state, e.type));
                a.degree++;
                b.degree++;
                a.nbrs.add(b);
                b.nbrs.add(a);
            }
        }
        for (V v : vs) {
            v.r = 4 + Math.min(11, Math.sqrt(v.degree) * 1.7);
        }
        seed();
        settle(220);
        info.setText(vs.size() + " nodes · " + es.size() + " edges   ·   solid: seen in traffic · dashed: found in code   ·   scroll to zoom · drag to pan · double-click to focus");
        start();
    }

    private void seed() {
        int n = Math.max(1, vs.size());
        double rad = 60 + 9 * Math.sqrt(n) * 4;
        int i = 0;
        for (V v : vs) {
            double layerR = rad * (0.35 + 0.13 * v.node.layer);
            double a = (i++ * 2.399963) % (Math.PI * 2);            // the golden angle spreads nodes evenly
            v.x = Math.cos(a) * layerR + (Math.random() - 0.5) * 8;
            v.y = Math.sin(a) * layerR + (Math.random() - 0.5) * 8;
            v.vx = 0;
            v.vy = 0;
        }
        steps = 0;
        fitted = false;
    }

    /** Run the layout this many steps right away, so the map appears already arranged. */
    private void settle(int n) {
        for (int i = 0; i < n && !vs.isEmpty(); i++) {
            step(Math.max(0.05, 1.0 - steps / 420.0));
            steps++;
        }
    }

    private void start() {
        steps = 0;
        if (!sim.isRunning()) {
            sim.start();
        }
    }

    // ------------------------------------------------------------------ layout

    private void tick() {
        if (vs.isEmpty() || steps > 420) {
            sim.stop();
            if (!fitted) {
                fit();
            }
            return;
        }
        step(Math.max(0.05, 1.0 - steps / 420.0));
        steps++;
        if (steps == 120 && !fitted) {
            fit();
        }
        canvas.repaint();
    }

    private void step(double temp) {
        double cell = 70;
        Map<Long, List<V>> grid = new HashMap<>();
        for (V v : vs) {
            grid.computeIfAbsent(key((int) Math.floor(v.x / cell), (int) Math.floor(v.y / cell)), k -> new ArrayList<>()).add(v);
        }
        for (V v : vs) {
            double fx = 0;
            double fy = 0;
            int cx = (int) Math.floor(v.x / cell);
            int cy = (int) Math.floor(v.y / cell);
            for (int dx = -1; dx <= 1; dx++) {
                for (int dy = -1; dy <= 1; dy++) {
                    List<V> bucket = grid.get(key(cx + dx, cy + dy));
                    if (bucket == null) {
                        continue;
                    }
                    for (V u : bucket) {
                        if (u == v) {
                            continue;
                        }
                        double ddx = v.x - u.x;
                        double ddy = v.y - u.y;
                        double d2 = ddx * ddx + ddy * ddy + 0.01;
                        if (d2 > cell * cell) {
                            continue;
                        }
                        double f = 900.0 / d2;
                        double d = Math.sqrt(d2);
                        fx += ddx / d * f;
                        fy += ddy / d * f;
                    }
                }
            }
            v.vx += fx;
            v.vy += fy;
        }
        for (E e : es) {
            double dx = e.b.x - e.a.x;
            double dy = e.b.y - e.a.y;
            double d = Math.sqrt(dx * dx + dy * dy) + 0.01;
            double want = 38 + e.a.r + e.b.r;
            double f = (d - want) * 0.045;
            double fx = dx / d * f;
            double fy = dy / d * f;
            e.a.vx += fx;
            e.a.vy += fy;
            e.b.vx -= fx;
            e.b.vy -= fy;
        }
        for (V v : vs) {
            v.vx -= v.x * 0.004;                // a light pull to the centre keeps islands together
            v.vy -= v.y * 0.004;
            if (v.pinned) {
                v.vx = 0;
                v.vy = 0;
                continue;
            }
            double sp = Math.sqrt(v.vx * v.vx + v.vy * v.vy);
            double max = 18 * temp + 1;
            if (sp > max) {
                v.vx = v.vx / sp * max;
                v.vy = v.vy / sp * max;
            }
            if (Double.isNaN(v.x) || Double.isInfinite(v.x) || Double.isNaN(v.y) || Double.isInfinite(v.y)) {
                v.x = 0;
                v.y = 0;
            }
            v.x += v.vx;
            v.y += v.vy;
            v.vx *= 0.62;
            v.vy *= 0.62;
        }
    }

    private static long key(int x, int y) {
        return ((long) x << 32) ^ (y & 0xffffffffL);
    }

    void fit() {
        if (vs.isEmpty() || canvas.getWidth() < 10) {
            return;
        }
        double minX = Double.MAX_VALUE;
        double minY = Double.MAX_VALUE;
        double maxX = -Double.MAX_VALUE;
        double maxY = -Double.MAX_VALUE;
        for (V v : vs) {
            minX = Math.min(minX, v.x);
            maxX = Math.max(maxX, v.x);
            minY = Math.min(minY, v.y);
            maxY = Math.max(maxY, v.y);
        }
        double w = Math.max(1, maxX - minX) + 80;
        double h = Math.max(1, maxY - minY) + 80;
        scale = Math.min(2.2, Math.min(canvas.getWidth() / w, canvas.getHeight() / h));
        ox = canvas.getWidth() / 2.0 - (minX + maxX) / 2 * scale;
        oy = canvas.getHeight() / 2.0 - (minY + maxY) / 2 * scale;
        fitted = true;
        canvas.repaint();
    }

    private void find() {
        String q = search.getText().strip().toLowerCase();
        V hit = null;
        if (!q.isEmpty()) {
            for (V v : vs) {
                if (v.node.label.toLowerCase().contains(q)) {
                    hit = v;
                    break;
                }
            }
        }
        if (hit != null) {
            select(hit);
            ox = canvas.getWidth() / 2.0 - hit.x * scale;
            oy = canvas.getHeight() / 2.0 - hit.y * scale;
        }
        canvas.repaint();
    }

    private void select(V v) {
        selected = v;
        if (v != null) {
            onSelect.accept(v.node);
        }
        canvas.repaint();
    }

    /** Select a node by id (from another tab). */
    void showNode(String id) {
        V v = byId.get(id);
        if (v != null) {
            selected = v;
            ox = canvas.getWidth() / 2.0 - v.x * scale;
            oy = canvas.getHeight() / 2.0 - v.y * scale;
            canvas.repaint();
        }
    }

    // ------------------------------------------------------------------ drawing and input

    private final class Canvas extends JComponent {
        private V dragging;
        private Point2D last;
        private boolean moved;

        Canvas() {
            setOpaque(true);
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    dragging = pick(e.getPoint());
                    last = e.getPoint();
                    moved = false;
                    if (dragging != null) {
                        dragging.pinned = true;
                    }
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    double dx = e.getX() - last.getX();
                    double dy = e.getY() - last.getY();
                    moved = moved || Math.abs(dx) + Math.abs(dy) > 2;
                    if (dragging != null) {
                        dragging.x += dx / scale;
                        dragging.y += dy / scale;
                        if (!sim.isRunning()) {
                            start();
                        }
                    } else {
                        ox += dx;
                        oy += dy;
                    }
                    last = e.getPoint();
                    repaint();
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (dragging != null && !moved) {
                        dragging.pinned = false;
                    }
                    if (!moved) {
                        select(pick(e.getPoint()));
                    }
                    dragging = null;
                }

                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        V v = pick(e.getPoint());
                        focus = v == focus ? null : v;
                        repaint();
                    }
                }

                @Override
                public void mouseMoved(MouseEvent e) {
                    V h = pick(e.getPoint());
                    if (h != hover) {
                        hover = h;
                        setCursor(Cursor.getPredefinedCursor(h == null ? Cursor.DEFAULT_CURSOR : Cursor.HAND_CURSOR));
                        repaint();
                    }
                }

                @Override
                public void mouseWheelMoved(MouseWheelEvent e) {
                    double f = e.getPreciseWheelRotation() < 0 ? 1.15 : 1 / 1.15;
                    double ns = Math.max(0.1, Math.min(5, scale * f));
                    ox = e.getX() - (e.getX() - ox) * ns / scale;
                    oy = e.getY() - (e.getY() - oy) * ns / scale;
                    scale = ns;
                    repaint();
                }
            };
            addMouseListener(ma);
            addMouseMotionListener(ma);
            addMouseWheelListener(ma);
        }

        private V pick(java.awt.Point p) {
            double x = (p.x - ox) / scale;
            double y = (p.y - oy) / scale;
            V best = null;
            double bd = 1e18;
            for (V v : vs) {
                if (focus != null && !visible(v)) {
                    continue;
                }
                double d = (v.x - x) * (v.x - x) + (v.y - y) * (v.y - y);
                double r = Math.max(v.r, 7 / scale);
                if (d <= r * r && d < bd) {
                    bd = d;
                    best = v;
                }
            }
            return best;
        }

        @Override
        protected void paintComponent(Graphics g0) {
            if (!fitted && getWidth() > 10 && !vs.isEmpty()) {
                fit();
            }
            Graphics2D g = (Graphics2D) g0.create();
            Theme.quality(g);
            g.setColor(Theme.dark() ? Theme.shift(Theme.bg(), -6) : Theme.surface());
            g.fillRect(0, 0, getWidth(), getHeight());
            if (vs.isEmpty()) {
                g.setColor(Theme.muted());
                g.setFont(Theme.font(13f, Font.PLAIN));
                g.drawString(model == null ? "Send some requests and the map appears here." : "Nothing to show: turn on a group above.", 24, 36);
                g.dispose();
                return;
            }
            AffineTransform base = g.getTransform();
            g.translate(ox, oy);
            g.scale(scale, scale);
            Set<V> lit = new HashSet<>();
            if (selected != null) {
                lit.add(selected);
                lit.addAll(selected.nbrs);
            }
            String q = search.getText().strip().toLowerCase();
            for (E e : es) {
                if (focus != null && !(visible(e.a) && visible(e.b))) {
                    continue;
                }
                boolean on = selected != null && (e.a == selected || e.b == selected);
                Color c = on ? Theme.ACCENT : Theme.alpha(Theme.fg(), selected != null ? 28 : 55);
                g.setColor(c);
                float w = (float) ((on ? 1.8 : 1.0) / Math.sqrt(scale));
                g.setStroke(switch (e.state) {
                    case "INFERRED" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {6f, 5f}, 0f);
                    case "EXTERNAL" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {1.5f, 4f}, 0f);
                    default -> new BasicStroke(w);
                });
                g.drawLine((int) e.a.x, (int) e.a.y, (int) e.b.x, (int) e.b.y);
            }
            g.setStroke(new BasicStroke(1f));
            g.setFont(Theme.font((float) Math.max(9, 11 / Math.sqrt(scale)), Font.PLAIN));
            FontMetrics fm = g.getFontMetrics();
            List<V> labelled = new ArrayList<>();
            for (V v : vs) {
                if (focus != null && !visible(v)) {
                    continue;
                }
                boolean dim = selected != null && !lit.contains(v);
                boolean match = !q.isEmpty() && v.node.label.toLowerCase().contains(q);
                Color c = Theme.type(v.node.type);
                g.setColor(dim ? Theme.alpha(c, 70) : c);
                g.fillOval((int) (v.x - v.r), (int) (v.y - v.r), (int) (v.r * 2), (int) (v.r * 2));
                if ("STATIC_ONLY".equals(v.node.attrs.get("api_state"))) {
                    g.setColor(Theme.ACCENT);
                    g.setStroke(new BasicStroke((float) (1.6 / Math.sqrt(scale)), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {3f, 2f}, 0f));
                    g.drawOval((int) (v.x - v.r - 2), (int) (v.y - v.r - 2), (int) (v.r * 2 + 4), (int) (v.r * 2 + 4));
                    g.setStroke(new BasicStroke(1f));
                }
                if (v == selected || v == hover || match) {
                    g.setColor(Theme.fg());
                    g.setStroke(new BasicStroke((float) (2 / Math.sqrt(scale))));
                    g.drawOval((int) (v.x - v.r - 2), (int) (v.y - v.r - 2), (int) (v.r * 2 + 4), (int) (v.r * 2 + 4));
                    g.setStroke(new BasicStroke(1f));
                }
                if (v == selected || v == hover || match || (v.degree >= 6 && scale > 0.5) || (lit.contains(v) && selected != null && scale > 0.5)) {
                    labelled.add(v);
                }
            }
            for (V v : labelled) {
                String t = v.node.label.length() > 46 ? v.node.label.substring(0, 45) + "…" : v.node.label;
                int tw = fm.stringWidth(t);
                int lx = (int) (v.x + v.r + 4);
                int ly = (int) (v.y + fm.getAscent() / 2.0 - 1);
                g.setColor(Theme.alpha(Theme.dark() ? Theme.shift(Theme.bg(), -6) : Theme.surface(), 200));
                g.fillRoundRect(lx - 3, ly - fm.getAscent(), tw + 6, fm.getHeight(), 6, 6);
                g.setColor(Theme.fg());
                g.drawString(t, lx, ly);
            }
            g.setTransform(base);
            legend(g);
            g.dispose();
        }

        private void legend(Graphics2D g) {
            String[][] items = {{"host", "host"}, {"route", "page"}, {"script", "script"}, {"endpoint", "endpoint"}, {"third_party", "third party"}, {"cookie", "trust"}, {"tech", "tech"}};
            int x = 12;
            int y = getHeight() - 14;
            g.setFont(Theme.font(11f, Font.PLAIN));
            for (String[] it : items) {
                g.setColor(Theme.type(it[0]));
                g.fillOval(x, y - 8, 9, 9);
                g.setColor(Theme.muted());
                g.drawString(it[1], x + 13, y);
                x += 22 + g.getFontMetrics().stringWidth(it[1]);
            }
        }
    }

    private boolean visible(V v) {
        return focus == null || v == focus || focus.nbrs.contains(v);
    }
}
