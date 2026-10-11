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
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.geom.AffineTransform;
import java.awt.geom.CubicCurve2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ButtonGroup;
import javax.swing.Timer;

/**
 * The map: the model as a network you can read. Two layouts (a force-directed network and a left-to-right flow),
 * both deterministic, so the same model always draws the same way; adding requests keeps what was already placed.
 * Solid lines were seen in traffic, dashed ones found in code.
 */
final class GraphPanel extends JPanel {
    private static final class V {
        final Model.Node node;
        double x;
        double y;
        double vx;
        double vy;
        double r = 5;
        int degree;
        boolean pinned;
        boolean hidden;
        /** Placed by an earlier layout: it moves less, so a growing map keeps its shape. */
        boolean settled;
        final List<V> nbrs = new ArrayList<>();
        final List<E> edges = new ArrayList<>();
        Color color;
        String shortLabel;

        V(Model.Node n) {
            this.node = n;
            this.color = Theme.type(n.type);
            String l = n.label;
            this.shortLabel = l.length() > 44 ? l.substring(0, 43) + "…" : l;
        }
    }

    private record E(V a, V b, String state, String type) {}

    private static final String[][] GROUPS = {
        {"Hosts", "host"}, {"Pages", "route"}, {"Scripts", "script"}, {"Endpoints", "endpoint,operation"}, {"Parameters", "parameter"},
        {"Third parties", "third_party"}, {"Trust", "cookie,auth,role"}, {"Tech", "tech"}};
    private static final int BIG = 1500;

    private final Canvas canvas = new Canvas();
    private final Map<String, JCheckBox> toggles = new LinkedHashMap<>();
    private final JTextField search = new JTextField(14);
    private final JLabel info = new JLabel(" ");
    private final JToggleButton networkBtn = new JToggleButton("Network", true);
    private final JToggleButton flowBtn = new JToggleButton("Flow");
    private final JCheckBox codeOnly = new JCheckBox("Only code-named");
    private final JCheckBox labelsBox = new JCheckBox("Labels", true);
    private Model model;
    private final List<V> vs = new ArrayList<>();
    private final List<E> es = new ArrayList<>();
    private final Map<String, V> byId = new HashMap<>();
    /** Where each node was last drawn, kept across rebuilds so a growing model does not scramble. */
    private final Map<String, double[]> memory = new HashMap<>();
    private final Set<String> hiddenTypes = new HashSet<>();
    private V selected;
    private V hover;
    private V focus;
    private Point mouse = new Point();
    private Consumer<Model.Node> onSelect = n -> { };
    private Consumer<Model.Node> onOpen = n -> { };
    private final Timer sim;
    private final Timer anim;
    private int steps;
    private int maxSteps = 320;
    private double scale = 1;
    private double ox;
    private double oy;
    private boolean fitted;
    private boolean flow;
    private List<V> matches = new ArrayList<>();
    private int matchAt = -1;
    // animated view
    private double tScale;
    private double tox;
    private double toy;
    private long animStart;
    private double fScale;
    private double fox;
    private double foy;

    GraphPanel() {
        super(new BorderLayout());
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        for (String[] g : GROUPS) {
            JCheckBox c = new JCheckBox(g[0], !g[0].equals("Parameters") && !g[0].equals("Tech"));
            c.setFocusable(false);
            c.setFont(Theme.font(11f, Font.PLAIN));
            c.addActionListener(e -> rebuild(false));
            toggles.put(g[1], c);
            bar.add(c);
        }
        codeOnly.setFocusable(false);
        codeOnly.setFont(Theme.font(11f, Font.PLAIN));
        codeOnly.setToolTipText("Show only endpoints the code names but nothing called, with what names them");
        codeOnly.addActionListener(e -> rebuild(false));
        labelsBox.setFocusable(false);
        labelsBox.setFont(Theme.font(11f, Font.PLAIN));
        labelsBox.addActionListener(e -> canvas.repaint());
        bar.add(codeOnly);
        bar.add(labelsBox);
        ButtonGroup bg = new ButtonGroup();
        bg.add(networkBtn);
        bg.add(flowBtn);
        for (JToggleButton b : new JToggleButton[] {networkBtn, flowBtn}) {
            b.setFocusable(false);
            b.setFont(Theme.font(11f, Font.PLAIN));
            b.setMargin(new java.awt.Insets(1, 8, 1, 8));
            bar.add(b);
        }
        networkBtn.setToolTipText("Force-directed: connected things sit near each other");
        flowBtn.setToolTipText("Left to right: host, pages, scripts, endpoints, then the rest");
        networkBtn.addActionListener(e -> setFlow(false));
        flowBtn.addActionListener(e -> setFlow(true));
        search.setToolTipText("Find a node (Enter for the next match)");
        search.putClientProperty("JTextField.placeholderText", "Find…");
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                find(true);
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                find(true);
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                find(true);
            }
        });
        search.addActionListener(e -> find(false));
        bar.add(search);
        bar.add(button("Fit", "Fit everything on screen (F)", this::fitAnimated));
        bar.add(button("Re-layout", "Forget positions and lay the map out again", () -> {
            memory.clear();
            rebuild(true);
        }));
        bar.add(button("PNG", "Save the map as an image", this::savePng));
        info.setForeground(Theme.muted());
        info.setFont(Theme.font(11f, Font.PLAIN));
        info.setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
        bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.line()));
        add(bar, BorderLayout.NORTH);
        add(canvas, BorderLayout.CENTER);
        add(info, BorderLayout.SOUTH);
        sim = new Timer(16, e -> tick());
        anim = new Timer(14, e -> animTick());
    }

    private static JButton button(String text, String tip, Runnable r) {
        JButton b = new JButton(text);
        b.setFocusable(false);
        b.setFont(Theme.font(11f, Font.PLAIN));
        b.setMargin(new java.awt.Insets(1, 8, 1, 8));
        b.setToolTipText(tip);
        b.addActionListener(e -> r.run());
        return b;
    }

    void onSelect(Consumer<Model.Node> c) {
        onSelect = c;
    }

    /** Called when the user asks to see a node in the Surface tab. */
    void onOpen(Consumer<Model.Node> c) {
        onOpen = c;
    }

    void setModel(Model m) {
        boolean first = model == null;
        this.model = m;
        selected = null;
        focus = null;
        if (m == null) {
            memory.clear();
        }
        rebuild(first);
    }

    private void setFlow(boolean f) {
        if (flow == f) {
            return;
        }
        flow = f;
        memory.clear();
        rebuild(true);
    }

    // ------------------------------------------------------------------ data

    private void rebuild(boolean refit) {
        sim.stop();
        vs.clear();
        es.clear();
        byId.clear();
        matches = new ArrayList<>();
        matchAt = -1;
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
        types.removeAll(hiddenTypes);
        boolean only = codeOnly.isSelected();
        Set<String> keep = null;
        if (only) {
            keep = new HashSet<>();
            for (Model.Node n : model.nodes.values()) {
                if ("STATIC_ONLY".equals(n.attrs.get("api_state"))) {
                    keep.add(n.id);
                }
            }
            for (Model.Edge e : model.edges) {
                if (keep.contains(e.dst) && e.type.equals("REFERENCES")) {
                    keep.add(e.src);
                }
            }
        }
        int cap = 0;
        for (Model.Node n : model.nodes.values()) {
            if (types.contains(n.type) && (keep == null || keep.contains(n.id))) {
                V v = new V(n);
                vs.add(v);
                byId.put(n.id, v);
                cap++;
            }
        }
        for (Model.Edge e : model.edges) {
            V a = byId.get(e.src);
            V b = byId.get(e.dst);
            if (a != null && b != null) {
                E ed = new E(a, b, e.state, e.type);
                es.add(ed);
                a.edges.add(ed);
                b.edges.add(ed);
                a.degree++;
                b.degree++;
                a.nbrs.add(b);
                b.nbrs.add(a);
            }
        }
        for (V v : vs) {
            v.r = 4 + Math.min(10, Math.sqrt(v.degree) * 1.6);
        }
        place();
        maxSteps = vs.size() > 900 ? 160 : 320;
        if (!flow) {
            relax(vs.size() > BIG ? 40 : 140, true);
        }
        info.setText(vs.size() + " nodes · " + es.size() + " edges   ·   solid: seen in traffic · dashed: found in code   ·   scroll to zoom · drag to pan or move · double-click to focus · right-click for more"
                + (cap > BIG ? "   ·   a large map: turn groups off to see less" : ""));
        if (refit || !fitted) {
            fitted = false;
        }
        if (!flow && !vs.isEmpty()) {
            steps = 140;
            sim.start();
        }
        canvas.repaint();
    }

    // ------------------------------------------------------------------ layout

    private static double rnd(String id, int salt) {
        long h = id.hashCode() * 0x9E3779B97F4A7C15L + salt * 0xBF58476D1CE4E5B9L;
        h ^= h >>> 29;
        h *= 0x94D049BB133111EBL;
        h ^= h >>> 32;
        return (h & 0xFFFFFFL) / (double) 0x1000000L;
    }

    private void place() {
        if (flow) {
            layoutFlow();
            return;
        }
        int n = Math.max(1, vs.size());
        double rad = 90 + 11 * Math.sqrt(n) * 3;
        List<V> fresh = new ArrayList<>();
        for (V v : vs) {
            double[] p = memory.get(v.node.id);
            if (p != null) {
                v.x = p[0];
                v.y = p[1];
                v.settled = true;
                v.pinned = p.length > 2 && p[2] == 1;
            } else {
                fresh.add(v);
            }
        }
        // new nodes start beside the neighbours that are already placed, or on a ring by layer when there are none
        for (V v : fresh) {
            double sx = 0;
            double sy = 0;
            int c = 0;
            for (V nb : v.nbrs) {
                if (memory.containsKey(nb.node.id)) {
                    sx += nb.x;
                    sy += nb.y;
                    c++;
                }
            }
            double a = rnd(v.node.id, 1) * Math.PI * 2;
            if (c > 0) {
                v.x = sx / c + Math.cos(a) * 40;
                v.y = sy / c + Math.sin(a) * 40;
            } else {
                double layerR = rad * (0.30 + 0.14 * v.node.layer);
                v.x = Math.cos(a) * layerR;
                v.y = Math.sin(a) * layerR;
            }
        }
        if (fresh.size() == vs.size()) {
            steps = 0;
        }
    }

    private static int column(Model.Node n) {
        return switch (n.type) {
            case "host", "tech" -> 0;
            case "route" -> 1;
            case "script" -> 2;
            case "endpoint", "operation" -> 3;
            case "parameter" -> 4;
            default -> 5;
        };
    }

    /** Left to right: host, pages, scripts, endpoints, parameters, then third parties and trust. Rows are ordered to keep lines short. */
    private void layoutFlow() {
        List<List<V>> cols = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            cols.add(new ArrayList<>());
        }
        for (V v : vs) {
            cols.get(column(v.node)).add(v);
        }
        for (List<V> c : cols) {
            c.sort(Comparator.comparing((V v) -> v.node.type).thenComparing(v -> v.node.label));
        }
        Map<V, Double> row = new HashMap<>();
        for (List<V> c : cols) {
            for (int i = 0; i < c.size(); i++) {
                row.put(c.get(i), (double) i);
            }
        }
        for (int pass = 0; pass < 4; pass++) {
            for (int ci = pass % 2 == 0 ? 1 : 4; pass % 2 == 0 ? ci < 6 : ci >= 0; ci += pass % 2 == 0 ? 1 : -1) {
                List<V> c = cols.get(ci);
                Map<V, Double> bary = new HashMap<>();
                for (V v : c) {
                    double sum = 0;
                    int cnt = 0;
                    for (V nb : v.nbrs) {
                        int nc = column(nb.node);
                        if (nc != ci && Math.abs(nc - ci) <= 2) {
                            sum += row.get(nb);
                            cnt++;
                        }
                    }
                    bary.put(v, cnt > 0 ? sum / cnt : row.get(v));
                }
                c.sort(Comparator.comparingDouble((V v) -> bary.get(v)).thenComparing(v -> v.node.label));
                for (int i = 0; i < c.size(); i++) {
                    row.put(c.get(i), (double) i);
                }
            }
        }
        // a tall column wraps into side-by-side stacks, so the whole map fits on screen at a size that can be read
        final int perStack = 28;
        double gap = 24;
        double x = 0;
        for (List<V> c : cols) {
            int stacks = Math.max(1, (c.size() + perStack - 1) / perStack);
            for (int i = 0; i < c.size(); i++) {
                V v = c.get(i);
                int sc = i / perStack;
                int inStack = Math.min(perStack, c.size() - sc * perStack);
                v.x = x + sc * 310;
                v.y = (i % perStack - (inStack - 1) / 2.0) * gap;
                v.pinned = false;
            }
            x += stacks * 310 + 70;
        }
        steps = maxSteps + 1;
    }

    private void remember() {
        for (V v : vs) {
            memory.put(v.node.id, new double[] {v.x, v.y, v.pinned ? 1 : 0});
        }
    }

    private void tick() {
        if (vs.isEmpty() || steps >= maxSteps) {
            sim.stop();
            remember();
            if (!fitted) {
                fitAnimated();
            }
            return;
        }
        step(Math.max(0.04, 1.0 - steps / (double) maxSteps) * 0.6);
        steps++;
        if (!fitted && steps % 40 == 0) {
            fit();
        }
        canvas.repaint();
    }

    /** Run this many layout steps right away, so the map is already arranged when first drawn. */
    private void relax(int n, boolean cool) {
        for (int i = 0; i < n && !vs.isEmpty(); i++) {
            step(cool ? Math.max(0.04, 1.0 - (steps + i) / (double) maxSteps) : 0.3);
        }
    }

    private void step(double temp) {
        double cell = 80;
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
                        double d2 = ddx * ddx + ddy * ddy;
                        if (d2 < 0.01) {
                            ddx = rnd(v.node.id, 7) - 0.5;
                            ddy = rnd(u.node.id, 9) - 0.5;
                            d2 = ddx * ddx + ddy * ddy + 0.01;
                        }
                        if (d2 > cell * cell) {
                            continue;
                        }
                        double d = Math.sqrt(d2);
                        double f = (1100.0 + 40 * (v.r + u.r)) / d2;
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
            double want = 42 + e.a.r + e.b.r;
            double k = e.state.equals("INFERRED") ? 0.035 : 0.06;
            double f = (d - want) * k;
            double fx = dx / d * f;
            double fy = dy / d * f;
            e.a.vx += fx;
            e.a.vy += fy;
            e.b.vx -= fx;
            e.b.vy -= fy;
        }
        for (V v : vs) {
            v.vx -= v.x * 0.006;
            v.vy -= v.y * 0.006;
            if (v.pinned) {
                v.vx = 0;
                v.vy = 0;
                continue;
            }
            double sp = Math.sqrt(v.vx * v.vx + v.vy * v.vy);
            double max = 22 * temp + 0.5;
            if (sp > max) {
                v.vx = v.vx / sp * max;
                v.vy = v.vy / sp * max;
            }
            double mobility = v.settled ? 0.3 : 1.0;
            v.x += v.vx * mobility;
            v.y += v.vy * mobility;
            v.vx *= 0.55;
            v.vy *= 0.55;
            if (Double.isNaN(v.x) || Double.isInfinite(v.x) || Double.isNaN(v.y) || Double.isInfinite(v.y)) {
                v.x = 0;
                v.y = 0;
            }
        }
    }

    private static long key(int x, int y) {
        return ((long) x << 32) ^ (y & 0xffffffffL);
    }

    // ------------------------------------------------------------------ view

    private double[] extent() {
        double minX = Double.MAX_VALUE;
        double minY = Double.MAX_VALUE;
        double maxX = -Double.MAX_VALUE;
        double maxY = -Double.MAX_VALUE;
        for (V v : vs) {
            if (focus != null && !visible(v)) {
                continue;
            }
            minX = Math.min(minX, v.x);
            maxX = Math.max(maxX, v.x);
            minY = Math.min(minY, v.y);
            maxY = Math.max(maxY, v.y);
        }
        return new double[] {minX, minY, maxX, maxY};
    }

    private double[] fitView() {
        double[] b = extent();
        double w = Math.max(1, b[2] - b[0]) + (flow ? 260 : 110);
        double h = Math.max(1, b[3] - b[1]) + 90;
        double s = Math.max(0.05, Math.min(flow ? 1.4 : 2.0, Math.min(canvas.getWidth() / w, canvas.getHeight() / h)));
        return new double[] {s, canvas.getWidth() / 2.0 - (b[0] + b[2]) / 2 * s, canvas.getHeight() / 2.0 - (b[1] + b[3]) / 2 * s};
    }

    void fit() {
        if (vs.isEmpty() || canvas.getWidth() < 10) {
            return;
        }
        double[] f = fitView();
        scale = f[0];
        ox = f[1];
        oy = f[2];
        fitted = true;
        canvas.repaint();
    }

    void fitAnimated() {
        if (vs.isEmpty() || canvas.getWidth() < 10) {
            return;
        }
        double[] f = fitView();
        animateTo(f[0], f[1], f[2]);
        fitted = true;
    }

    private void animateTo(double s, double x, double y) {
        fScale = scale;
        fox = ox;
        foy = oy;
        tScale = s;
        tox = x;
        toy = y;
        animStart = System.nanoTime();
        anim.start();
    }

    private void animTick() {
        double t = Math.min(1.0, (System.nanoTime() - animStart) / 240_000_000.0);
        double e = 1 - Math.pow(1 - t, 3);
        scale = fScale + (tScale - fScale) * e;
        ox = fox + (tox - fox) * e;
        oy = foy + (toy - foy) * e;
        canvas.repaint();
        if (t >= 1.0) {
            anim.stop();
        }
    }

    private void centerOn(V v) {
        double s = Math.max(scale, 0.9);
        animateTo(s, canvas.getWidth() / 2.0 - v.x * s, canvas.getHeight() / 2.0 - v.y * s);
    }

    // ------------------------------------------------------------------ search and selection

    private void find(boolean fromTyping) {
        String q = search.getText().strip().toLowerCase();
        if (fromTyping) {
            matches = new ArrayList<>();
            matchAt = -1;
            if (!q.isEmpty()) {
                for (V v : vs) {
                    if (v.node.label.toLowerCase().contains(q)) {
                        matches.add(v);
                    }
                }
                matches.sort(Comparator.comparingInt((V v) -> -v.degree));
            }
        }
        if (matches.isEmpty()) {
            canvas.repaint();
            return;
        }
        matchAt = (matchAt + 1) % matches.size();
        V hit = matches.get(matchAt);
        select(hit);
        centerOn(hit);
        info.setText("match " + (matchAt + 1) + " of " + matches.size() + " — Enter for the next");
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
            select(v);
            centerOn(v);
        }
    }

    private boolean visible(V v) {
        return focus == null || v == focus || focus.nbrs.contains(v);
    }

    private void savePng() {
        if (vs.isEmpty()) {
            return;
        }
        javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
        fc.setSelectedFile(new java.io.File("burp2model-map.png"));
        if (fc.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        BufferedImage img = new BufferedImage(Math.max(400, canvas.getWidth()), Math.max(300, canvas.getHeight()), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        canvas.paintAll(g);
        g.dispose();
        try {
            javax.imageio.ImageIO.write(img, "png", fc.getSelectedFile());
            info.setText("saved " + fc.getSelectedFile());
        } catch (Exception e) {
            info.setText("could not save: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ the canvas

    private final class Canvas extends JComponent {
        private V dragging;
        private Point last;
        private boolean moved;

        Canvas() {
            setOpaque(true);
            setFocusable(true);
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    requestFocusInWindow();
                    if (e.isPopupTrigger()) {
                        popup(e);
                        return;
                    }
                    anim.stop();
                    dragging = pick(e.getPoint());
                    last = e.getPoint();
                    moved = false;
                    if (dragging != null) {
                        dragging.pinned = true;
                    }
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    if (last == null) {
                        return;
                    }
                    double dx = e.getX() - last.getX();
                    double dy = e.getY() - last.getY();
                    moved = moved || Math.abs(dx) + Math.abs(dy) > 2;
                    if (dragging != null) {
                        dragging.x += dx / scale;
                        dragging.y += dy / scale;
                    } else {
                        ox += dx;
                        oy += dy;
                    }
                    last = e.getPoint();
                    repaint();
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        popup(e);
                        return;
                    }
                    if (dragging != null && moved) {
                        remember();
                    } else if (dragging != null) {
                        dragging.pinned = memory.containsKey(dragging.node.id) && memory.get(dragging.node.id).length > 2 && memory.get(dragging.node.id)[2] == 1;
                    }
                    if (!moved && e.getButton() == MouseEvent.BUTTON1) {
                        select(pick(e.getPoint()));
                    }
                    dragging = null;
                }

                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                        V v = pick(e.getPoint());
                        focus = v == null || v == focus ? null : v;
                        if (focus != null) {
                            select(focus);
                        }
                        fitAnimated();
                    }
                }

                @Override
                public void mouseMoved(MouseEvent e) {
                    mouse = e.getPoint();
                    V h = pick(e.getPoint());
                    if (h != hover) {
                        hover = h;
                        setCursor(Cursor.getPredefinedCursor(h == null ? Cursor.DEFAULT_CURSOR : Cursor.HAND_CURSOR));
                    }
                    repaint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hover = null;
                    repaint();
                }

                @Override
                public void mouseWheelMoved(MouseWheelEvent e) {
                    double f = Math.pow(1.18, -e.getPreciseWheelRotation());
                    double ns = Math.max(0.05, Math.min(6, scale * f));
                    ox = e.getX() - (e.getX() - ox) * ns / scale;
                    oy = e.getY() - (e.getY() - oy) * ns / scale;
                    scale = ns;
                    fitted = true;
                    repaint();
                }
            };
            addMouseListener(ma);
            addMouseMotionListener(ma);
            addMouseWheelListener(ma);
            addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    switch (e.getKeyCode()) {
                        case KeyEvent.VK_F -> fitAnimated();
                        case KeyEvent.VK_ESCAPE -> {
                            focus = null;
                            selected = null;
                            repaint();
                        }
                        case KeyEvent.VK_EQUALS, KeyEvent.VK_PLUS -> zoom(1.25);
                        case KeyEvent.VK_MINUS -> zoom(0.8);
                        case KeyEvent.VK_LEFT -> {
                            ox += 60;
                            repaint();
                        }
                        case KeyEvent.VK_RIGHT -> {
                            ox -= 60;
                            repaint();
                        }
                        case KeyEvent.VK_UP -> {
                            oy += 60;
                            repaint();
                        }
                        case KeyEvent.VK_DOWN -> {
                            oy -= 60;
                            repaint();
                        }
                        default -> {
                        }
                    }
                }
            });
        }

        private void zoom(double f) {
            double ns = Math.max(0.05, Math.min(6, scale * f));
            ox = getWidth() / 2.0 - (getWidth() / 2.0 - ox) * ns / scale;
            oy = getHeight() / 2.0 - (getHeight() / 2.0 - oy) * ns / scale;
            scale = ns;
            repaint();
        }

        private void popup(MouseEvent e) {
            V v = pick(e.getPoint());
            JPopupMenu m = new JPopupMenu();
            if (v != null) {
                select(v);
                m.add(item("Focus on this and its neighbours", () -> {
                    focus = v;
                    fitAnimated();
                }));
                m.add(item("Show it in Surface", () -> onOpen.accept(v.node)));
                m.add(item(v.pinned ? "Unpin" : "Pin here", () -> {
                    v.pinned = !v.pinned;
                    remember();
                    repaint();
                }));
                m.add(item("Hide this", () -> {
                    v.hidden = true;
                    repaint();
                }));
                m.add(item("Copy its name", () -> Tables.copy(v.node.label)));
            } else {
                m.add(item("Fit", GraphPanel.this::fitAnimated));
                m.add(item("Clear focus and hidden", () -> {
                    focus = null;
                    for (V x : vs) {
                        x.hidden = false;
                    }
                    repaint();
                }));
            }
            m.show(this, e.getX(), e.getY());
        }

        private JMenuItem item(String t, Runnable r) {
            JMenuItem i = new JMenuItem(t);
            i.addActionListener(e -> r.run());
            return i;
        }

        private V pick(Point p) {
            double x = (p.x - ox) / scale;
            double y = (p.y - oy) / scale;
            V best = null;
            double bd = 1e18;
            for (V v : vs) {
                if (v.hidden || (focus != null && !visible(v))) {
                    continue;
                }
                double d = (v.x - x) * (v.x - x) + (v.y - y) * (v.y - y);
                double r = Math.max(v.r + 2, 8 / scale);
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
            g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
            Color bg = Theme.dark() ? Theme.shift(Theme.bg(), -8) : Theme.surface();
            g.setColor(bg);
            g.fillRect(0, 0, getWidth(), getHeight());
            if (vs.isEmpty()) {
                g.setColor(Theme.muted());
                g.setFont(Theme.font(13f, Font.PLAIN));
                g.drawString(model == null ? "Send some requests and the map appears here." : "Nothing to show: turn a group on above.", 24, 36);
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
            } else if (hover != null) {
                lit.add(hover);
                lit.addAll(hover.nbrs);
            }
            boolean dimming = !lit.isEmpty();
            drawEdges(g, lit, dimming);
            drawNodes(g, lit, dimming);
            drawLabels(g, lit);
            g.setTransform(base);
            legend(g);
            minimap(g);
            tooltip(g);
            g.dispose();
        }

        private void drawEdges(Graphics2D g, Set<V> lit, boolean dimming) {
            double sw = 1.0 / Math.sqrt(scale);
            Color base = Theme.fg();
            Map<String, Path2D.Double> batches = new HashMap<>();
            List<E> hot = new ArrayList<>();
            for (E e : es) {
                if (e.a.hidden || e.b.hidden || (focus != null && !(visible(e.a) && visible(e.b)))) {
                    continue;
                }
                boolean on = selected != null ? (e.a == selected || e.b == selected) : hover != null && (e.a == hover || e.b == hover);
                if (on) {
                    hot.add(e);
                    continue;
                }
                if (scale < 0.25 && vs.size() > 400 && !e.state.equals("OBSERVED")) {
                    continue;
                }
                Path2D.Double p = batches.computeIfAbsent(e.state, k -> new Path2D.Double());
                addEdge(p, e);
            }
            int alpha = dimming ? 26 : (vs.size() > 600 ? 50 : 78);
            for (Map.Entry<String, Path2D.Double> b : batches.entrySet()) {
                g.setColor(Theme.alpha(base, alpha));
                g.setStroke(strokeFor(b.getKey(), (float) sw));
                g.draw(b.getValue());
            }
            g.setFont(Theme.font((float) Math.max(9, 10 / Math.sqrt(scale)), Font.PLAIN));
            for (E e : hot) {
                g.setColor(Theme.ACCENT);
                g.setStroke(strokeFor(e.state, (float) (sw * 2)));
                Path2D.Double p = new Path2D.Double();
                addEdge(p, e);
                g.draw(p);
                if (scale > 0.55 && hot.size() <= 10) {
                    double mx = (e.a.x + e.b.x) / 2;
                    double my = (e.a.y + e.b.y) / 2;
                    String t = e.type.toLowerCase().replace('_', ' ');
                    FontMetrics fm = g.getFontMetrics();
                    g.setColor(Theme.alpha(Theme.dark() ? Theme.shift(Theme.bg(), -8) : Theme.surface(), 220));
                    g.fillRoundRect((int) mx - fm.stringWidth(t) / 2 - 3, (int) my - fm.getAscent(), fm.stringWidth(t) + 6, fm.getHeight(), 6, 6);
                    g.setColor(Theme.ACCENT);
                    g.drawString(t, (int) mx - fm.stringWidth(t) / 2, (int) my);
                }
            }
            g.setStroke(new BasicStroke(1f));
        }

        private void addEdge(Path2D.Double p, E e) {
            if (flow) {
                double mx = (e.a.x + e.b.x) / 2;
                CubicCurve2D.Double c = new CubicCurve2D.Double(e.a.x, e.a.y, mx, e.a.y, mx, e.b.y, e.b.x, e.b.y);
                p.append(c, false);
            } else {
                p.append(new Line2D.Double(e.a.x, e.a.y, e.b.x, e.b.y), false);
            }
        }

        private BasicStroke strokeFor(String state, float w) {
            return switch (state) {
                case "INFERRED" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {6f * w, 5f * w}, 0f);
                case "EXTERNAL" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {1.5f * w, 4f * w}, 0f);
                default -> new BasicStroke(w);
            };
        }

        private void drawNodes(Graphics2D g, Set<V> lit, boolean dimming) {
            String q = search.getText().strip().toLowerCase();
            for (V v : vs) {
                if (v.hidden || (focus != null && !visible(v))) {
                    continue;
                }
                boolean dim = dimming && !lit.contains(v);
                g.setColor(dim ? Theme.alpha(v.color, 60) : v.color);
                g.fill(new java.awt.geom.Ellipse2D.Double(v.x - v.r, v.y - v.r, v.r * 2, v.r * 2));
                if ("STATIC_ONLY".equals(v.node.attrs.get("api_state"))) {
                    g.setColor(dim ? Theme.alpha(Theme.ACCENT, 70) : Theme.ACCENT);
                    g.setStroke(new BasicStroke((float) (1.6 / Math.sqrt(scale)), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {3f, 2.5f}, 0f));
                    g.draw(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 2.5, v.y - v.r - 2.5, v.r * 2 + 5, v.r * 2 + 5));
                }
                boolean match = !q.isEmpty() && v.node.label.toLowerCase().contains(q);
                if (v == selected || v == hover || match || v.pinned) {
                    g.setColor(v.pinned && v != selected ? Theme.muted() : Theme.fg());
                    g.setStroke(new BasicStroke((float) ((v == selected ? 2.4 : 1.6) / Math.sqrt(scale))));
                    g.draw(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 3, v.y - v.r - 3, v.r * 2 + 6, v.r * 2 + 6));
                }
                g.setStroke(new BasicStroke(1f));
            }
        }

        /** Labels are placed in priority order and skipped where they would overlap one already drawn. */
        private void drawLabels(Graphics2D g, Set<V> lit) {
            if (!labelsBox.isSelected()) {
                return;
            }
            g.setFont(Theme.font((float) Math.max(9.5, 11.5 / Math.sqrt(scale)), Font.PLAIN));
            FontMetrics fm = g.getFontMetrics();
            String q = search.getText().strip().toLowerCase();
            List<V> cand = new ArrayList<>();
            for (V v : vs) {
                if (v.hidden || (focus != null && !visible(v))) {
                    continue;
                }
                boolean match = !q.isEmpty() && v.node.label.toLowerCase().contains(q);
                if (v == selected || v == hover || match || (selected != null && lit.contains(v) && scale > 0.4)
                        || (flow && scale > 0.3) || (!flow && v.degree >= 5 && scale > 0.35) || scale > 1.6) {
                    cand.add(v);
                }
            }
            cand.sort(Comparator.comparingInt((V v) -> v == selected ? 0 : v == hover ? 1 : 2).thenComparingInt(v -> -v.degree));
            List<Rectangle> placed = new ArrayList<>();
            Rectangle view = new Rectangle((int) (-ox / scale) - 200, (int) (-oy / scale) - 100, (int) (getWidth() / scale) + 400, (int) (getHeight() / scale) + 200);
            int drawn = 0;
            for (V v : cand) {
                if (drawn > 140 && v != selected && v != hover) {
                    break;
                }
                if (!view.contains(v.x, v.y)) {
                    continue;
                }
                int tw = fm.stringWidth(v.shortLabel);
                int lx = (int) (v.x + v.r + 5);
                int ly = (int) (v.y + fm.getAscent() / 2.0 - 1);
                Rectangle r = new Rectangle(lx - 3, ly - fm.getAscent(), tw + 6, fm.getHeight());
                boolean clash = false;
                if (v != selected && v != hover) {
                    for (Rectangle p : placed) {
                        if (p.intersects(r)) {
                            clash = true;
                            break;
                        }
                    }
                }
                if (clash) {
                    continue;
                }
                placed.add(r);
                g.setColor(Theme.alpha(Theme.dark() ? Theme.shift(Theme.bg(), -8) : Theme.surface(), 215));
                g.fillRoundRect(r.x, r.y, r.width, r.height, 6, 6);
                g.setColor(Theme.fg());
                g.drawString(v.shortLabel, lx, ly);
                drawn++;
            }
        }

        private void legend(Graphics2D g) {
            String[][] items = {{"host", "host"}, {"route", "page"}, {"script", "script"}, {"endpoint", "endpoint"}, {"third_party", "third party"}, {"cookie", "trust"}, {"tech", "tech"}};
            int x = 12;
            int y = getHeight() - 14;
            g.setFont(Theme.font(11f, Font.PLAIN));
            for (String[] it : items) {
                Color c = Theme.type(it[0]);
                g.setColor(c);
                g.fillOval(x, y - 8, 9, 9);
                g.setColor(Theme.muted());
                g.drawString(it[1], x + 13, y);
                x += 22 + g.getFontMetrics().stringWidth(it[1]);
            }
            g.setColor(Theme.ACCENT);
            g.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {3f, 2.5f}, 0f));
            g.drawOval(x, y - 9, 11, 11);
            g.setStroke(new BasicStroke(1f));
            g.setColor(Theme.muted());
            g.drawString("named in code, never called", x + 16, y);
        }

        private void minimap(Graphics2D g) {
            if (vs.size() < 30) {
                return;
            }
            double[] b = extent();
            double bw = Math.max(1, b[2] - b[0]);
            double bh = Math.max(1, b[3] - b[1]);
            int mw = 160;
            int mh = (int) Math.max(40, Math.min(110, mw * bh / bw));
            int mx = getWidth() - mw - 12;
            int my = getHeight() - mh - 12;
            g.setColor(Theme.alpha(Theme.surface(), 220));
            g.fill(new RoundRectangle2D.Float(mx, my, mw, mh, 8, 8));
            g.setColor(Theme.line());
            g.draw(new RoundRectangle2D.Float(mx, my, mw, mh, 8, 8));
            double s = Math.min((mw - 12) / bw, (mh - 12) / bh);
            for (V v : vs) {
                if (v.hidden) {
                    continue;
                }
                g.setColor(Theme.alpha(v.color, 170));
                g.fillRect((int) (mx + 6 + (v.x - b[0]) * s), (int) (my + 6 + (v.y - b[1]) * s), 2, 2);
            }
            double vx = (-ox / scale - b[0]) * s + mx + 6;
            double vy = (-oy / scale - b[1]) * s + my + 6;
            double vw = getWidth() / scale * s;
            double vh = getHeight() / scale * s;
            g.setColor(Theme.ACCENT);
            g.setClip(mx, my, mw, mh);
            g.drawRect((int) vx, (int) vy, (int) vw, (int) vh);
            g.setClip(null);
        }

        private void tooltip(Graphics2D g) {
            V v = hover;
            if (v == null || dragging != null) {
                return;
            }
            List<String> lines = new ArrayList<>();
            lines.add(v.node.label.length() > 70 ? v.node.label.substring(0, 69) + "…" : v.node.label);
            Object st = v.node.attrs.get("api_state");
            lines.add(v.node.type.replace('_', ' ') + (st == null ? "" : " · " + String.valueOf(st).replace('_', ' ').toLowerCase()) + " · " + v.degree + " connections");
            if (!v.node.evidence.isEmpty()) {
                lines.add(v.node.evidence.size() + " request" + (v.node.evidence.size() == 1 ? "" : "s") + " · first ev_" + v.node.evidence.get(0));
            }
            g.setFont(Theme.font(11.5f, Font.PLAIN));
            FontMetrics fm = g.getFontMetrics();
            int w = 0;
            for (String l : lines) {
                w = Math.max(w, fm.stringWidth(l));
            }
            int h = lines.size() * (fm.getHeight() + 1) + 10;
            int x = Math.min(getWidth() - w - 24, mouse.x + 16);
            int y = Math.min(getHeight() - h - 8, mouse.y + 14);
            g.setColor(Theme.alpha(Theme.dark() ? Theme.shift(Theme.bg(), 18) : Color.WHITE, 245));
            g.fill(new RoundRectangle2D.Float(x, y, w + 18, h, 8, 8));
            g.setColor(Theme.line());
            g.draw(new RoundRectangle2D.Float(x, y, w + 18, h, 8, 8));
            g.setColor(v.color);
            g.fillRoundRect(x, y + 6, 3, h - 12, 3, 3);
            int ty = y + 6 + fm.getAscent();
            for (int i = 0; i < lines.size(); i++) {
                g.setColor(i == 0 ? Theme.fg() : Theme.muted());
                g.setFont(Theme.font(11.5f, i == 0 ? Font.BOLD : Font.PLAIN));
                g.drawString(lines.get(i), x + 11, ty);
                ty += fm.getHeight() + 1;
            }
        }
    }

    static JComponent unused() {
        return new JLabel();
    }
}
