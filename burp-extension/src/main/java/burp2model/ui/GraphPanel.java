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
    static final class V {
        Model.Node node;
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
        /** The label lowercased once, for search highlighting on every frame. */
        final String lower;

        V(Model.Node n) {
            this.node = n;
            this.color = Theme.type(n.type);
            String l = n.label;
            this.shortLabel = l.length() > 44 ? l.substring(0, 43) + "…" : l;
            this.lower = l.toLowerCase();
        }
    }

    record E(V a, V b, String state, String type) {}

    private static final String[][] GROUPS = {
        {"Hosts", "host"}, {"Pages", "route"}, {"Scripts", "script"}, {"Endpoints", "endpoint,operation"}, {"Parameters", "parameter"},
        {"Third parties", "third_party"}, {"Trust", "cookie,auth,role"}, {"Tech", "tech"}};
    private static final int BIG = 1500;
    /** Above this many nodes, frames drawn while the map moves skip dashes and labels. */
    private static final int FAST_PAINT = 600;

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
            // parameters, tech and trust (roles, cookies, credentials) are off at first: each links to most of the map
            // and turns it into a ball of lines; one click brings any of them back
            JCheckBox c = new JCheckBox(g[0], !g[0].equals("Parameters") && !g[0].equals("Tech") && !g[0].equals("Trust"));
            c.setFont(Theme.font(11f, Font.PLAIN));
            c.addActionListener(e -> rebuild(false));
            toggles.put(g[1], c);
            bar.add(c);
        }
        codeOnly.setFont(Theme.font(11f, Font.PLAIN));
        codeOnly.setToolTipText("Show only endpoints the code names but nothing called, with what names them");
        codeOnly.addActionListener(e -> rebuild(false));
        labelsBox.setFont(Theme.font(11f, Font.PLAIN));
        labelsBox.addActionListener(e -> canvas.repaint());
        bar.add(codeOnly);
        bar.add(labelsBox);
        ButtonGroup bg = new ButtonGroup();
        bg.add(networkBtn);
        bg.add(flowBtn);
        for (JToggleButton b : new JToggleButton[] {networkBtn, flowBtn}) {
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
        // finding selects the match, which loads its facts and request: wait until typing pauses
        findLater.setRepeats(false);
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }
        });
        search.addActionListener(e -> {
            boolean pending = findLater.isRunning();
            findLater.stop();
            find(pending);
        });
        bar.add(search);
        bar.add(button("Fit", "Fit everything on screen (F)", this::fitAnimated));
        bar.add(button("Re-layout", "Forget positions and lay the map out again", () -> {
            memory.clear();
            rebuild(true);
        }));
        bar.add(button("PNG", "Save the map as an image", this::savePng));
        info.setForeground(Theme.MUTED);
        info.setFont(Theme.font(11f, Font.PLAIN));
        info.setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
        bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE));
        add(bar, BorderLayout.NORTH);
        add(canvas, BorderLayout.CENTER);
        add(info, BorderLayout.SOUTH);
        sim = new Timer(16, e -> tick());
        anim = new Timer(14, e -> animTick());
    }

    private static JButton button(String text, String tip, Runnable r) {
        JButton b = new JButton(text);
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

    /** The model's nodes and edges as a fingerprint: the same structure needs no new layout. */
    private long structure;

    private static long structureOf(Model m) {
        long h = 0xcbf29ce484222325L;
        for (Model.Node n : m.nodes.values()) {
            h = (h ^ n.id.hashCode()) * 0x100000001b3L;
            h = (h ^ n.type.hashCode()) * 0x100000001b3L;
            h = (h ^ String.valueOf(n.attrs.get("api_state")).hashCode()) * 0x100000001b3L;
        }
        for (Model.Edge e : m.edges) {
            h = (h ^ e.src.hashCode()) * 0x100000001b3L;
            h = (h ^ e.dst.hashCode()) * 0x100000001b3L;
            h = (h ^ e.type.hashCode()) * 0x100000001b3L;
            h = (h ^ String.valueOf(e.state).hashCode()) * 0x100000001b3L;
        }
        return h ^ ((long) m.nodes.size() << 32) ^ m.edges.size();
    }

    void setModel(Model m) {
        if (m != null && model != null && structureOf(m) == structure) {
            // live capture added requests but nothing new to draw: keep the layout, the selection and the view
            this.model = m;
            for (V v : vs) {
                Model.Node n = m.nodes.get(v.node.id);
                if (n != null) {
                    v.node = n;
                }
            }
            canvas.repaint();
            return;
        }
        structure = m == null ? 0 : structureOf(m);
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
        // the toggles always say which layout is drawn, however it was switched
        networkBtn.setSelected(!f);
        flowBtn.setSelected(f);
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
        // keep what is on screen as the starting point: new requests must not send the map back to older positions
        if (!vs.isEmpty() && !flow && !layingOut) {
            remember();
        }
        matches = new ArrayList<>();
        matchAt = -1;
        if (model == null) {
            vs.clear();
            es.clear();
            byId.clear();
            layingOut = false;
            canvas.repaint();
            return;
        }
        // the new graph is built aside; the one on screen stays until the new one is placed
        List<V> vs = new ArrayList<>();
        List<E> es = new ArrayList<>();
        Map<String, V> byId = new HashMap<>();
        Set<String> types = new HashSet<>();
        toggles.forEach((k, c) -> {
            if (c.isSelected()) {
                for (String t : k.split(",")) {
                    types.add(t);
                }
            }
        });
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
        maxSteps = vs.size() > 900 ? 160 : 320;
        int gen = ++layoutGen;
        String infoText = vs.size() + " nodes · " + es.size() + " edges   ·   solid: seen in traffic · dashed: found in code   ·   scroll to zoom · drag to pan or move · double-click to focus · right-click for more"
                + (cap > BIG ? "   ·   a large map: turn groups off to see less" : "");
        // The map never animates: the layout is computed to the end and shown once. Nodes already placed keep their
        // place (they are fixed while new ones settle among them), so a refresh only adds; Re-layout starts over.
        if (!flow && vs.size() > ASYNC_LAYOUT) {
            // a big map lays out on a background thread while the current one stays on screen
            Map<String, double[]> mem = new HashMap<>(memory);
            int max = maxSteps;
            boolean firstMap = this.vs.isEmpty();
            layingOut = true;
            LAYOUT.execute(() -> {
                MapLayout.placeAll(vs, mem);
                MapLayout.relax(vs, es, max, true, 0, max);
                javax.swing.SwingUtilities.invokeLater(() -> {
                    if (gen != layoutGen) {
                        return;                                 // a newer model arrived meanwhile
                    }
                    install(vs, es, byId);
                    layingOut = false;
                    steps = maxSteps;
                    remember();
                    info.setText(infoText);
                    if (refit || firstMap) {
                        fitted = false;
                    }
                    canvas.repaint();
                });
            });
            return;
        }
        install(vs, es, byId);
        layingOut = false;
        place();
        if (!flow) {
            MapLayout.relax(vs, es, maxSteps, true, 0, maxSteps);
            remember();
        }
        steps = maxSteps;
        info.setText(infoText);
        if (refit) {
            fitted = false;
        }
        canvas.repaint();
    }

    /** Put a newly built graph on screen in one step. */
    private void install(List<V> nv, List<E> ne, Map<String, V> nb) {
        vs.clear();
        vs.addAll(nv);
        es.clear();
        es.addAll(ne);
        byId.clear();
        byId.putAll(nb);
    }

    /** Above this many nodes the first layout runs off the Swing thread. */
    static final int ASYNC_LAYOUT = 60;
    private static final java.util.concurrent.ThreadPoolExecutor LAYOUT = new java.util.concurrent.ThreadPoolExecutor(1, 1, 2, java.util.concurrent.TimeUnit.SECONDS,
            new java.util.concurrent.LinkedBlockingQueue<>(), r -> {
                Thread t = new Thread(r, "burp2model-map-layout");
                t.setDaemon(true);
                return t;
            });

    static {
        LAYOUT.allowCoreThreadTimeOut(true);                    // no thread left behind once the map is idle
    }

    private int layoutGen;
    private volatile boolean layingOut;

    /** For tests: wait until a background layout has been applied. */
    void awaitLayout(long ms) throws InterruptedException {
        long end = System.currentTimeMillis() + ms;
        while (layingOut && System.currentTimeMillis() < end) {
            Thread.sleep(10);
        }
    }

    // ------------------------------------------------------------------ layout


    private void place() {
        if (flow) {
            MapLayout.layoutFlow(vs);
            steps = maxSteps + 1;
            return;
        }
        if (MapLayout.placeAll(vs, memory)) {
            steps = 0;
        }
    }




    private void remember() {
        for (V v : vs) {
            memory.put(v.node.id, new double[] {v.x, v.y, v.pinned ? 1 : 0});
        }
    }

    private void tick() {
        if (vs.isEmpty() || steps >= maxSteps) {
            sim.stop();
            canvas.repaint();                                   // one full-quality frame once the map settles
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
        // a big map takes longer to draw than to step: draw every third step so the Swing thread keeps up with input
        if (vs.size() <= FAST_PAINT || steps % 3 == 0) {
            canvas.repaint();
        }
    }

    /** Run this many layout steps right away, so the map is already arranged when first drawn. */
    private void relax(int n, boolean cool) {
        MapLayout.relax(vs, es, n, cool, steps, maxSteps);
    }


    private void step(double temp) {
        MapLayout.step(vs, es, temp);
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

    private final Timer findLater = new Timer(200, e -> find(true));

    private void find(boolean fromTyping) {
        String q = search.getText().strip().toLowerCase();
        if (fromTyping) {
            matches = new ArrayList<>();
            matchAt = -1;
            if (!q.isEmpty()) {
                for (V v : vs) {
                    if (v.lower.contains(q)) {
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
    /** Stop the layout and camera timers (the extension is unloading). */
    void stop() {
        sim.stop();
        anim.stop();
    }

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
        private boolean fast;
        private double vx0;
        private double vy0;
        private double vx1;
        private double vy1;

        /** A big map while it moves (layout running, camera animating, being dragged) is drawn the cheap way. */
        private boolean moving() {
            return vs.size() > FAST_PAINT && (sim.isRunning() || anim.isRunning() || (last != null && moved));
        }

        private boolean inView(V v) {
            return v.x >= vx0 && v.x <= vx1 && v.y >= vy0 && v.y <= vy1;
        }

        /** An edge is skipped only when its bounding box misses the screen (flow curves stay inside it too). */
        private boolean inView(E e) {
            return Math.max(e.a.x, e.b.x) >= vx0 && Math.min(e.a.x, e.b.x) <= vx1 && Math.max(e.a.y, e.b.y) >= vy0 && Math.min(e.a.y, e.b.y) <= vy1;
        }

        Canvas() {
            setOpaque(true);
            setFocusable(true);
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    requestFocusInWindow();
                    if (layingOut) {
                        return;
                    }
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
                    if (moved && fast) {
                        repaint();                              // the full-quality frame after a drag
                    }
                    last = null;
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
                    if (layingOut) {
                        return;
                    }
                    V h = pick(e.getPoint());
                    boolean changed = h != hover;
                    if (changed) {
                        hover = h;
                        setCursor(Cursor.getPredefinedCursor(h == null ? Cursor.DEFAULT_CURSOR : Cursor.HAND_CURSOR));
                    }
                    // the tooltip follows the mouse over a node; over empty canvas nothing changes, so nothing is redrawn
                    if (changed || h != null) {
                        repaint();
                    }
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
                    if (e.getKeyChar() == '/') {
                        search.requestFocusInWindow();          // '/' jumps to Find, as in many viewers
                        search.selectAll();
                        return;
                    }
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
            fast = moving();
            // a big map in motion is drawn without dashes and labels (they come back when it stops); antialiasing stays
            // on, since Java2D's plain renderer is slower than Marlin on large paths
            g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, fast ? RenderingHints.VALUE_STROKE_NORMALIZE : RenderingHints.VALUE_STROKE_PURE);
            Color bg = Theme.dark() ? Theme.shift(Theme.bg(), -8) : Theme.surface();
            g.setColor(bg);
            g.fillRect(0, 0, getWidth(), getHeight());
            if (layingOut && vs.isEmpty()) {
                g.setColor(Theme.muted());
                g.setFont(Theme.font(13f, Font.PLAIN));
                g.drawString("Laying out " + vs.size() + " nodes…", 24, 36);
                g.dispose();
                return;
            }
            // what is on screen, in map coordinates, with a margin for node sizes and rings
            double pad = 30 / scale + 20;
            vx0 = -ox / scale - pad;
            vy0 = -oy / scale - pad;
            vx1 = (getWidth() - ox) / scale + pad;
            vy1 = (getHeight() - oy) / scale + pad;
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
                if (!inView(e)) {
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
            if (fast) {
                return new BasicStroke(w);
            }
            return switch (state) {
                case "INFERRED" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {6f * w, 5f * w}, 0f);
                case "EXTERNAL" -> new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {1.5f * w, 4f * w}, 0f);
                default -> new BasicStroke(w);
            };
        }

        private void drawNodes(Graphics2D g, Set<V> lit, boolean dimming) {
            String q = search.getText().strip().toLowerCase();
            // nodes of one colour are filled as one shape, and the code-only rings stroked as one: a few draw calls, not thousands
            Map<Color, Path2D.Double> fills = new LinkedHashMap<>();
            Path2D.Double rings = new Path2D.Double();
            Path2D.Double dimRings = new Path2D.Double();
            List<V> marked = new ArrayList<>();
            for (V v : vs) {
                if (v.hidden || (focus != null && !visible(v)) || !inView(v)) {
                    continue;
                }
                boolean dim = dimming && !lit.contains(v);
                fills.computeIfAbsent(dim ? Theme.alpha(v.color, 60) : v.color, k -> new Path2D.Double())
                        .append(new java.awt.geom.Ellipse2D.Double(v.x - v.r, v.y - v.r, v.r * 2, v.r * 2), false);
                if ("STATIC_ONLY".equals(v.node.attrs.get("api_state"))) {
                    (dim ? dimRings : rings).append(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 2.5, v.y - v.r - 2.5, v.r * 2 + 5, v.r * 2 + 5), false);
                }
                if (v == selected || v == hover || v.pinned || (!q.isEmpty() && v.lower.contains(q))) {
                    marked.add(v);
                }
            }
            fills.forEach((c, shape) -> {
                g.setColor(c);
                g.fill(shape);
            });
            // code-only rings: present but quiet, so a map of mostly code-only endpoints still shows its structure
            float rw = (float) (1.1 / Math.sqrt(scale));
            g.setStroke(fast ? new BasicStroke(rw) : new BasicStroke(rw, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {2.5f, 3f}, 0f));
            g.setColor(Theme.alpha(Theme.ACCENT, 40));
            g.draw(dimRings);
            g.setColor(Theme.alpha(Theme.ACCENT, 150));
            g.draw(rings);
            for (V v : marked) {
                g.setColor(v.pinned && v != selected ? Theme.muted() : Theme.fg());
                g.setStroke(new BasicStroke((float) ((v == selected ? 2.4 : 1.6) / Math.sqrt(scale))));
                g.draw(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 3, v.y - v.r - 3, v.r * 2 + 6, v.r * 2 + 6));
            }
            g.setStroke(new BasicStroke(1f));
        }

        /** Labels are placed in priority order and skipped where they would overlap one already drawn. */
        private void drawLabels(Graphics2D g, Set<V> lit) {
            if (!labelsBox.isSelected()) {
                return;
            }
            // labels are drawn in map space: keep them at least 10 px on screen however far the map is zoomed out
            g.setFont(Theme.font((float) Math.max(Math.max(9.5, 11.5 / Math.sqrt(scale)), 10.5 / scale), Font.PLAIN));
            FontMetrics fm = g.getFontMetrics();
            String q = search.getText().strip().toLowerCase();
            List<V> cand = new ArrayList<>();
            for (V v : vs) {
                if (v.hidden || (focus != null && !visible(v)) || !inView(v)) {
                    continue;
                }
                if (fast && v != selected && v != hover) {
                    continue;                                   // labels come back in the full-quality frame
                }
                boolean match = !q.isEmpty() && v.lower.contains(q);
                if (v == selected || v == hover || match || (selected != null && lit.contains(v) && scale > 0.4)
                        || (flow && scale > 0.3) || (!flow && v.degree >= 5 && scale > 0.35) || scale > 1.6
                        || vs.size() <= 80) {                           // a small map names everything that fits
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
}
