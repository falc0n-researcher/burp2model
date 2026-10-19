package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Point;
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
import javax.swing.JLabel;
import javax.swing.JPanel;
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
    static final int FAST_PAINT = 600;

    final MapCanvas canvas = new MapCanvas(this);
    private final Map<String, JCheckBox> toggles = new LinkedHashMap<>();
    final JTextField search = new JTextField(14);
    private final JLabel info = new JLabel(" ");
    private final JToggleButton networkBtn = new JToggleButton("Network", true);
    private final JToggleButton flowBtn = new JToggleButton("Flow");
    private final JCheckBox codeOnly = new JCheckBox("Only code-named");
    final JCheckBox labelsBox = new JCheckBox("Labels", true);
    Model model;
    final List<V> vs = new ArrayList<>();
    final List<E> es = new ArrayList<>();
    private final Map<String, V> byId = new HashMap<>();
    /** Where each node was last drawn, kept across rebuilds so a growing model does not scramble. */
    final Map<String, double[]> memory = new HashMap<>();
    V selected;
    V hover;
    V focus;
    Point mouse = new Point();
    private Consumer<Model.Node> onSelect = n -> { };
    Consumer<Model.Node> onOpen = n -> { };
    final Timer sim;
    final Timer anim;
    private int steps;
    private int maxSteps = 320;
    double scale = 1;
    double ox;
    double oy;
    boolean fitted;
    boolean flow;
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
    volatile boolean layingOut;

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




    void remember() {
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

    double[] extent() {
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

    void select(V v) {
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

    boolean visible(V v) {
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

}
