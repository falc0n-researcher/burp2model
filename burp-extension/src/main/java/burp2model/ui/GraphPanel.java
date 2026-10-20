package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.Timer;

/**
 * The map: the model as a network you can read. Two layouts (a force-directed network and a left-to-right flow),
 * both deterministic, so the same model always draws the same way; adding requests keeps what was already placed.
 * Solid lines were seen in traffic, dashed ones found in code. GraphData decides what is drawn, MapLayout where,
 * MapCanvas how; Viewport is the camera and GraphToolbar the bar above. This class holds them together.
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
        /** For a group's stand-in: how many nodes it holds (0 for an ordinary node). */
        int members;
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

    private static final int BIG = 1500;
    /** Above this many nodes, frames drawn while the map moves skip dashes and labels. */
    static final int FAST_PAINT = 600;

    final MapCanvas canvas = new MapCanvas(this);
    final Viewport view = new Viewport(canvas);
    final GraphToolbar bar;
    final JTextField search;
    final JCheckBox labelsBox;
    final JCheckBox groupBox;
    private final JLabel info = new JLabel(" ");
    /** Groups the user opened (they stay open across refreshes until closed or Re-layout). */
    final Set<String> expanded = new HashSet<>();
    /** Member node id -> the group key it belongs to, for the nodes of open groups (to close them again). */
    final Map<String, String> openGroupOf = new HashMap<>();
    /** Group stand-in id -> its member nodes. */
    final Map<String, List<Model.Node>> groupMembers = new HashMap<>();
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
    private int steps;
    private int maxSteps = 320;
    boolean flow;
    private List<V> matches = new ArrayList<>();
    private int matchAt = -1;

    GraphPanel() {
        super(new BorderLayout());
        bar = new GraphToolbar(new GraphToolbar.Actions() {
            @Override
            public void rebuild() {
                GraphPanel.this.rebuild(false);
            }

            @Override
            public void repaint() {
                canvas.repaint();
            }

            @Override
            public void setFlow(boolean f) {
                GraphPanel.this.setFlow(f);
            }

            @Override
            public void find(boolean fresh) {
                GraphPanel.this.find(fresh);
            }

            @Override
            public void fit() {
                fitAnimated();
            }

            @Override
            public void relayout() {
                memory.clear();
                expanded.clear();                   // and close every opened group
                GraphPanel.this.rebuild(true);
            }

            @Override
            public void savePng() {
                GraphPanel.this.savePng();
            }
        });
        search = bar.search;
        labelsBox = bar.labelsBox;
        groupBox = bar.groupBox;
        info.setForeground(Theme.MUTED);
        info.setFont(Theme.font(11f, Font.PLAIN));
        info.setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
        add(bar, BorderLayout.NORTH);
        add(canvas, BorderLayout.CENTER);
        add(info, BorderLayout.SOUTH);
        sim = new Timer(16, e -> tick());
    }

    void onSelect(Consumer<Model.Node> c) {
        onSelect = c;
    }

    /** Called when the user asks to see a node in the Surface tab. */
    void onOpen(Consumer<Model.Node> c) {
        onOpen = c;
    }

    /** The structure (GraphData.structureOf) of the model on the map: the same structure needs no new layout. */
    private long structure;

    void setModel(Model m) {
        if (m != null && model != null && GraphData.structureOf(m) == structure) {
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
        structure = m == null ? 0 : GraphData.structureOf(m);
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
        bar.showFlow(f);
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
        GraphData.Graph g = GraphData.build(model, bar.types(), bar.codeOnly.isSelected(), groupBox.isSelected() && !flow, expanded);
        List<V> vs = g.vs();
        List<E> es = g.es();
        groupMembers.clear();
        groupMembers.putAll(g.groupMembers());
        openGroupOf.clear();
        openGroupOf.putAll(g.openGroupOf());
        maxSteps = vs.size() > 900 ? 160 : 320;
        int gen = ++layoutGen;
        int groupCount = groupMembers.size();
        String infoText = vs.size() + " nodes · " + es.size() + " edges"
                + (groupCount > 0 ? "   ·   " + groupCount + " groups: double-click one to open it" : "")
                + "   ·   solid: seen in traffic · dashed: found in code   ·   scroll to zoom · drag to pan or move · double-click to focus · right-click for more"
                + (g.shown() > BIG && groupCount == 0 ? "   ·   a large map: turn groups off to see less" : "");
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
                    install(g);
                    layingOut = false;
                    steps = maxSteps;
                    remember();
                    info.setText(infoText);
                    if (refit || firstMap) {
                        view.fitted = false;
                    }
                    canvas.repaint();
                });
            });
            return;
        }
        install(g);
        layingOut = false;
        if (flow) {
            MapLayout.layoutFlow(this.vs);
        } else {
            MapLayout.placeAll(this.vs, memory);
            MapLayout.relax(vs, es, maxSteps, true, 0, maxSteps);
            remember();
        }
        steps = maxSteps;
        info.setText(infoText);
        if (refit) {
            view.fitted = false;
        }
        canvas.repaint();
    }

    /** Open a group: its members take its place, starting around where it was. */
    void expandGroup(V g) {
        if (g == null || g.members == 0) {
            return;
        }
        String key = g.node.id.substring("group:".length());
        List<Model.Node> members = groupMembers.getOrDefault(g.node.id, List.of());
        // the rest of the map moves out by the disc's radius, all in the same direction from the group, so its shape
        // is kept; the members fill the disc, evenly (a sunflower spiral), and stay where they are put
        double rad = GraphData.openRadius(members.size());
        double cx = g.x;
        double cy = g.y;
        Set<String> ids = new HashSet<>();
        ids.add(g.node.id);
        for (Model.Node n : members) {
            ids.add(n.id);
        }
        shiftOut(cx, cy, rad, ids);
        memory.remove(g.node.id);
        for (int i = 0; i < members.size(); i++) {
            double d = rad * 0.92 * Math.sqrt((i + 0.5) / members.size());
            double a = i * 2.399963229728653;
            memory.put(members.get(i).id, new double[] {cx + Math.cos(a) * d, cy + Math.sin(a) * d, 0});
        }
        expanded.add(key);
        selected = null;
        rebuild(true);                          // the map grew or shrank: fit it again
    }

    /** Move every remembered position except `skip` along the line from (cx, cy) by `by` (inwards when negative, never past the centre). */
    private void shiftOut(double cx, double cy, double by, Set<String> skip) {
        remember();
        for (Map.Entry<String, double[]> e : memory.entrySet()) {
            if (skip.contains(e.getKey())) {
                continue;
            }
            double[] p = e.getValue();
            double dx = p[0] - cx;
            double dy = p[1] - cy;
            double d = Math.hypot(dx, dy);
            if (d < 1e-6) {
                dx = 1;
                dy = 0;
                d = 1;
            }
            double nd = Math.max(by < 0 ? Math.min(d, 8) : 0, d + by);
            p[0] = cx + dx / d * nd;
            p[1] = cy + dy / d * nd;
        }
        // the nodes on screen too, since the next layout starts from what is on screen
        for (V v : vs) {
            double[] p = memory.get(v.node.id);
            if (p != null && !skip.contains(v.node.id)) {
                v.x = p[0];
                v.y = p[1];
            }
        }
    }

    /** Close the open group a node belongs to: its members fold back into one node where they are. */
    void collapseGroupOf(V v) {
        String key = v == null ? null : openGroupOf.get(v.node.id);
        if (key == null) {
            return;
        }
        double sx = 0;
        double sy = 0;
        int c = 0;
        for (V x : vs) {
            if (key.equals(openGroupOf.get(x.node.id))) {
                sx += x.x;
                sy += x.y;
                c++;
            }
        }
        if (c > 0) {
            Set<String> ids = new HashSet<>();
            for (V x : vs) {
                if (key.equals(openGroupOf.get(x.node.id))) {
                    ids.add(x.node.id);
                    memory.remove(x.node.id);
                }
            }
            // the rest of the map closes the gap the group left
            shiftOut(sx / c, sy / c, -GraphData.openRadius(c), ids);
            memory.put("group:" + key, new double[] {sx / c, sy / c, 0});
        }
        expanded.remove(key);
        selected = null;
        rebuild(true);                          // the map grew or shrank: fit it again
    }

    /** Put a newly built graph on screen in one step. */
    private void install(GraphData.Graph g) {
        vs.clear();
        vs.addAll(g.vs());
        es.clear();
        es.addAll(g.es());
        byId.clear();
        byId.putAll(g.byId());
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

    /** For tests: the nodes on the map now. */
    List<V> vsForTest() {
        return new ArrayList<>(vs);
    }

    /** For tests: wait until a background layout has been applied. */
    void awaitLayout(long ms) throws InterruptedException {
        long end = System.currentTimeMillis() + ms;
        while (layingOut && System.currentTimeMillis() < end) {
            Thread.sleep(10);
        }
    }

    // ------------------------------------------------------------------ layout

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
            if (!view.fitted) {
                fitAnimated();
            }
            return;
        }
        MapLayout.step(vs, es, Math.max(0.04, 1.0 - steps / (double) maxSteps) * 0.6);
        steps++;
        if (!view.fitted && steps % 40 == 0) {
            fit();
        }
        // a big map takes longer to draw than to step: draw every third step so the Swing thread keeps up with input
        if (vs.size() <= FAST_PAINT || steps % 3 == 0) {
            canvas.repaint();
        }
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

    void fit() {
        if (vs.isEmpty() || canvas.getWidth() < 10) {
            return;
        }
        view.jumpTo(view.fitting(extent(), flow));
        view.fitted = true;
    }

    void fitAnimated() {
        if (vs.isEmpty() || canvas.getWidth() < 10) {
            return;
        }
        double[] f = view.fitting(extent(), flow);
        view.animateTo(f[0], f[1], f[2]);
        view.fitted = true;
    }

    // ------------------------------------------------------------------ search and selection

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
        view.centerOn(hit.x, hit.y);
        info.setText("match " + (matchAt + 1) + " of " + matches.size() + " — Enter for the next");
    }

    void select(V v) {
        selected = v;
        if (v != null) {
            onSelect.accept(v.node);
        }
        canvas.repaint();
    }

    /** Stop the layout, camera and search timers (the extension is unloading). */
    void stop() {
        sim.stop();
        view.anim.stop();
        bar.stop();
    }

    /** Select a node by id (from another tab). */
    void showNode(String id) {
        V v = byId.get(id);
        if (v != null) {
            select(v);
            view.centerOn(v.x, v.y);
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
}
