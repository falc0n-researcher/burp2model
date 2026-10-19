package burp2model.ui;

import burp2model.ui.GraphPanel.E;
import burp2model.ui.GraphPanel.V;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

/** The map's canvas: drawing, hit testing, mouse and keys. The graph, layout and camera state live in GraphPanel. */
final class MapCanvas extends JComponent {
private static final long serialVersionUID = 1L;
private final GraphPanel map;
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
        return map.vs.size() > GraphPanel.FAST_PAINT && (map.sim.isRunning() || map.anim.isRunning() || (last != null && moved));
    }

    private boolean inView(V v) {
        return v.x >= vx0 && v.x <= vx1 && v.y >= vy0 && v.y <= vy1;
    }

    /** An edge is skipped only when its bounding box misses the screen (flow curves stay inside it too). */
    private boolean inView(E e) {
        return Math.max(e.a().x, e.b().x) >= vx0 && Math.min(e.a().x, e.b().x) <= vx1 && Math.max(e.a().y, e.b().y) >= vy0 && Math.min(e.a().y, e.b().y) <= vy1;
    }

    MapCanvas(GraphPanel map) {
        this.map = map;
        setOpaque(true);
        setFocusable(true);
        MouseAdapter ma = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                requestFocusInWindow();
                if (map.layingOut) {
                    return;
                }
                if (e.isPopupTrigger()) {
                    popup(e);
                    return;
                }
                map.anim.stop();
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
                    dragging.x += dx / map.scale;
                    dragging.y += dy / map.scale;
                } else {
                    map.ox += dx;
                    map.oy += dy;
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
                    map.remember();
                } else if (dragging != null) {
                    dragging.pinned = map.memory.containsKey(dragging.node.id) && map.memory.get(dragging.node.id).length > 2 && map.memory.get(dragging.node.id)[2] == 1;
                }
                if (!moved && e.getButton() == MouseEvent.BUTTON1) {
                    map.select(pick(e.getPoint()));
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
                    if (v != null && v.members > 0) {
                        map.expandGroup(v);                 // a group opens in place
                        return;
                    }
                    map.focus = v == null || v == map.focus ? null : v;
                    if (map.focus != null) {
                        map.select(map.focus);
                    }
                    map.fitAnimated();
                }
            }

            @Override
            public void mouseMoved(MouseEvent e) {
                map.mouse = e.getPoint();
                if (map.layingOut) {
                    return;
                }
                V h = pick(e.getPoint());
                boolean changed = h != map.hover;
                if (changed) {
                    map.hover = h;
                    setCursor(Cursor.getPredefinedCursor(h == null ? Cursor.DEFAULT_CURSOR : Cursor.HAND_CURSOR));
                }
                // the tooltip follows the mouse over a node; over empty canvas nothing changes, so nothing is redrawn
                if (changed || h != null) {
                    repaint();
                }
            }

            @Override
            public void mouseExited(MouseEvent e) {
                map.hover = null;
                repaint();
            }

            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                double f = Math.pow(1.18, -e.getPreciseWheelRotation());
                double ns = Math.max(0.05, Math.min(6, map.scale * f));
                map.ox = e.getX() - (e.getX() - map.ox) * ns / map.scale;
                map.oy = e.getY() - (e.getY() - map.oy) * ns / map.scale;
                map.scale = ns;
                map.fitted = true;
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
                    map.search.requestFocusInWindow();          // '/' jumps to Find, as in many viewers
                    map.search.selectAll();
                    return;
                }
                switch (e.getKeyCode()) {
                    case KeyEvent.VK_F -> map.fitAnimated();
                    case KeyEvent.VK_ESCAPE -> {
                        map.focus = null;
                        map.selected = null;
                        repaint();
                    }
                    case KeyEvent.VK_EQUALS, KeyEvent.VK_PLUS -> zoom(1.25);
                    case KeyEvent.VK_MINUS -> zoom(0.8);
                    case KeyEvent.VK_LEFT -> {
                        map.ox += 60;
                        repaint();
                    }
                    case KeyEvent.VK_RIGHT -> {
                        map.ox -= 60;
                        repaint();
                    }
                    case KeyEvent.VK_UP -> {
                        map.oy += 60;
                        repaint();
                    }
                    case KeyEvent.VK_DOWN -> {
                        map.oy -= 60;
                        repaint();
                    }
                    default -> {
                    }
                }
            }
        });
    }

    private void zoom(double f) {
        double ns = Math.max(0.05, Math.min(6, map.scale * f));
        map.ox = getWidth() / 2.0 - (getWidth() / 2.0 - map.ox) * ns / map.scale;
        map.oy = getHeight() / 2.0 - (getHeight() / 2.0 - map.oy) * ns / map.scale;
        map.scale = ns;
        repaint();
    }

    private void popup(MouseEvent e) {
        V v = pick(e.getPoint());
        JPopupMenu m = new JPopupMenu();
        if (v != null) {
            map.select(v);
            if (v.members > 0) {
                m.add(item("Open this group (" + v.members + ")", () -> map.expandGroup(v)));
            } else if (map.openGroupOf.containsKey(v.node.id)) {
                m.add(item("Close its group", () -> map.collapseGroupOf(v)));
            }
            m.add(item("Focus on this and its neighbours", () -> {
                map.focus = v;
                map.fitAnimated();
            }));
            if (v.members == 0) {
                m.add(item("Show it in Surface", () -> map.onOpen.accept(v.node)));
            }
            m.add(item(v.pinned ? "Unpin" : "Pin here", () -> {
                v.pinned = !v.pinned;
                map.remember();
                repaint();
            }));
            m.add(item("Hide this", () -> {
                v.hidden = true;
                repaint();
            }));
            m.add(item("Copy its name", () -> Tables.copy(v.node.label)));
        } else {
            m.add(item("Fit", map::fitAnimated));
            m.add(item("Clear focus and hidden", () -> {
                map.focus = null;
                for (V x : map.vs) {
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
        double x = (p.x - map.ox) / map.scale;
        double y = (p.y - map.oy) / map.scale;
        V best = null;
        double bd = 1e18;
        for (V v : map.vs) {
            if (v.hidden || (map.focus != null && !map.visible(v))) {
                continue;
            }
            double d = (v.x - x) * (v.x - x) + (v.y - y) * (v.y - y);
            double r = Math.max(v.r + 2, 8 / map.scale);
            if (d <= r * r && d < bd) {
                bd = d;
                best = v;
            }
        }
        return best;
    }

    @Override
    protected void paintComponent(Graphics g0) {
        if (!map.fitted && getWidth() > 10 && !map.vs.isEmpty()) {
            map.fit();
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
        if (map.layingOut && map.vs.isEmpty()) {
            g.setColor(Theme.muted());
            g.setFont(Theme.font(13f, Font.PLAIN));
            g.drawString("Laying out " + map.vs.size() + " nodes…", 24, 36);
            g.dispose();
            return;
        }
        // what is on screen, in map coordinates, with a margin for node sizes and rings
        double pad = 30 / map.scale + 20;
        vx0 = -map.ox / map.scale - pad;
        vy0 = -map.oy / map.scale - pad;
        vx1 = (getWidth() - map.ox) / map.scale + pad;
        vy1 = (getHeight() - map.oy) / map.scale + pad;
        if (map.vs.isEmpty()) {
            g.setColor(Theme.muted());
            g.setFont(Theme.font(13f, Font.PLAIN));
            g.drawString(map.model == null ? "Send some requests and the map appears here." : "Nothing to show: turn a group on above.", 24, 36);
            g.dispose();
            return;
        }
        AffineTransform base = g.getTransform();
        g.translate(map.ox, map.oy);
        g.scale(map.scale, map.scale);
        Set<V> lit = new HashSet<>();
        if (map.selected != null) {
            lit.add(map.selected);
            lit.addAll(map.selected.nbrs);
        } else if (map.hover != null) {
            lit.add(map.hover);
            lit.addAll(map.hover.nbrs);
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
        double sw = 1.0 / Math.sqrt(map.scale);
        Color base = Theme.fg();
        Map<String, Path2D.Double> batches = new HashMap<>();
        List<E> hot = new ArrayList<>();
        for (E e : map.es) {
            if (e.a().hidden || e.b().hidden || (map.focus != null && !(map.visible(e.a()) && map.visible(e.b())))) {
                continue;
            }
            if (!inView(e)) {
                continue;
            }
            boolean on = map.selected != null ? (e.a() == map.selected || e.b() == map.selected) : map.hover != null && (e.a() == map.hover || e.b() == map.hover);
            if (on) {
                hot.add(e);
                continue;
            }
            if (map.scale < 0.25 && map.vs.size() > 400 && !e.state().equals("OBSERVED")) {
                continue;
            }
            Path2D.Double p = batches.computeIfAbsent(e.state(), k -> new Path2D.Double());
            addEdge(p, e);
        }
        int alpha = dimming ? 26 : (map.vs.size() > 600 ? 50 : 78);
        for (Map.Entry<String, Path2D.Double> b : batches.entrySet()) {
            g.setColor(Theme.alpha(base, alpha));
            g.setStroke(strokeFor(b.getKey(), (float) sw));
            g.draw(b.getValue());
        }
        g.setFont(Theme.font((float) Math.max(9, 10 / Math.sqrt(map.scale)), Font.PLAIN));
        for (E e : hot) {
            g.setColor(Theme.ACCENT);
            g.setStroke(strokeFor(e.state(), (float) (sw * 2)));
            Path2D.Double p = new Path2D.Double();
            addEdge(p, e);
            g.draw(p);
            if (map.scale > 0.55 && hot.size() <= 10) {
                double mx = (e.a().x + e.b().x) / 2;
                double my = (e.a().y + e.b().y) / 2;
                String t = e.type().toLowerCase().replace('_', ' ');
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
        if (map.flow) {
            double mx = (e.a().x + e.b().x) / 2;
            CubicCurve2D.Double c = new CubicCurve2D.Double(e.a().x, e.a().y, mx, e.a().y, mx, e.b().y, e.b().x, e.b().y);
            p.append(c, false);
        } else {
            p.append(new Line2D.Double(e.a().x, e.a().y, e.b().x, e.b().y), false);
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
        String q = map.search.getText().strip().toLowerCase();
        // nodes of one colour are filled as one shape, and the code-only rings stroked as one: a few draw calls, not thousands
        Map<Color, Path2D.Double> fills = new LinkedHashMap<>();
        Path2D.Double rings = new Path2D.Double();
        Path2D.Double dimRings = new Path2D.Double();
        Path2D.Double groupRings = new Path2D.Double();
        List<V> marked = new ArrayList<>();
        for (V v : map.vs) {
            if (v.hidden || (map.focus != null && !map.visible(v)) || !inView(v)) {
                continue;
            }
            boolean dim = dimming && !lit.contains(v);
            fills.computeIfAbsent(dim ? Theme.alpha(v.color, 60) : v.color, k -> new Path2D.Double())
                    .append(new java.awt.geom.Ellipse2D.Double(v.x - v.r, v.y - v.r, v.r * 2, v.r * 2), false);
            if (v.members > 0) {
                groupRings.append(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 3.5, v.y - v.r - 3.5, v.r * 2 + 7, v.r * 2 + 7), false);
            }
            if ("STATIC_ONLY".equals(v.node.attrs.get("api_state"))) {
                (dim ? dimRings : rings).append(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 2.5, v.y - v.r - 2.5, v.r * 2 + 5, v.r * 2 + 5), false);
            }
            if (v == map.selected || v == map.hover || v.pinned || (!q.isEmpty() && v.lower.contains(q))) {
                marked.add(v);
            }
        }
        fills.forEach((c, shape) -> {
            g.setColor(c);
            g.fill(shape);
        });
        // a group wears a second ring: there is more inside, a double-click away
        g.setStroke(new BasicStroke((float) (1.4 / Math.sqrt(map.scale))));
        g.setColor(Theme.alpha(Theme.fg(), 110));
        g.draw(groupRings);
        // code-only rings: present but quiet, so a map of mostly code-only endpoints still shows its structure
        float rw = (float) (1.1 / Math.sqrt(map.scale));
        g.setStroke(fast ? new BasicStroke(rw) : new BasicStroke(rw, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[] {2.5f, 3f}, 0f));
        g.setColor(Theme.alpha(Theme.ACCENT, 40));
        g.draw(dimRings);
        g.setColor(Theme.alpha(Theme.ACCENT, 150));
        g.draw(rings);
        for (V v : marked) {
            g.setColor(v.pinned && v != map.selected ? Theme.muted() : Theme.fg());
            g.setStroke(new BasicStroke((float) ((v == map.selected ? 2.4 : 1.6) / Math.sqrt(map.scale))));
            g.draw(new java.awt.geom.Ellipse2D.Double(v.x - v.r - 3, v.y - v.r - 3, v.r * 2 + 6, v.r * 2 + 6));
        }
        g.setStroke(new BasicStroke(1f));
    }

    /** Labels are placed in priority order and skipped where they would overlap one already drawn. */
    private void drawLabels(Graphics2D g, Set<V> lit) {
        if (!map.labelsBox.isSelected()) {
            return;
        }
        // labels are drawn in map space: keep them at least 10 px on screen however far the map is zoomed out
        g.setFont(Theme.font((float) Math.max(Math.max(9.5, 11.5 / Math.sqrt(map.scale)), 10.5 / map.scale), Font.PLAIN));
        FontMetrics fm = g.getFontMetrics();
        String q = map.search.getText().strip().toLowerCase();
        List<V> cand = new ArrayList<>();
        for (V v : map.vs) {
            if (v.hidden || (map.focus != null && !map.visible(v)) || !inView(v)) {
                continue;
            }
            if (fast && v != map.selected && v != map.hover) {
                continue;                                   // labels come back in the full-quality frame
            }
            boolean match = !q.isEmpty() && v.lower.contains(q);
            if (v == map.selected || v == map.hover || match || (map.selected != null && lit.contains(v) && map.scale > 0.4)
                    || (map.flow && map.scale > 0.3) || (!map.flow && v.degree >= 5 && map.scale > 0.35) || map.scale > 1.6
                    || map.vs.size() <= 80 || v.members > 0) {          // a small map names everything; groups are always named
                cand.add(v);
            }
        }
        cand.sort(Comparator.comparingInt((V v) -> v == map.selected ? 0 : v == map.hover ? 1 : 2).thenComparingInt(v -> -v.degree));
        List<Rectangle> placed = new ArrayList<>();
        Rectangle view = new Rectangle((int) (-map.ox / map.scale) - 200, (int) (-map.oy / map.scale) - 100, (int) (getWidth() / map.scale) + 400, (int) (getHeight() / map.scale) + 200);
        int drawn = 0;
        for (V v : cand) {
            if (drawn > 140 && v != map.selected && v != map.hover) {
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
            if (v != map.selected && v != map.hover) {
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
        if (map.vs.size() < 30) {
            return;
        }
        double[] b = map.extent();
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
        for (V v : map.vs) {
            if (v.hidden) {
                continue;
            }
            g.setColor(Theme.alpha(v.color, 170));
            g.fillRect((int) (mx + 6 + (v.x - b[0]) * s), (int) (my + 6 + (v.y - b[1]) * s), 2, 2);
        }
        double vx = (-map.ox / map.scale - b[0]) * s + mx + 6;
        double vy = (-map.oy / map.scale - b[1]) * s + my + 6;
        double vw = getWidth() / map.scale * s;
        double vh = getHeight() / map.scale * s;
        g.setColor(Theme.ACCENT);
        g.setClip(mx, my, mw, mh);
        g.drawRect((int) vx, (int) vy, (int) vw, (int) vh);
        g.setClip(null);
    }

    private void tooltip(Graphics2D g) {
        V v = map.hover;
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
        int x = Math.min(getWidth() - w - 24, map.mouse.x + 16);
        int y = Math.min(getHeight() - h - 8, map.mouse.y + 14);
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
