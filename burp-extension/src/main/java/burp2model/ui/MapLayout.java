package burp2model.ui;

import burp2model.engine.Model;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * How the map is laid out: a force-directed network (seeded from remembered positions, so a growing map keeps its
 * shape) and a left-to-right flow by kind. Plain functions over the vertices, so they can run off the Swing thread.
 */
final class MapLayout {
    private MapLayout() {}

    static double rnd(String id, int salt) {
        long h = id.hashCode() * 0x9E3779B97F4A7C15L + salt * 0xBF58476D1CE4E5B9L;
        h ^= h >>> 29;
        h *= 0x94D049BB133111EBL;
        h ^= h >>> 32;
        return (h & 0xFFFFFFL) / (double) 0x1000000L;
    }

    /** Seed positions: remembered ones, or beside placed neighbours, or on a ring by layer. True when every node is new. */
    static boolean placeAll(List<GraphPanel.V> vs, Map<String, double[]> memory) {
        int n = Math.max(1, vs.size());
        double rad = 90 + 11 * Math.sqrt(n) * 3;
        List<GraphPanel.V> fresh = new ArrayList<>();
        for (GraphPanel.V v : vs) {
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
        for (GraphPanel.V v : fresh) {
            double sx = 0;
            double sy = 0;
            int c = 0;
            for (GraphPanel.V nb : v.nbrs) {
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
        return fresh.size() == vs.size();
    }

    static int column(Model.Node n) {
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
    static void layoutFlow(List<GraphPanel.V> vs) {
        List<List<GraphPanel.V>> cols = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            cols.add(new ArrayList<>());
        }
        for (GraphPanel.V v : vs) {
            cols.get(column(v.node)).add(v);
        }
        for (List<GraphPanel.V> c : cols) {
            c.sort(Comparator.comparing((GraphPanel.V v) -> v.node.type).thenComparing(v -> v.node.label));
        }
        Map<GraphPanel.V, Double> row = new HashMap<>();
        for (List<GraphPanel.V> c : cols) {
            for (int i = 0; i < c.size(); i++) {
                row.put(c.get(i), (double) i);
            }
        }
        for (int pass = 0; pass < 4; pass++) {
            for (int ci = pass % 2 == 0 ? 1 : 4; pass % 2 == 0 ? ci < 6 : ci >= 0; ci += pass % 2 == 0 ? 1 : -1) {
                List<GraphPanel.V> c = cols.get(ci);
                Map<GraphPanel.V, Double> bary = new HashMap<>();
                for (GraphPanel.V v : c) {
                    double sum = 0;
                    int cnt = 0;
                    for (GraphPanel.V nb : v.nbrs) {
                        int nc = column(nb.node);
                        if (nc != ci && Math.abs(nc - ci) <= 2) {
                            sum += row.get(nb);
                            cnt++;
                        }
                    }
                    bary.put(v, cnt > 0 ? sum / cnt : row.get(v));
                }
                c.sort(Comparator.comparingDouble((GraphPanel.V v) -> bary.get(v)).thenComparing(v -> v.node.label));
                for (int i = 0; i < c.size(); i++) {
                    row.put(c.get(i), (double) i);
                }
            }
        }
        // a tall column wraps into side-by-side stacks, so the whole map fits on screen at a size that can be read
        final int perStack = 28;
        double gap = 24;
        double x = 0;
        for (List<GraphPanel.V> c : cols) {
            int stacks = Math.max(1, (c.size() + perStack - 1) / perStack);
            for (int i = 0; i < c.size(); i++) {
                GraphPanel.V v = c.get(i);
                int sc = i / perStack;
                int inStack = Math.min(perStack, c.size() - sc * perStack);
                v.x = x + sc * 310;
                v.y = (i % perStack - (inStack - 1) / 2.0) * gap;
                v.pinned = false;
            }
            x += stacks * 310 + 70;
        }
    }

    static void relax(List<GraphPanel.V> vs, List<GraphPanel.E> es, int n, boolean cool, int steps, int maxSteps) {
        for (int i = 0; i < n && !vs.isEmpty(); i++) {
            step(vs, es, cool ? Math.max(0.04, 1.0 - (steps + i) / (double) maxSteps) : 0.3);
        }
    }

    static void step(List<GraphPanel.V> vs, List<GraphPanel.E> es, double temp) {
        double cell = 110;
        Map<Long, List<GraphPanel.V>> grid = new HashMap<>();
        for (GraphPanel.V v : vs) {
            grid.computeIfAbsent(key((int) Math.floor(v.x / cell), (int) Math.floor(v.y / cell)), k -> new ArrayList<>()).add(v);
        }
        for (GraphPanel.V v : vs) {
            double fx = 0;
            double fy = 0;
            int cx = (int) Math.floor(v.x / cell);
            int cy = (int) Math.floor(v.y / cell);
            for (int dx = -1; dx <= 1; dx++) {
                for (int dy = -1; dy <= 1; dy++) {
                    List<GraphPanel.V> bucket = grid.get(key(cx + dx, cy + dy));
                    if (bucket == null) {
                        continue;
                    }
                    for (GraphPanel.V u : bucket) {
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
                        double f = (2000.0 + 60 * (v.r + u.r)) / d2;
                        fx += ddx / d * f;
                        fy += ddy / d * f;
                    }
                }
            }
            v.vx += fx;
            v.vy += fy;
        }
        for (GraphPanel.E e : es) {
            double dx = e.b().x - e.a().x;
            double dy = e.b().y - e.a().y;
            double d = Math.sqrt(dx * dx + dy * dy) + 0.01;
            double want = 64 + e.a().r + e.b().r;
            double k = e.state().equals("INFERRED") ? 0.035 : 0.06;
            double f = (d - want) * k;
            double fx = dx / d * f;
            double fy = dy / d * f;
            e.a().vx += fx;
            e.a().vy += fy;
            e.b().vx -= fx;
            e.b().vy -= fy;
        }
        for (GraphPanel.V v : vs) {
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
            // a node already on the map stays exactly where it is; only new ones find a place among them
            double mobility = v.settled ? 0.0 : 1.0;
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

    static long key(int x, int y) {
        return ((long) x << 32) ^ (y & 0xffffffffL);
    }
}
