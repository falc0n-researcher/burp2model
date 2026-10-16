package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;

/** The site map: host, then path, then the methods seen or named in code at each path. */
final class SiteTree extends JPanel {
    private record Entry(String label, Model.Node node) {}

    private final JTree tree = new JTree(new DefaultTreeModel(new DefaultMutableTreeNode(new Entry("Nothing yet", null))));
    private Consumer<List<Model.Node>> onSelect = l -> { };
    /** How many endpoints and pages sit under each folder, counted once per model (not per row painted). */
    private Map<DefaultMutableTreeNode, Integer> counts = new java.util.IdentityHashMap<>();

    SiteTree() {
        super(new BorderLayout());
        tree.setRootVisible(false);
        tree.setRowHeight(Theme.rowHeight(Theme.mono(12f), 24));
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new DefaultTreeCellRenderer() {
            @Override
            public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel, boolean exp, boolean leaf, int row, boolean focus) {
                JLabel l = (JLabel) super.getTreeCellRendererComponent(t, value, sel, exp, leaf, row, focus);
                Object o = ((DefaultMutableTreeNode) value).getUserObject();
                l.setIcon(null);
                l.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 4));
                if (o instanceof Entry e) {
                    int kids = ((DefaultMutableTreeNode) value).getChildCount();
                    if (e.node() != null) {
                        l.setFont(Theme.mono(12f));
                        String st = String.valueOf(e.node().attrs.get("api_state"));
                        String dot = "<font color='" + Theme.hex(Theme.state(st)) + "'>●</font> ";
                        Object m = e.node().attrs.get("method");
                        String chip = e.node().type.equals("endpoint")
                                ? "<font color='" + Theme.hex(Theme.method(m == null ? "" : String.valueOf(m))) + "'><b>" + (m == null ? "*" : m) + "</b></font>"
                                : "<font color='" + Theme.hex(Theme.GREEN) + "'><b>page</b></font>";
                        l.setText("<html>" + dot + chip + " <font color='" + Theme.hex(Theme.muted()) + "'>" + e.node().evidence.size() + " req</font></html>");
                    } else {
                        l.setFont(Theme.mono(12f).deriveFont(kids > 0 ? Font.BOLD : Font.PLAIN));
                        l.setText(e.label() + (kids > 0 ? "   " + counts.getOrDefault(value, 0) : ""));
                    }
                }
                return l;
            }
        });
        tree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode n = (DefaultMutableTreeNode) tree.getLastSelectedPathComponent();
            if (n != null) {
                List<Model.Node> out = new ArrayList<>();
                collect(n, out);
                onSelect.accept(out);
            }
        });
        JScrollPane sp = new JScrollPane(tree);
        sp.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Theme.LINE));
        add(sp, BorderLayout.CENTER);
    }


    /** Fill `into` with the number of model nodes under each folder; returns the count under n. */
    private static int count(DefaultMutableTreeNode n, Map<DefaultMutableTreeNode, Integer> into) {
        if (n.getUserObject() instanceof Entry en && en.node() != null) {
            return 1;
        }
        int c = 0;
        for (int i = 0; i < n.getChildCount(); i++) {
            c += count((DefaultMutableTreeNode) n.getChildAt(i), into);
        }
        into.put(n, c);
        return c;
    }

    private static void collect(DefaultMutableTreeNode n, List<Model.Node> out) {
        for (Enumeration<?> e = n.depthFirstEnumeration(); e.hasMoreElements() && out.size() < 400; ) {
            DefaultMutableTreeNode k = (DefaultMutableTreeNode) e.nextElement();
            if (k.getUserObject() instanceof Entry en && en.node() != null) {
                out.add(en.node());
            }
        }
    }

    void onSelect(Consumer<List<Model.Node>> c) {
        onSelect = c;
    }

    void setModel(Model m) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(new Entry("root", null));
        Map<DefaultMutableTreeNode, Map<String, DefaultMutableTreeNode>> folders = new java.util.IdentityHashMap<>();
        if (m != null) {
            List<Model.Node> nodes = new ArrayList<>();
            for (Model.Node n : m.nodes.values()) {
                if ((n.type.equals("endpoint") || n.type.equals("route")) && n.attrs.get("host") != null && n.attrs.get("path") != null) {
                    nodes.add(n);
                }
            }
            nodes.sort(Comparator.comparing((Model.Node n) -> String.valueOf(n.attrs.get("host"))).thenComparing(n -> String.valueOf(n.attrs.get("path")))
                    .thenComparing(n -> String.valueOf(n.attrs.get("method"))));
            for (Model.Node n : nodes) {
                DefaultMutableTreeNode cur = child(folders, root, String.valueOf(n.attrs.get("host")));
                String path = String.valueOf(n.attrs.get("path")).split("\\?", 2)[0];
                for (String seg : path.split("/")) {
                    if (!seg.isEmpty()) {
                        cur = child(folders, cur, seg);
                    }
                }
                DefaultMutableTreeNode leaf = new DefaultMutableTreeNode(new Entry(n.label, n));
                int at = 0;
                while (at < cur.getChildCount() && ((DefaultMutableTreeNode) cur.getChildAt(at)).isLeaf()) {
                    at++;
                }
                cur.insert(leaf, at);
            }
        }
        Map<DefaultMutableTreeNode, Integer> c = new java.util.IdentityHashMap<>();
        count(root, c);
        counts = c;
        tree.setModel(new DefaultTreeModel(root));
        for (int i = 0; i < Math.min(tree.getRowCount(), 12); i++) {
            tree.expandRow(i);
        }
    }

    /** The folder `label` under parent, made if missing; looked up in a map, not by scanning the children. */
    private static DefaultMutableTreeNode child(Map<DefaultMutableTreeNode, Map<String, DefaultMutableTreeNode>> folders, DefaultMutableTreeNode parent, String label) {
        return folders.computeIfAbsent(parent, k -> new java.util.HashMap<>()).computeIfAbsent(label, k -> {
            DefaultMutableTreeNode c = new DefaultMutableTreeNode(new Entry(label, null));
            parent.add(c);
            return c;
        });
    }
}
