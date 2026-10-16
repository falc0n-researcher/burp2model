package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.table.DefaultTableModel;

/** Surface: endpoints, pages, scripts, third parties and the rest, as a list or a site map by path. */
final class SurfaceTab implements Tab {
    private final MainPanel app;
    private final JComboBox<String> typeBox = new JComboBox<>(new String[] {"endpoint", "route", "script", "third_party", "cookie", "auth", "parameter",
        "host", "tech", "operation", "role", "all"});
    private final JTextField surfaceFilter = new JTextField(22);
    private final DefaultTableModel surfaceModel = Tables.model("Type", "Name", "State", "Statuses", "Roles", "Requests", "Host");
    private final JTable surfaceTable = Tables.table(surfaceModel);
    private final SiteTree siteTree = new SiteTree();
    private final Facts surfaceFacts = new Facts();
    private final EvidenceViewer surfaceViewer = new EvidenceViewer();
    private final List<Model.Node> surfaceRows = new ArrayList<>();
    private final JPanel surfaceCards = new JPanel(new java.awt.CardLayout());
    private final Component view;

    SurfaceTab(MainPanel app) {
        this.app = app;
        this.view = build();
        surfaceFacts.onNode(app::goToNode);
    }

    /** Search the whole surface (the header's search box). */
    void search(String text) {
        typeBox.setSelectedItem("all");
        surfaceFilter.setText(text);
        showSurfaceList(true);
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        surfaceViewer.setModel(m);
        siteTree.setModel(m);
        fillSurface();
    }

    private Component build() {
        JPanel top = toolbar();
        top.add(new JLabel("Show"));
        top.add(typeBox);
        top.add(new JLabel("Filter"));
        top.add(surfaceFilter);
        JToggleButton list = new JToggleButton("List", true);
        JToggleButton tree = new JToggleButton("Site map");
        ButtonGroup bg = new ButtonGroup();
        bg.add(list);
        bg.add(tree);
        list.addActionListener(e -> showSurfaceList(true));
        tree.addActionListener(e -> showSurfaceList(false));
        top.add(list);
        top.add(tree);
        typeBox.addActionListener(e -> fillSurface());
        surfaceFilter.getDocument().addDocumentListener(debounced(150, () -> Tables.filter(surfaceTable, surfaceFilter.getText())));
        surfaceTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(surfaceTable);
            if (i >= 0 && i < surfaceRows.size()) {
                Model.Node n = surfaceRows.get(i);
                surfaceViewer.show(n.evidence, n.label);
                surfaceFacts.show(n, app.model());
            }
        });
        siteTree.onSelect(nodes -> {
            if (nodes.size() == 1) {
                surfaceFacts.show(nodes.get(0), app.model());
                surfaceViewer.show(nodes.get(0).evidence, nodes.get(0).label);
            } else if (!nodes.isEmpty()) {
                java.util.Set<Integer> ev = new java.util.TreeSet<>();
                nodes.forEach(n -> ev.addAll(n.evidence));
                surfaceFacts.showText(nodes.size() + " things under this path", "Pick one to see its facts. The requests behind all of them are listed below.");
                surfaceViewer.show(new ArrayList<>(ev).subList(0, Math.min(300, ev.size())), nodes.size() + " things");
            }
        });
        Tables.render(surfaceTable, "Type", Renderers.type());
        Tables.render(surfaceTable, "Name", Renderers.path());
        Tables.render(surfaceTable, "State", Renderers.state());
        Tables.widths(surfaceTable, 100, 420, 120, 90, 90, 80, 200);
        surfaceCards.add(scroll(surfaceTable), "list");
        surfaceCards.add(siteTree, "tree");
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(masterDetail(surfaceCards, surfaceFacts, surfaceViewer, 0.5), BorderLayout.CENTER);
        return p;
    }

    private void showSurfaceList(boolean list) {
        ((java.awt.CardLayout) surfaceCards.getLayout()).show(surfaceCards, list ? "list" : "tree");
    }

    private void fillSurface() {
        Model m = app.model();
        surfaceRows.clear();
        List<Object[]> rows = new ArrayList<>();
        if (m != null) {
            String type = (String) typeBox.getSelectedItem();
            List<Model.Node> ns = new ArrayList<>();
            for (Model.Node n : m.nodes.values()) {
                if ("all".equals(type) ? !n.type.equals("parameter") || surfaceFilter.getText().length() > 1 : n.type.equals(type)) {
                    ns.add(n);
                }
            }
            java.util.List<String> order = java.util.List.of("host", "route", "endpoint", "script", "third_party", "cookie", "auth", "role", "operation", "tech", "parameter");
            ns.sort(java.util.Comparator.comparingInt((Model.Node n) -> order.indexOf(n.type)).thenComparing(n -> n.label));
            for (Model.Node n : ns) {
                surfaceRows.add(n);
                Object st = n.attrs.get("api_state");
                Object statuses = n.attrs.get("statuses");
                Object reqs = n.attrs.get("requests");
                rows.add(new Object[] {n.type, n.label, st == null ? "" : st, statuses == null ? "" : String.valueOf(statuses).replace("[", "").replace("]", ""),
                        String.join(",", n.roles), reqs == null ? String.valueOf(n.evidence.size()) : String.valueOf(reqs),
                        n.attrs.get("host") == null ? "" : String.valueOf(n.attrs.get("host"))});
            }
        }
        Tables.fill(surfaceModel, rows);
        Tables.filter(surfaceTable, surfaceFilter.getText());
        surfaceViewer.clear();
        surfaceFacts.clear("Select a row, or switch to Site map to browse by path.");
    }

    /** Select a node in the list (a connection link in a facts card, or the map's Open); MainPanel brings the tab forward. */
    void show(String id) {
        Model m = app.model();
        if (m == null || !m.nodes.containsKey(id)) {
            return;
        }
        Model.Node n = m.nodes.get(id);
        typeBox.setSelectedItem(n.type);
        surfaceFilter.setText("");
        showSurfaceList(true);
        for (int i = 0; i < surfaceRows.size(); i++) {
            if (surfaceRows.get(i).id.equals(id)) {
                int v = surfaceTable.convertRowIndexToView(i);
                surfaceTable.setRowSelectionInterval(v, v);
                surfaceTable.scrollRectToVisible(surfaceTable.getCellRect(v, 0, true));
                break;
            }
        }
    }
}
