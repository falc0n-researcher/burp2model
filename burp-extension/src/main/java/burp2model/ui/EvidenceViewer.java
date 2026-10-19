package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;

/** The redacted request and response behind a node, edge or query row: evidence ids at the left, the two messages beside them. */
final class EvidenceViewer extends JPanel {
    private final DefaultListModel<Integer> list = new DefaultListModel<>();
    private final JList<Integer> ids = new JList<>(list);
    private MessageView req = new HttpPane("Request");
    private MessageView resp = new HttpPane("Response");
    private MessageEditors editors;
    private final JSplitPane panes;
    private final JLabel title = new JLabel(" ");
    private Model model;
    private final List<Integer> current = new ArrayList<>();

    EvidenceViewer() {
        super(new BorderLayout());
        ids.setFont(Theme.mono(12f));
        ids.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean sel, boolean focus) {
                JLabel c = (JLabel) super.getListCellRendererComponent(l, v, i, sel, focus);
                int id = (Integer) v;
                Map<String, Object> ev = meta(id);
                String label = "ev_" + id;
                if (ev != null) {
                    label += "  " + ev.get("method") + " " + (ev.get("status") == null ? "" : ev.get("status"));
                }
                c.setText(label);
                c.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
                return c;
            }
        });
        ids.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                show(ids.getSelectedIndex());
            }
        });
        title.setFont(Theme.font(12f, Font.BOLD));
        title.setBorder(BorderFactory.createEmptyBorder(6, 10, 4, 10));
        panes = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req.view(), resp.view());
        panes.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean done;

            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!done && panes.getWidth() > 50) {
                    done = true;
                    panes.setDividerLocation(0.5);
                }
            }
        });
        panes.setResizeWeight(0.5);
        panes.setBorder(null);
        JScrollPane idScroll = new JScrollPane(ids);
        idScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Theme.LINE));
        idScroll.setPreferredSize(new java.awt.Dimension(150, 100));
        JPanel body = new JPanel(new BorderLayout());
        body.add(idScroll, BorderLayout.WEST);
        body.add(panes, BorderLayout.CENTER);
        add(title, BorderLayout.NORTH);
        add(body, BorderLayout.CENTER);
    }

    /** Show requests and responses in Burp's message editors, or (null) in burp2model's own panes. */
    void useEditors(MessageEditors e) {
        if (e == editors) {
            return;
        }
        editors = e;
        req = e == null ? new HttpPane("Request") : new BurpMessagePane("Request", e.request());
        resp = e == null ? new HttpPane("Response") : new BurpMessagePane("Response", e.response());
        int at = panes.getDividerLocation();
        panes.setLeftComponent(req.view());
        panes.setRightComponent(resp.view());
        panes.setDividerLocation(at);
        int sel = ids.getSelectedIndex();
        if (sel >= 0) {
            show(sel);
        } else {
            req.clear("Select something above to see the request behind it.");
            resp.clear("");
        }
    }

    boolean usesEditors() {
        return editors != null;
    }

    void setModel(Model m) {
        this.model = m;
        clear();
    }

    void clear() {
        list.clear();
        current.clear();
        req.clear("Select something above to see the request behind it.");
        resp.clear("");
        title.setText(" ");
    }

    /** Show these evidence ids; the first is selected. */
    void show(List<Integer> evidence, String heading) {
        current.clear();
        list.clear();
        // real requests first; the page or script that merely names the thing comes after
        List<Integer> ordered = new ArrayList<>(evidence);
        ordered.sort(java.util.Comparator.comparingInt(this::codeRank));
        for (int i : ordered) {
            current.add(i);
            list.addElement(i);
        }
        title.setText(heading == null || heading.isBlank() ? " " : heading);
        if (!current.isEmpty()) {
            ids.setSelectedIndex(0);
        } else {
            req.clear("Named in the code, never captured: there is no request or response to show.");
            resp.clear("");
        }
    }

    private int codeRank(int id) {
        Map<String, Object> ev = meta(id);
        String mime = ev == null ? "" : String.valueOf(ev.get("mime")).toLowerCase();
        return mime.equals("script") || mime.equals("html") ? 1 : 0;
    }

    private Map<String, Object> find(int id) {
        return model == null ? null : model.evidenceLog.byId(id);
    }

    /** The small fields only: enough to label a list row without unpacking its request and response. */
    private Map<String, Object> meta(int id) {
        if (model == null) {
            return null;
        }
        int i = model.evidenceLog.indexOfId(id);
        return i < 0 ? null : model.evidenceLog.meta(i);
    }

    @SuppressWarnings("unchecked")
    private void show(int idx) {
        if (idx < 0 || idx >= current.size()) {
            return;
        }
        Map<String, Object> ev = find(current.get(idx));
        if (ev == null) {
            return;
        }
        req.show((Map<String, Object>) ev.get("request"));
        resp.show((Map<String, Object>) ev.get("response"));
    }
}
