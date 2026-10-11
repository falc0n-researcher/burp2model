package burp2model.ui;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;

/** The redacted request and response behind a node, edge or query row. Evidence ids on the left, text on the right. */
final class EvidenceViewer extends JPanel {
    private final DefaultListModel<String> list = new DefaultListModel<>();
    private final JList<String> ids = new JList<>(list);
    private final JTextArea req = area();
    private final JTextArea resp = area();
    private final JLabel title = new JLabel(" ");
    private Model model;
    private final List<Integer> current = new ArrayList<>();

    EvidenceViewer() {
        super(new BorderLayout());
        ids.setVisibleRowCount(6);
        ids.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                show(ids.getSelectedIndex());
            }
        });
        JPanel panes = new JPanel(new GridLayout(1, 2, 6, 0));
        panes.add(wrap(req, "Request (values masked)"));
        panes.add(wrap(resp, "Response (values masked)"));
        JScrollPane idScroll = new JScrollPane(ids);
        idScroll.setBorder(new TitledBorder("Evidence"));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, idScroll, panes);
        split.setResizeWeight(0.0);
        split.setDividerLocation(120);
        add(title, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    private static JTextArea area() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(Tables.mono());
        a.setLineWrap(true);
        a.setWrapStyleWord(false);
        return a;
    }

    private static JScrollPane wrap(JTextArea a, String name) {
        JScrollPane s = new JScrollPane(a);
        s.setBorder(new TitledBorder(name));
        return s;
    }

    void setModel(Model m) {
        this.model = m;
        clear();
    }

    void clear() {
        list.clear();
        current.clear();
        req.setText("");
        resp.setText("");
        title.setText(" ");
    }

    /** Show these evidence ids; the first is selected. */
    void show(List<Integer> evidence, String heading) {
        current.clear();
        list.clear();
        for (int i : evidence) {
            current.add(i);
            list.addElement("ev_" + i);
        }
        title.setText(heading == null ? " " : heading);
        if (!current.isEmpty()) {
            ids.setSelectedIndex(0);
        } else {
            req.setText("");
            resp.setText("No request is behind this: the code names it, but it was never captured.");
        }
    }

    @SuppressWarnings("unchecked")
    private void show(int idx) {
        if (idx < 0 || idx >= current.size() || model == null) {
            return;
        }
        int want = current.get(idx);
        for (Map<String, Object> ev : model.evidenceLog) {
            if (((Number) ev.get("id")).intValue() == want) {
                req.setText(format((Map<String, Object>) ev.get("request")));
                resp.setText(format((Map<String, Object>) ev.get("response")));
                req.setCaretPosition(0);
                resp.setCaretPosition(0);
                return;
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static String format(Map<String, Object> m) {
        if (m == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(String.valueOf(m.getOrDefault("line", ""))).append('\n');
        for (Object h : (List<Object>) m.getOrDefault("headers", List.of())) {
            List<Object> kv = (List<Object>) h;
            sb.append(kv.get(0)).append(": ").append(kv.get(1)).append('\n');
        }
        String body = String.valueOf(m.getOrDefault("body", ""));
        if (!body.isEmpty()) {
            sb.append('\n').append(body);
        }
        if (Boolean.TRUE.equals(m.get("truncated"))) {
            sb.append("\n… (cut off)");
        }
        return sb.toString();
    }
}
