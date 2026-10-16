package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/** Requests: every captured request with its masked request and response. */
final class RequestsTab implements Tab {
    private final MainPanel app;
    private final DefaultTableModel reqModel = Tables.model("#", "Method", "Host", "Path", "Status", "Role");
    private final JTable reqTable = Tables.table(reqModel);
    private final JTextField reqFilter = new JTextField(24);
    private final EvidenceViewer reqViewer = new EvidenceViewer();
    private final Component view;

    RequestsTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        reqViewer.setModel(m);
        fillRequests(m);
    }

    private Component build() {
        JPanel top = toolbar();
        top.add(new JLabel("Filter"));
        top.add(reqFilter);
        top.add(Widgets.muted("method, host, path, status or role"));
        reqFilter.getDocument().addDocumentListener(debounced(150, () -> Tables.filter(reqTable, reqFilter.getText())));
        reqTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(reqTable);
            if (i >= 0) {
                int id = (Integer) reqModel.getValueAt(i, 0);
                reqViewer.show(List.of(id), "ev_" + id);
            }
        });
        Tables.render(reqTable, "Method", Renderers.method());
        Tables.render(reqTable, "Status", Renderers.status());
        Tables.render(reqTable, "Path", Renderers.path());
        Tables.widths(reqTable, 50, 90, 220, 480, 80, 90);
        JSplitPane sp = split(JSplitPane.VERTICAL_SPLIT, scroll(reqTable), reqViewer, 0.45);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void fillRequests(Model m) {
        reqModel.setRowCount(0);
        if (m == null) {
            return;
        }
        List<Object[]> rows = new ArrayList<>(m.evidenceLog.size());
        for (int i = 0; i < m.evidenceLog.size(); i++) {
            Map<String, Object> ev = m.evidenceLog.meta(i);
            String p = m.evidenceLog.path(i);
            rows.add(new Object[] {((Number) ev.get("id")).intValue(), ev.get("method"), ev.get("host"), p.isEmpty() ? ev.get("path") : p,
                    ev.get("status") == null ? "" : String.valueOf(ev.get("status")), ev.get("role") == null ? "" : ev.get("role")});
        }
        Tables.fill(reqModel, rows);
        Tables.filter(reqTable, reqFilter.getText());
    }
}
