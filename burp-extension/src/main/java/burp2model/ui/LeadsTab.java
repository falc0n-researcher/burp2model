package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Analysis;
import burp2model.engine.Model;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/** To check: the ranked leads, and the open questions ranked by what answering each would add. */
final class LeadsTab implements Tab {
    private final MainPanel app;
    private final DefaultTableModel leadsModel = Tables.model("Severity", "Endpoint", "Why it matters", "Do next");
    private final JTable leadsTable = Tables.table(leadsModel);
    private final Facts leadsFacts = new Facts();
    private final EvidenceViewer leadsViewer = new EvidenceViewer();
    private final DefaultTableModel gapsModel = Tables.model("Value", "Type", "About", "Not known", "Smallest next step");
    private final JTable gapsTable = Tables.table(gapsModel);
    private final JTabbedPane checkTabs = new JTabbedPane();
    private final Component view;

    LeadsTab(MainPanel app) {
        this.app = app;
        this.view = build();
        leadsFacts.onNode(app::goToNode);
    }

    /** Show this lead selected (a click on one in the Overview). */
    void selectLead(Analysis.Lead l) {
        checkTabs.setSelectedIndex(0);
        int idx = app.leads().indexOf(l);
        if (idx >= 0) {
            int v = leadsTable.convertRowIndexToView(idx);
            leadsTable.setRowSelectionInterval(v, v);
            leadsTable.scrollRectToVisible(leadsTable.getCellRect(v, 0, true));
        }
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        leadsViewer.setModel(m);
        fillLeads(m);
        fillGaps(m);
    }

    private Component build() {
        leadsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(leadsTable);
            if (i >= 0 && i < app.leads().size()) {
                Analysis.Lead l = app.leads().get(i);
                leadsFacts.showLead(l);
                leadsViewer.show(l.endpoint().evidence, l.endpoint().label);
            }
        });
        Tables.render(leadsTable, "Severity", Renderers.severity());
        Tables.render(leadsTable, "Endpoint", Renderers.path());
        Tables.widths(leadsTable, 90, 340, 360, 360);
        checkTabs.addTab("Leads", masterDetail(scroll(leadsTable), leadsFacts, leadsViewer, 0.5));
        Tables.render(gapsTable, "Value", Renderers.ids());
        Tables.render(gapsTable, "About", Renderers.path());
        Tables.widths(gapsTable, 60, 230, 300, 320, 360);
        JPanel gaps = new JPanel(new BorderLayout());
        JLabel note = Widgets.muted("Open questions ranked by how much resolving each improves the picture. Absence is a gap in observation, never a statement about the target.");
        note.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        gaps.add(note, BorderLayout.NORTH);
        gaps.add(scroll(gapsTable), BorderLayout.CENTER);
        checkTabs.addTab("Open questions", gaps);
        return checkTabs;
    }

    private void fillLeads(Model m) {
        List<Object[]> rows = new ArrayList<>();
        for (Analysis.Lead l : app.leads()) {
            Analysis.Signal s = l.signals().get(0);
            String sev = l.sev().equals("hot") ? "High" : l.sev().equals("warn") ? "Medium" : "Note";
            rows.add(new Object[] {sev, l.endpoint().label, s.title() + (l.signals().size() > 1 ? "  (+" + (l.signals().size() - 1) + " more)" : ""), s.next()});
        }
        Tables.fill(leadsModel, rows);
        leadsViewer.clear();
        leadsFacts.clear("Select a lead to see why it matters.");
    }

    private void fillGaps(Model m) {
        List<Object[]> rows = new ArrayList<>();
        if (m != null) {
            for (Map<String, Object> g : Analysis.gaps(m)) {
                rows.add(new Object[] {String.valueOf(g.get("leverage")), g.get("type"), g.get("entity"), g.get("unknown"), g.get("next")});
            }
        }
        Tables.fill(gapsModel, rows);
    }
}
