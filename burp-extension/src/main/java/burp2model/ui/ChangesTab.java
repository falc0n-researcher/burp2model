package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Diff;
import burp2model.engine.Model;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/** Changes: the builds, and what changed between any two. */
final class ChangesTab implements Tab {
    private final MainPanel app;
    private final DefaultTableModel buildsModel = Tables.model("#", "When (UTC)", "Label", "Nodes", "Edges", "Requests");
    private final JTable buildsTable = Tables.table(buildsModel);
    private final DiffView diffView = new DiffView();
    private final Component view;

    ChangesTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        fillBuilds();
    }

    private Component build() {
        JPanel top = toolbar();
        JButton prev = new JButton("What changed since the previous build");
        JButton sel = new JButton("Compare the selected build with the latest");
        prev.setFocusable(false);
        sel.setFocusable(false);
        top.add(prev);
        top.add(sel);
        top.add(Widgets.muted("Every send is a build. Drift is a change in the surface to understand, never a finding."));
        prev.addActionListener(e -> diffBuilds(app.session() == null ? 0 : app.session().builds().size() - 1, app.session() == null ? 0 : app.session().builds().size()));
        sel.addActionListener(e -> {
            int i = Tables.selected(buildsTable);
            if (i >= 0) {
                diffBuilds((Integer) buildsModel.getValueAt(i, 0), app.session().builds().size());
            }
        });
        Tables.widths(buildsTable, 40, 170, 220, 70, 70, 80);
        buildsTable.setPreferredScrollableViewportSize(new java.awt.Dimension(400, 120));
        JSplitPane sp = split(JSplitPane.VERTICAL_SPLIT, scroll(buildsTable), diffView, 0.2, 0.18);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void diffBuilds(int older, int newer) {
        if (app.session() == null || older < 1 || newer < 2 || older >= newer) {
            diffView.show("Send more requests first: a comparison needs two builds.");
            return;
        }
        Session s = app.session();
        diffView.show("Comparing build " + older + " with build " + newer + "…");
        app.async("Comparing builds…", () -> Diff.formatText(s.diff(older, newer)), diffView::show,
                t -> diffView.show("could not compare: " + MainPanel.messageOf(t)));
    }

    private void fillBuilds() {
        buildsModel.setRowCount(0);
        if (app.session() == null) {
            return;
        }
        for (Session.BuildInfo b : app.session().builds()) {
            buildsModel.addRow(new Object[] {b.id(), b.builtAt().replace('T', ' ').replace("Z", ""), b.label(), b.nodes(), b.edges(), b.requests()});
        }
        if (app.session().builds().size() >= 2) {
            diffBuilds(app.session().builds().size() - 1, app.session().builds().size());
        } else {
            diffView.show(app.session().builds().isEmpty() ? "" : "One build so far. Send more requests and this shows what changed.");
        }
    }
}
