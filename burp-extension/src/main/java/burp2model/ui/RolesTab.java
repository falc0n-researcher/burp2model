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
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/** Roles: what each account reached, compared. */
final class RolesTab implements Tab {
    private final MainPanel app;
    private final JComboBox<String> lowBox = new JComboBox<>();
    private final JComboBox<String> highBox = new JComboBox<>();
    private final DefaultTableModel rolesModel = Tables.model("Kind", "Endpoint", "Statuses", "Unknown", "Next");
    private final JTable rolesTable = Tables.table(rolesModel);
    private final JLabel rolesNote = new JLabel(" ");
    private final EvidenceViewer rolesViewer = new EvidenceViewer();
    private final List<List<Integer>> rolesEvidence = new ArrayList<>();
    private final Component view;

    RolesTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        rolesViewer.setModel(m);
        fillRoles(m);
    }

    private Component build() {
        JPanel top = toolbar();
        top.add(new JLabel("Lower-privilege role"));
        top.add(lowBox);
        top.add(new JLabel("Higher-privilege role"));
        top.add(highBox);
        JButton go = new JButton("Compare");
        top.add(go);
        go.addActionListener(e -> compareRoles());
        rolesTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int i = Tables.selected(rolesTable);
            if (i >= 0 && i < rolesEvidence.size()) {
                rolesViewer.show(rolesEvidence.get(i), String.valueOf(rolesModel.getValueAt(i, 1)));
            }
        });
        Tables.render(rolesTable, "Endpoint", Renderers.path());
        Tables.render(rolesTable, "Statuses", Renderers.codes());
        Tables.widths(rolesTable, 200, 340, 160, 300, 340);
        rolesNote.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        rolesNote.setForeground(Theme.MUTED);
        JPanel head = new JPanel(new BorderLayout());
        head.add(top, BorderLayout.NORTH);
        head.add(rolesNote, BorderLayout.SOUTH);
        JSplitPane sp = split(JSplitPane.VERTICAL_SPLIT, scroll(rolesTable), rolesViewer, 0.45);
        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    @SuppressWarnings("unchecked")
    private void compareRoles() {
        Model m = app.model();
        rolesModel.setRowCount(0);
        rolesEvidence.clear();
        if (m == null || lowBox.getSelectedItem() == null || highBox.getSelectedItem() == null || m.roles.size() < 2) {
            rolesNote.setText("Send requests under at least two roles first: set a role in Settings before each send.");
            return;
        }
        Map<String, Object> r = Analysis.crossRole(m, (String) lowBox.getSelectedItem(), (String) highBox.getSelectedItem());
        String[][] sections = {{"low_reached_privileged", "Low role reached a privileged-looking path"}, {"high_only", "Only the high role reached it"},
            {"shared_same_success", "Both roles got 2xx"}};
        int n = 0;
        for (String[] s : sections) {
            for (Object o : (List<Object>) r.get(s[0])) {
                Map<String, Object> e = (Map<String, Object>) o;
                rolesModel.addRow(new Object[] {s[1], e.get("endpoint"), Cells.text(e.get("statuses")), e.get("unknown"), e.get("next")});
                List<Integer> ev = new ArrayList<>();
                for (Object x : (List<Object>) e.get("evidence")) {
                    ev.add(((Number) x).intValue());
                }
                rolesEvidence.add(ev);
                n++;
            }
        }
        rolesNote.setText(n + " things to compare. Each is a hypothesis to verify, not a finding.");
    }

    /** How privileged a role name sounds: anonymous and guests lowest, administrators highest, anything else between. */
    static int rank(String role) {
        String r = role.toLowerCase(java.util.Locale.ROOT);
        if (r.matches(".*(anon|guest|public|visitor|unauth|none).*")) {
            return 0;
        }
        if (r.matches(".*(root|super|admin|owner|staff|internal|ops|manager|moderator|support).*")) {
            return 3;
        }
        if (r.matches(".*(user|member|customer|client|basic|viewer|reader|free).*")) {
            return 1;
        }
        return 2;
    }

    private void fillRoles(Model m) {
        Object low = lowBox.getSelectedItem();
        Object high = highBox.getSelectedItem();
        lowBox.removeAllItems();
        highBox.removeAllItems();
        if (m != null) {
            for (String r : m.roles) {
                lowBox.addItem(r);
                highBox.addItem(r);
            }
            if (low != null && high != null) {
                lowBox.setSelectedItem(low);
                highBox.setSelectedItem(high);
            } else if (m.roles.size() > 1) {
                // first time: guess which is the lower role from its name (guest < user < admin), not the alphabet
                List<String> byRank = new ArrayList<>(m.roles);
                byRank.sort(java.util.Comparator.comparingInt(RolesTab::rank).thenComparing(r -> r));
                lowBox.setSelectedItem(byRank.get(0));
                highBox.setSelectedItem(byRank.get(byRank.size() - 1));
            }
        }
        if (m == null || m.roles.size() < 2) {
            rolesNote.setText("Comparing roles needs requests sent under two roles. Set a role in Settings (for example user), send that account's requests, "
                    + "change it (for example admin), and send the other account's.");
        } else {
            compareRoles();
        }
    }
}
