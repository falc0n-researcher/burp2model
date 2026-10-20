package burp2model.ui;

import java.awt.FlowLayout;
import java.awt.Font;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.Timer;

/** The bar above the map: which node types show, code-only, groups, labels, the two layouts, Find, Fit, Re-layout and PNG. */
final class GraphToolbar extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String[][] GROUPS = {
        {"Hosts", "host"}, {"Pages", "route"}, {"Scripts", "script"}, {"Endpoints", "endpoint,operation"}, {"Parameters", "parameter"},
        {"Third parties", "third_party"}, {"Trust", "cookie,auth,role"}, {"Tech", "tech"}};

    /** What the buttons do. */
    interface Actions {
        /** The shown types, code-only or grouping changed. */
        void rebuild();

        void repaint();

        void setFlow(boolean flow);

        /** Find the next match; `fresh` when the text changed since the last find. */
        void find(boolean fresh);

        void fit();

        void relayout();

        void savePng();
    }

    private final Map<String, JCheckBox> toggles = new LinkedHashMap<>();
    final JTextField search = new JTextField(14);
    final JToggleButton networkBtn = new JToggleButton("Network", true);
    final JToggleButton flowBtn = new JToggleButton("Flow");
    final JCheckBox codeOnly = new JCheckBox("Only code-named");
    final JCheckBox labelsBox = new JCheckBox("Labels", true);
    /** Large maps show each host's path areas as groups; double-click opens one. */
    final JCheckBox groupBox = new JCheckBox("Group", true);
    private final Timer findLater;

    GraphToolbar(Actions act) {
        super(new FlowLayout(FlowLayout.LEFT, 6, 3));
        for (String[] g : GROUPS) {
            // parameters, tech and trust (roles, cookies, credentials) are off at first: each links to most of the map
            // and turns it into a ball of lines; one click brings any of them back
            JCheckBox c = new JCheckBox(g[0], !g[0].equals("Parameters") && !g[0].equals("Tech") && !g[0].equals("Trust"));
            c.setFont(Theme.font(11f, Font.PLAIN));
            c.addActionListener(e -> act.rebuild());
            toggles.put(g[1], c);
            add(c);
        }
        codeOnly.setFont(Theme.font(11f, Font.PLAIN));
        codeOnly.setToolTipText("Show only endpoints the code names but nothing called, with what names them");
        codeOnly.addActionListener(e -> act.rebuild());
        labelsBox.setFont(Theme.font(11f, Font.PLAIN));
        labelsBox.addActionListener(e -> act.repaint());
        groupBox.setFont(Theme.font(11f, Font.PLAIN));
        groupBox.setToolTipText("On a large map, show each host's path areas as groups (double-click a group to open it)");
        groupBox.addActionListener(e -> act.rebuild());
        add(codeOnly);
        add(groupBox);
        add(labelsBox);
        ButtonGroup bg = new ButtonGroup();
        bg.add(networkBtn);
        bg.add(flowBtn);
        for (JToggleButton b : new JToggleButton[] {networkBtn, flowBtn}) {
            b.setFont(Theme.font(11f, Font.PLAIN));
            b.setMargin(new java.awt.Insets(1, 8, 1, 8));
            add(b);
        }
        networkBtn.setToolTipText("Force-directed: connected things sit near each other");
        flowBtn.setToolTipText("Left to right: host, pages, scripts, endpoints, then the rest");
        networkBtn.addActionListener(e -> act.setFlow(false));
        flowBtn.addActionListener(e -> act.setFlow(true));
        search.setToolTipText("Find a node (Enter for the next match)");
        search.putClientProperty("JTextField.placeholderText", "Find…");
        // finding selects the match, which loads its facts and request: wait until typing pauses
        findLater = new Timer(200, e -> act.find(true));
        findLater.setRepeats(false);
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                findLater.restart();
            }
        });
        search.addActionListener(e -> {
            boolean pending = findLater.isRunning();
            findLater.stop();
            act.find(pending);
        });
        add(search);
        add(button("Fit", "Fit everything on screen (F)", act::fit));
        add(button("Re-layout", "Forget positions and lay the map out again", act::relayout));
        add(button("PNG", "Save the map as an image", act::savePng));
        setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE));
    }

    private static JButton button(String text, String tip, Runnable r) {
        JButton b = new JButton(text);
        b.setFont(Theme.font(11f, Font.PLAIN));
        b.setMargin(new java.awt.Insets(1, 8, 1, 8));
        b.setToolTipText(tip);
        b.addActionListener(e -> r.run());
        return b;
    }

    /** The node types whose box is ticked. */
    Set<String> types() {
        Set<String> types = new HashSet<>();
        toggles.forEach((k, c) -> {
            if (c.isSelected()) {
                for (String t : k.split(",")) {
                    types.add(t);
                }
            }
        });
        return types;
    }

    /** Show which layout is drawn, however it was switched. */
    void showFlow(boolean flow) {
        networkBtn.setSelected(!flow);
        flowBtn.setSelected(flow);
    }

    void stop() {
        findLater.stop();
    }
}
