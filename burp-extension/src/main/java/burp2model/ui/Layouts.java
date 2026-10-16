package burp2model.ui;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/** Layout pieces the tabs share: split panes, toolbars, scroll panes, read-only text, form rows, debounced listeners. */
final class Layouts {
    private Layouts() {}

    /** A split pane with the divider at `weight` of the space, thin and borderless. */
    static JSplitPane split(int orientation, Component a, Component b, double weight) {
        return split(orientation, a, b, weight, weight);
    }

    /** The same, with the divider first at `share` and extra space going `resize` to the first side. */
    static JSplitPane split(int orientation, Component a, Component b, double share, double resize) {
        JSplitPane sp = divide(new JSplitPane(orientation, a, b), share);
        sp.setResizeWeight(resize);
        sp.setBorder(null);
        sp.setDividerSize(5);
        return sp;
    }

    static JTextArea textArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(Theme.mono(12f));
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setMargin(new Insets(10, 14, 10, 14));
        return a;
    }

    /** Master list over a detail row: facts at the right, the request behind it below. */
    /** Put a split's divider at this share the first time it has a size. */
    static <T extends JSplitPane> T divide(T sp, double share) {
        sp.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean done;

            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!done && sp.getWidth() > 50 && sp.getHeight() > 50) {
                    done = true;
                    sp.setDividerLocation(share);
                }
            }
        });
        return sp;
    }

    static JSplitPane masterDetail(Component master, Facts facts, EvidenceViewer viewer, double weight) {
        JSplitPane top = split(JSplitPane.HORIZONTAL_SPLIT, master, facts, 0.72);
        JSplitPane sp = divide(new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, viewer), weight);
        sp.setResizeWeight(weight);
        sp.setBorder(null);
        sp.setDividerSize(5);
        return sp;
    }

    static JPanel toolbar() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.line()));
        return p;
    }

    static JScrollPane scroll(Component c) {
        JScrollPane s = new JScrollPane(c);
        s.setBorder(null);
        if (c instanceof JTable t) {
            s.setColumnHeaderView(t.getTableHeader());          // set now, not when the pane is first shown
        }
        return s;
    }

    static int line(JPanel p, GridBagConstraints c, int row, String label, JTextField f, String hint) {
        c.gridx = 0;
        c.gridy = row;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        p.add(f, c);
        c.gridx = 2;
        JLabel h = Widgets.muted(hint);
        p.add(h, c);
        return row + 1;
    }

    /** A document listener that runs `r` once typing pauses for `ms` (filtering thousands of rows per keystroke lags). */
    static SimpleDoc debounced(int ms, Runnable r) {
        javax.swing.Timer t = new javax.swing.Timer(ms, e -> r.run());
        t.setRepeats(false);
        return new SimpleDoc(t::restart);
    }

    /** A document listener that calls one runnable. */
    static final class SimpleDoc implements javax.swing.event.DocumentListener {
        private final Runnable r;

        SimpleDoc(Runnable r) {
            this.r = r;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            r.run();
        }
    }
}
