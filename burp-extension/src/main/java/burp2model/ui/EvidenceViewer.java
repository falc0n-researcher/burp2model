package burp2model.ui;

import burp2model.engine.Model;
import burp2model.engine.Parse;
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
    /** Whether the panes show the masked copy or the request as Burp captured it. */
    private final JLabel source = new JLabel(" ");
    private final java.awt.CardLayout cards = new java.awt.CardLayout();
    private final JPanel cardPanel = new JPanel(cards);
    private final JLabel emptyHint = new JLabel(" ", javax.swing.SwingConstants.CENTER);
    /** Where the real request comes from (null: always masked), and how to look it up off the Swing thread. */
    private java.util.function.IntFunction<byte[][]> captured;
    private java.util.function.Consumer<Runnable> background;
    private int showing;
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
        // before anything is picked, one quiet line instead of two empty panes
        emptyHint.setForeground(Theme.MUTED);
        emptyHint.setFont(Theme.font(12f, Font.PLAIN));
        cardPanel.add(emptyHint, "empty");
        cardPanel.add(body, "panes");
        source.setFont(Theme.font(11f, Font.PLAIN));
        source.setForeground(Theme.MUTED);
        source.setBorder(BorderFactory.createEmptyBorder(6, 10, 4, 12));
        JPanel head = new JPanel(new BorderLayout());
        head.add(title, BorderLayout.CENTER);
        head.add(source, BorderLayout.EAST);
        head.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.LINE));
        add(head, BorderLayout.NORTH);
        add(cardPanel, BorderLayout.CENTER);
        empty("Select a row above to see its request and response.");
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
        req.clear("");
        resp.clear("");
        title.setText(" ");
        empty("Select a row above to see its request and response.");
    }

    private void empty(String hint) {
        showing++;
        source.setText(" ");
        emptyHint.setText(hint);
        cards.show(cardPanel, "empty");
    }

    /**
     * Show the request as Burp captured it (real cookies and tokens) when `captured` finds it, else the masked copy.
     * The real values are only shown, never stored. Null turns it off.
     */
    void useCaptured(java.util.function.IntFunction<byte[][]> captured, java.util.function.Consumer<Runnable> background) {
        this.captured = captured;
        this.background = background;
        int sel = ids.getSelectedIndex();
        if (sel >= 0) {
            show(sel);
        }
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
            cards.show(cardPanel, "panes");
            ids.setSelectedIndex(0);
        } else {
            empty("Named in the code, never captured: there is no request or response to show.");
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
        int id = current.get(idx);
        Map<String, Object> ev = find(id);
        if (ev == null) {
            return;
        }
        cards.show(cardPanel, "panes");
        req.show((Map<String, Object>) ev.get("request"));
        resp.show((Map<String, Object>) ev.get("response"));
        int ticket = ++showing;
        if (captured == null) {
            source.setText("masked");
            source.setToolTipText("Secrets are masked in what burp2model stores.");
            return;
        }
        source.setText("masked · looking it up in Burp…");
        java.util.function.IntFunction<byte[][]> from = captured;
        background.accept(() -> {
            byte[][] raw;
            try {
                raw = from.apply(id);
            } catch (RuntimeException e) {
                raw = null;
            }
            byte[][] got = raw;
            javax.swing.SwingUtilities.invokeLater(() -> {
                if (ticket != showing) {
                    return;                                     // another row was picked meanwhile
                }
                if (got == null) {
                    source.setText("masked: not in Burp's history any more");
                    source.setToolTipText("Requests from an imported file, or removed from Burp's history, are shown as stored: masked.");
                    return;
                }
                req.show(Parse.plain(got[0]));
                resp.show(Parse.plain(got[1]));
                source.setText("as captured: real values from Burp, not saved");
                source.setToolTipText("Shown from Burp's own copy. burp2model stores, exports and copies for AI only the masked version.");
            });
        });
    }
}
