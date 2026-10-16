package burp2model.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;

/**
 * The page a new user lands on: what burp2model is, three steps to a first model, buttons that start one, and what
 * stays private. Display type is pixel art (the bundled Silkscreen and Pixelify Sans); everything meant to be read
 * at length stays in Burp's own font. Shown on first run and whenever the open model is empty.
 */
final class Welcome extends JPanel {
    private static final long serialVersionUID = 1L;

    /** What the buttons do; MainPanel supplies them. */
    interface Actions {
        void sample();

        void importFile();

        void liveCapture();

        void settings();

        void getStarted(boolean showOnStart);
    }

    private final PixelArt.Button live = new PixelArt.Button("Turn on live capture", false, false);
    private final JCheckBox showOnStart = new JCheckBox("Show this page every time Burp starts");
    private final JPanel steps = new JPanel(new GridLayout(1, 3, 14, 14));
    private final JPanel buttons = new JPanel(new GridLayout(2, 2, 12, 12));
    private final PixelArt.Button start = new PixelArt.Button("Get started", true, true);

    Welcome(Actions actions, String version) {
        super(new BorderLayout());
        Column column = new Column();
        column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
        column.setOpaque(false);
        column.setBorder(BorderFactory.createEmptyBorder(28, 24, 28, 24));

        column.add(hero(version));
        column.add(Box.createVerticalStrut(26));
        column.add(label("HOW IT WORKS"));
        column.add(Box.createVerticalStrut(10));
        steps.setOpaque(false);
        steps.add(step("1", "Send", "Right-click requests in Proxy history or the Site map and choose Send to burp2model, "
                + "or let live capture add in-scope traffic as you browse."));
        steps.add(step("2", "Explore", "Ranked leads to check, a map of pages, scripts and endpoints, and every request behind "
                + "them, with secrets masked."));
        steps.add(step("3", "Ask", "Query the model offline in plain words or BQL, or use Copy for AI to hand it to your own "
                + "assistant: every claim cites a request."));
        steps.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(steps);
        column.add(Box.createVerticalStrut(26));
        column.add(label("START HERE"));
        column.add(Box.createVerticalStrut(10));

        PixelArt.Button sample = new PixelArt.Button("Try the sample model", true, false);
        PixelArt.Button importBtn = new PixelArt.Button("Import HAR or Burp XML", false, false);
        PixelArt.Button settings = new PixelArt.Button("Open Settings", false, false);
        sample.setToolTipText("Load a small demo shop (two roles) into a model called 'sample', to look around");
        importBtn.setToolTipText("Add the requests from a HAR file (browser DevTools, ZAP, mitmproxy) or a Burp \"Save items\" export");
        live.setToolTipText("Add in-scope Proxy traffic (Burp's target scope) to the model every few seconds");
        settings.setToolTipText("Model name, role for the next send, scope");
        sample.setMnemonic('T');
        importBtn.setMnemonic('I');
        live.setMnemonic('L');
        settings.setMnemonic('O');
        sample.addActionListener(e -> actions.sample());
        importBtn.addActionListener(e -> actions.importFile());
        live.addActionListener(e -> actions.liveCapture());
        settings.addActionListener(e -> actions.settings());
        buttons.setOpaque(false);
        buttons.add(sample);
        buttons.add(importBtn);
        buttons.add(live);
        buttons.add(settings);
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(buttons);
        column.add(Box.createVerticalStrut(26));
        column.add(label("WHAT STAYS PRIVATE"));
        column.add(Box.createVerticalStrut(8));
        column.add(body("Models are kept on this machine in ~/.burp2model and hold masked requests only: cookies, tokens, keys "
                + "and personal data are replaced before anything is stored. Nothing is sent anywhere, except Recon (only when you "
                + "press it, to the host you name) and what you paste into your own AI. Only capture traffic you are allowed to test.", false));
        column.add(Box.createVerticalStrut(24));

        JPanel foot = new JPanel(new BorderLayout());
        foot.setOpaque(false);
        foot.setAlignmentX(Component.LEFT_ALIGNMENT);
        showOnStart.setOpaque(false);
        showOnStart.setFont(Theme.font(12f, Font.PLAIN));
        showOnStart.setMnemonic('S');
        foot.add(showOnStart, BorderLayout.WEST);
        start.setMnemonic('G');
        start.addActionListener(e -> actions.getStarted(showOnStart.isSelected()));
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setOpaque(false);
        right.add(start);
        foot.add(right, BorderLayout.EAST);
        foot.setMaximumSize(new Dimension(Integer.MAX_VALUE, foot.getPreferredSize().height));
        column.add(foot);

        // a centred column at most 880 wide, scrolling when the pane is small
        JPanel centre = new JPanel(new GridBagLayout()) {
            private static final long serialVersionUID = 1L;

            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                g.setColor(Theme.bg());
                g.fillRect(0, 0, getWidth(), getHeight());
                if (Theme.dark()) {
                    PixelArt.dither(g, getWidth(), getHeight(), 8, Theme.alpha(Theme.fg(), 18));
                }
                g.dispose();
            }
        };
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTH;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.NONE;
        centre.add(column, c);
        Scroller scroller = new Scroller(centre);
        JScrollPane sp = new JScrollPane(scroller);
        sp.setBorder(null);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        add(sp, BorderLayout.CENTER);
        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                reflow();
            }
        });
    }

    /** Three steps side by side, or stacked when the pane is narrow; the same for the buttons. */
    private void reflow() {
        boolean narrow = getWidth() < 720;
        ((GridLayout) steps.getLayout()).setRows(narrow ? 3 : 1);
        ((GridLayout) steps.getLayout()).setColumns(narrow ? 1 : 3);
        ((GridLayout) buttons.getLayout()).setRows(narrow ? 4 : 2);
        ((GridLayout) buttons.getLayout()).setColumns(narrow ? 1 : 2);
        invalidateTree(this);
        revalidate();
        // wrapped text knows its height only once its width is set: measure again after this layout
        javax.swing.SwingUtilities.invokeLater(() -> {
            invalidateTree(this);
            revalidate();
            repaint();
        });
    }

    private static void invalidateTree(java.awt.Container c) {
        c.invalidate();
        for (Component k : c.getComponents()) {
            if (k instanceof java.awt.Container cc) {
                invalidateTree(cc);
            }
        }
    }

    /** Reflect the current state: whether live capture is already on, and the show-on-start choice. */
    void update(boolean liveOn, boolean showEveryStart) {
        live.setText(liveOn ? "Live capture is on" : "Turn on live capture");
        live.setEnabled(!liveOn);
        showOnStart.setSelected(showEveryStart);
        start.requestFocusInWindow();
    }

    private JComponent hero(String version) {
        JPanel card = new JPanel(new GridBagLayout()) {
            private static final long serialVersionUID = 1L;

            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                int px = Math.max(2, Math.round(2 * Theme.uiScale()));
                PixelArt.frame(g, px, px, getWidth() - px, getHeight() - px, px, null, Theme.alpha(Theme.fg(), 30));
                PixelArt.frame(g, 0, 0, getWidth() - px, getHeight() - px, px, Theme.surface(), Theme.line());
                g.setColor(Theme.ACCENT);
                g.fillRect(px, px, 2 * px, getHeight() - 3 * px);            // the accent stripe the header uses too
                g.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(26, 30, 26, 30));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        int px = Math.max(5, Math.round(5 * Theme.uiScale()));
        JLabel mark = new JLabel(new javax.swing.Icon() {
            @Override
            public void paintIcon(Component comp, Graphics g, int x, int y) {
                PixelArt.logo((Graphics2D) g, x, y, px);
            }

            @Override
            public int getIconWidth() {
                return PixelArt.logoSize(px);
            }

            @Override
            public int getIconHeight() {
                return PixelArt.logoSize(px);
            }
        });
        mark.getAccessibleContext().setAccessibleName("burp2model logo");
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.gridheight = 3;
        c.insets = new Insets(0, 0, 0, 26);
        c.anchor = GridBagConstraints.CENTER;
        card.add(mark, c);
        c.gridx = 1;
        c.gridheight = 1;
        c.weightx = 1;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(0, 0, 10, 0);
        card.add(new PixelArt.Text("BURP2MODEL", () -> Theme.pixel(6), () -> Theme.ACCENT), c);
        c.gridy = 1;
        c.insets = new Insets(0, 0, 6, 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        int beside = PixelArt.logoSize(px) + 26;                   // the logo's column, left of the text
        Wrap tag = new Wrap("Turn Burp traffic into an evidence-backed model of the app.", beside);
        tag.setFont(Theme.font(16f, Font.PLAIN));
        card.add(styled(tag, Theme.fg()), c);
        c.gridy = 2;
        c.insets = new Insets(0, 0, 0, 0);
        Wrap meta = new Wrap("Extension " + version + "  ·  works offline  ·  secrets are masked before anything is stored", beside);
        meta.setFont(Theme.font(12f, Font.PLAIN));
        card.add(styled(meta, Theme.muted()), c);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, card.getPreferredSize().height + 4));
        return card;
    }

    private static JComponent step(String n, String title, String text) {
        JPanel card = new JPanel(new BorderLayout(0, 8)) {
            private static final long serialVersionUID = 1L;

            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                int px = Math.max(2, Math.round(2 * Theme.uiScale()));
                PixelArt.frame(g, 0, 0, getWidth(), getHeight(), px, Theme.surface(), Theme.line());
                g.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(16, 18, 18, 18));
        JPanel head = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        head.setOpaque(false);
        head.add(new PixelArt.Text(n, () -> Theme.pixel(3), () -> Theme.ACCENT));
        head.add(Box.createHorizontalStrut(12));
        head.add(new PixelArt.Text(title, () -> Theme.pixelSans(false), Theme::fg));
        card.add(head, BorderLayout.NORTH);
        card.add(body(text, true), BorderLayout.CENTER);
        card.getAccessibleContext().setAccessibleName("Step " + n + ": " + title);
        return card;
    }

    /** A section heading in small pixel capitals. */
    private static JComponent label(String text) {
        PixelArt.Text t = new PixelArt.Text(text, () -> Theme.pixel(2), Theme::muted);
        t.setAlignmentX(Component.LEFT_ALIGNMENT);
        return t;
    }

    /** Wrapped body text in Burp's font. */
    private static JComponent body(String text, boolean small) {
        Wrap a = new Wrap(text, 0);
        a.setFont(Theme.font(small ? 13f : 13.5f, Font.PLAIN));
        return styled(a, Theme.fg());
    }

    private static JComponent styled(Wrap a, java.awt.Color fg) {
        a.setEditable(false);
        a.setFocusable(false);                                  // read-only text: Tab goes to the buttons, not through paragraphs
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setOpaque(false);
        a.setBorder(null);
        a.setForeground(fg);
        a.setAlignmentX(Component.LEFT_ALIGNMENT);
        return a;
    }

    /**
     * A text area whose preferred height is the height of its text wrapped at its parent's width. A plain one
     * asks for one line until it has been laid out once, so the page would cut every paragraph short.
     */
    private static final class Wrap extends javax.swing.JTextArea {
        private static final long serialVersionUID = 1L;

        /** Width taken by siblings beside it in the same parent (the logo in the hero). */
        private final int reserve;

        Wrap(String text, int reserve) {
            super(text);
            this.reserve = reserve;
        }

        @Override
        public Dimension getPreferredSize() {
            java.awt.Container p = getParent();
            if (p != null && p.getWidth() > 0) {
                Insets in = p.getInsets();
                int w = p.getWidth() - in.left - in.right - reserve;
                if (w > 0 && w != getWidth()) {
                    setSize(w, Short.MAX_VALUE);                 // wrap at that width, then measure
                }
            }
            return super.getPreferredSize();
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
        }
    }

    /** The column: tracks the viewport width, so text wraps instead of scrolling sideways. */
    private static final class Column extends JPanel {
        private static final long serialVersionUID = 1L;

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(880, super.getMaximumSize().height);
        }

        /** As wide as the pane allows, up to 880; the height follows from the text wrapped at that width. */
        @Override
        public Dimension getPreferredSize() {
            int avail = getParent() == null || getParent().getWidth() == 0 ? 880 : getParent().getWidth();
            int w = Math.max(360, Math.min(880, avail));
            Dimension d = super.getPreferredSize();
            return new Dimension(w, d.height);
        }
    }

    private static final class Scroller extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;

        Scroller(JComponent inner) {
            super(new BorderLayout());
            add(inner, BorderLayout.CENTER);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle r, int o, int d) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle r, int o, int d) {
            return o == SwingConstants.VERTICAL ? r.height - 32 : r.width;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return getParent() != null && getParent().getHeight() > getPreferredSize().height;
        }
    }
}
