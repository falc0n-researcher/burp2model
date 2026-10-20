package burp2model.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.geom.RoundRectangle2D;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Small custom-painted pieces: cards, number tiles, stacked bars and chips. */
final class Widgets {
    private Widgets() {}

    /** A rounded surface with a thin border; children sit inside it. */
    static class Card extends JPanel {
        Card(int pad) {
            super(new BorderLayout());
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(pad, pad + 2, pad, pad + 2));
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.quality(g);
            RoundRectangle2D r = new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 12, 12);
            g.setColor(Theme.surface());
            g.fill(r);
            g.setColor(Theme.line());
            g.draw(r);
            g.dispose();
            super.paintComponent(g0);
        }
    }

    /** A big number over a small label, with an optional coloured edge. */
    static final class Tile extends Card {
        private final JLabel number = new JLabel("0");
        private final JLabel label = new JLabel("");
        private Color accent;

        Tile(String text, Color accent) {
            super(10);
            this.accent = accent;
            number.setFont(Theme.font(26f, Font.BOLD));
            number.setForeground(accent == null ? Theme.fg() : accent);
            label.setText(text);
            label.setFont(Theme.font(11f, Font.PLAIN));
            label.setForeground(Theme.MUTED);
            JPanel box = new JPanel(new BorderLayout());
            box.setOpaque(false);
            box.add(number, BorderLayout.CENTER);
            box.add(label, BorderLayout.SOUTH);
            add(box, BorderLayout.CENTER);
            setPreferredSize(new Dimension(Math.round(150 * Theme.uiScale()), Math.round(76 * Theme.uiScale())));
        }

        void set(Object value) {
            number.setText(String.valueOf(value));
        }

        @Override
        protected void paintComponent(Graphics g0) {
            super.paintComponent(g0);
            if (accent != null) {
                Graphics2D g = (Graphics2D) g0.create();
                g.setColor(accent);
                g.fillRoundRect(0, 10, 3, getHeight() - 20, 3, 3);
                g.dispose();
            }
        }
    }

    /** One horizontal bar split into coloured segments, with a legend underneath. */
    static final class Bar extends JComponent {
        record Seg(String name, long value, Color color) {}

        private List<Seg> segs = List.of();

        Bar() {
            setPreferredSize(new Dimension(Math.round(300 * Theme.uiScale()), Math.round(64 * Theme.uiScale())));
        }

        void set(List<Seg> s) {
            segs = s;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.quality(g);
            long total = segs.stream().mapToLong(Seg::value).sum();
            int w = getWidth();
            int y = 4;
            int h = 14;
            g.setColor(Theme.surface2());
            g.fill(new RoundRectangle2D.Float(0, y, w, h, h, h));
            if (total > 0) {
                g.setClip(new RoundRectangle2D.Float(0, y, w, h, h, h));
                float x = 0;
                for (Seg s : segs) {
                    float sw = (float) s.value() / total * w;
                    g.setColor(s.color());
                    g.fillRect(Math.round(x), y, Math.round(sw) + 1, h);
                    x += sw;
                }
                g.setClip(null);
            }
            g.setFont(Theme.font(11f, Font.PLAIN));
            FontMetrics fm = g.getFontMetrics();
            int lx = 0;
            int ly = y + h + 8;
            for (Seg s : segs) {
                if (s.value() == 0) {
                    continue;
                }
                g.setColor(s.color());
                g.fillOval(lx, ly + 3, 8, 8);
                String t = s.name() + "  " + s.value();
                g.setColor(Theme.fg());
                g.drawString(t, lx + 13, ly + fm.getAscent());
                lx += 13 + fm.stringWidth(t) + 18;
                if (lx > w - 80) {
                    lx = 0;
                    ly += 16;
                }
            }
            g.dispose();
        }
    }

    /** A rounded tag with a coloured dot, for a technology or a role. */
    static final class Chip extends JComponent {
        private final String text;
        private final Color color;

        Chip(String text, Color color) {
            this.text = text;
            this.color = color;
            setFont(Theme.font(12f, Font.PLAIN));
            FontMetrics fm = getFontMetrics(getFont());
            setPreferredSize(new Dimension(fm.stringWidth(text) + 30, fm.getHeight() + 8));
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.quality(g);
            g.setColor(Theme.surface2());
            g.fillRoundRect(0, 0, getWidth() - 2, getHeight() - 2, 14, 14);
            g.setColor(Theme.line());
            g.drawRoundRect(0, 0, getWidth() - 3, getHeight() - 3, 14, 14);
            g.setColor(color);
            g.fillOval(8, getHeight() / 2 - 4, 8, 8);
            g.setColor(Theme.fg());
            g.setFont(getFont());
            FontMetrics fm = g.getFontMetrics();
            g.drawString(text, 21, (getHeight() + fm.getAscent() - fm.getDescent()) / 2 - 1);
            g.dispose();
        }
    }

    /** Like flow(), but the row wraps and the panel asks for the height of every row (FlowLayout asks for one). */
    static JPanel wrapFlow(int gap) {
        JPanel p = new JPanel(new WrapFlow(gap));
        p.setOpaque(false);
        return p;
    }

    static final class WrapFlow extends FlowLayout {
        private static final long serialVersionUID = 1L;

        WrapFlow(int gap) {
            super(FlowLayout.LEFT, gap, gap);
        }

        @Override
        public Dimension preferredLayoutSize(java.awt.Container target) {
            return size(target, true);
        }

        @Override
        public Dimension minimumLayoutSize(java.awt.Container target) {
            Dimension d = size(target, false);
            d.width -= getHgap() + 1;
            return d;
        }

        private Dimension size(java.awt.Container target, boolean preferred) {
            synchronized (target.getTreeLock()) {
                int width = target.getWidth();
                for (java.awt.Container c = target.getParent(); width == 0 && c != null; c = c.getParent()) {
                    width = c.getWidth();
                }
                java.awt.Insets in = target.getInsets();
                int max = (width == 0 ? Integer.MAX_VALUE : width) - in.left - in.right - getHgap() * 2;
                int w = 0;
                int h = 0;
                int rowW = 0;
                int rowH = 0;
                for (java.awt.Component c : target.getComponents()) {
                    if (!c.isVisible()) {
                        continue;
                    }
                    Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                    if (rowW > 0 && rowW + d.width > max) {
                        w = Math.max(w, rowW);
                        h += rowH + getVgap();
                        rowW = 0;
                        rowH = 0;
                    }
                    rowW += d.width + getHgap();
                    rowH = Math.max(rowH, d.height);
                }
                w = Math.max(w, rowW);
                h += rowH;
                return new Dimension(w + in.left + in.right + getHgap() * 2, h + in.top + in.bottom + getVgap() * 2);
            }
        }
    }

    static JPanel flow(int gap) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, gap, gap));
        p.setOpaque(false);
        return p;
    }

    static JLabel heading(String text) {
        JLabel l = new JLabel(text);
        l.setFont(Theme.font(13f, Font.BOLD));
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        return l;
    }

    static JLabel muted(String text) {
        JLabel l = new JLabel(text);
        l.setFont(Theme.font(11f, Font.PLAIN));
        l.setForeground(Theme.MUTED);
        return l;
    }

    // ------------------------------------------------------------------ text without HTML
    // Swing labels only render HTML when the look and feel allows it, and inside Burp it may not: the markup then
    // shows as text ("<html>…</html>"). These pieces style text with fonts and colours instead.

    /**
     * Read-only text that wraps at its parent's width (less `reserve` for what sits beside it) and asks for the
     * height that wrapping needs.
     */
    static final class WrapText extends javax.swing.JTextArea {
        private static final long serialVersionUID = 1L;
        private final int reserve;

        WrapText(String text, int reserve) {
            super(text);
            this.reserve = reserve;
            setEditable(false);
            setFocusable(false);
            setLineWrap(true);
            setWrapStyleWord(true);
            setOpaque(false);
            setBorder(null);
            setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        }

        @Override
        public Dimension getPreferredSize() {
            java.awt.Container p = getParent();
            if (p != null && p.getWidth() > 0) {
                java.awt.Insets in = p.getInsets();
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

    static WrapText wrapText(String text, Font font, Color fg) {
        WrapText t = new WrapText(text, 0);
        t.setFont(font);
        t.setForeground(fg);
        return t;
    }

    /** A clickable name, underlined, in a blue that reads at 4.5:1 on the card. */
    static JLabel link(String text, Font font) {
        JLabel l = new JLabel(text);
        l.setFont(font.deriveFont(java.util.Map.of(java.awt.font.TextAttribute.UNDERLINE, java.awt.font.TextAttribute.UNDERLINE_ON)));
        l.setForeground(Theme.readable(Theme.BLUE, Theme.surface()));
        l.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        return l;
    }

    /** A menu item with a bold title and a muted line under it, drawn directly. */
    static final class TwoLineItem extends javax.swing.JMenuItem {
        private static final long serialVersionUID = 1L;
        private final String title;
        private final String desc;

        TwoLineItem(String title, String desc) {
            super("");
            this.title = title;
            this.desc = desc;
            getAccessibleContext().setAccessibleName(title);
            getAccessibleContext().setAccessibleDescription(desc);
        }

        private Font titleFont() {
            return Theme.font(12f, Font.BOLD);
        }

        private Font descFont() {
            return Theme.font(11f, Font.PLAIN);
        }

        @Override
        public Dimension getPreferredSize() {
            java.awt.FontMetrics a = getFontMetrics(titleFont());
            java.awt.FontMetrics b = getFontMetrics(descFont());
            return new Dimension(Math.max(a.stringWidth(title), b.stringWidth(desc)) + 36, a.getHeight() + b.getHeight() + 12);
        }

        @Override
        protected void paintComponent(Graphics g0) {
            super.paintComponent(g0);                           // the background, and the highlight when armed
            Graphics2D g = (Graphics2D) g0.create();
            Theme.textHints(g);
            boolean armed = isArmed() || isSelected();
            Color fg = armed ? orDefault(javax.swing.UIManager.getColor("MenuItem.selectionForeground"), Color.WHITE)
                    : orDefault(javax.swing.UIManager.getColor("MenuItem.foreground"), Theme.fg());
            java.awt.FontMetrics a = g.getFontMetrics(titleFont());
            g.setFont(titleFont());
            g.setColor(fg);
            g.drawString(title, 18, 6 + a.getAscent());
            g.setFont(descFont());
            g.setColor(new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 170));
            g.drawString(desc, 18, 6 + a.getHeight() + g.getFontMetrics().getAscent());
            g.dispose();
        }

        private static Color orDefault(Color c, Color d) {
            return c == null ? d : c;
        }
    }
}
