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
            label.setForeground(Theme.muted());
            JPanel box = new JPanel(new BorderLayout());
            box.setOpaque(false);
            box.add(number, BorderLayout.CENTER);
            box.add(label, BorderLayout.SOUTH);
            add(box, BorderLayout.CENTER);
            setPreferredSize(new Dimension(150, 76));
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
            setPreferredSize(new Dimension(300, 64));
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
            setPreferredSize(new Dimension(fm.stringWidth(text) + 30, 24));
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
        l.setForeground(Theme.muted());
        return l;
    }
}
