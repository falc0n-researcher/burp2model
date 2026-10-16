package burp2model.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.RoundRectangle2D;
import javax.swing.UIManager;

/** Colors and small drawing helpers. Everything follows Burp's light or dark theme; accents are fixed. */
final class Theme {
    private Theme() {}

    static final Color ACCENT = new Color(0xE8, 0x50, 0x02);          // burp orange, the signal colour
    static final Color GREEN = new Color(0x0F, 0xA7, 0x9A);
    static final Color BLUE = new Color(0x1E, 0x88, 0xE5);
    static final Color PURPLE = new Color(0x7A, 0x5C, 0xFF);
    static final Color AMBER = new Color(0xE0, 0x9B, 0x1A);
    static final Color RED = new Color(0xD9, 0x3F, 0x3F);
    static final Color GRAY = new Color(0x8A, 0x93, 0x9E);

    static Color bg() {
        Color c = UIManager.getColor("Panel.background");
        return c == null ? Color.WHITE : c;
    }

    static boolean dark() {
        Color c = bg();
        return (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) < 128;
    }

    static Color fg() {
        Color c = UIManager.getColor("Label.foreground");
        return c == null ? (dark() ? Color.WHITE : Color.BLACK) : c;
    }

    /** The colour of a card or a text pane: a step away from the panel background. */
    static Color surface() {
        return dark() ? shift(bg(), 14) : Color.WHITE;
    }

    static Color surface2() {
        return dark() ? shift(bg(), 26) : shift(bg(), -6);
    }

    static Color line() {
        return dark() ? shift(bg(), 46) : shift(bg(), -26);
    }

    static Color muted() {
        Color f = fg();
        return new Color(f.getRed(), f.getGreen(), f.getBlue(), 150);
    }

    static Color selection() {
        Color c = UIManager.getColor("Table.selectionBackground");
        return c == null ? new Color(0x39, 0x6F, 0xD6) : c;
    }

    /** #rrggbb, for colours inside HTML labels. */
    static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    static Color shift(Color c, int d) {
        return new Color(clamp(c.getRed() + d), clamp(c.getGreen() + d), clamp(c.getBlue() + d));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }

    static Color alpha(Color c, int a) {
        return new Color(c.getRed(), c.getGreen(), c.getBlue(), a);
    }

    /** Burp's UI font at `size` (sizes are written for Burp's default; a larger font setting scales them all). */
    static Font font(float size, int style) {
        Font base = UIManager.getFont("Label.font");
        return (base == null ? new Font(Font.SANS_SERIF, Font.PLAIN, 12) : base).deriveFont(style, size * uiScale());
    }

    /** A row tall enough for `f` with breathing room, never below `min` (also scaled). */
    static int rowHeight(Font f, int min) {
        java.awt.FontMetrics fm = new java.awt.Canvas().getFontMetrics(f);
        return Math.max(Math.round(min * uiScale()), fm.getHeight() + 8);
    }

    // ------------------------------------------------------------------ colours that follow a theme switch

    /**
     * A colour looked up each time it is used. Burp can switch between light and dark while the extension is loaded;
     * a border or label given Theme.line() at startup would keep the old theme's colour, one given LINE does not.
     */
    private static final class Live extends Color {
        private static final long serialVersionUID = 1L;
        private final transient java.util.function.Supplier<Color> of;

        Live(java.util.function.Supplier<Color> of) {
            super(0, true);
            this.of = of;
        }

        @Override
        public int getRGB() {
            return of.get().getRGB();
        }

        @Override
        public int getRed() {
            return of.get().getRed();
        }

        @Override
        public int getGreen() {
            return of.get().getGreen();
        }

        @Override
        public int getBlue() {
            return of.get().getBlue();
        }

        @Override
        public int getAlpha() {
            return of.get().getAlpha();
        }

        @Override
        public int getTransparency() {
            return of.get().getTransparency();
        }
    }

    static final Color LINE = new Live(Theme::line);
    static final Color MUTED = new Live(Theme::muted);
    static final Color SURFACE = new Live(Theme::surface);

    // ------------------------------------------------------------------ contrast

    /** WCAG relative luminance. */
    private static double luminance(Color c) {
        double[] ch = {c.getRed() / 255.0, c.getGreen() / 255.0, c.getBlue() / 255.0};
        for (int i = 0; i < 3; i++) {
            ch[i] = ch[i] <= 0.03928 ? ch[i] / 12.92 : Math.pow((ch[i] + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
    }

    static double contrast(Color a, Color b) {
        double la = luminance(a);
        double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    /**
     * `c` darkened (on a light background) or lightened (on a dark one) just enough for text in it to reach 4.5:1:
     * the accent colours as text, readable in both themes.
     */
    static Color readable(Color c, Color bg) {
        Color out = new Color(c.getRed(), c.getGreen(), c.getBlue());
        boolean darken = luminance(bg) > 0.4;
        for (int i = 0; i < 40 && contrast(out, bg) < 4.5; i++) {
            out = darken ? shift(out, -8) : shift(out, 8);
        }
        return out;
    }

    // ------------------------------------------------------------------ display type (the welcome page)

    private static Font plexBold;
    private static Font plexSemi;
    private static boolean fontsTried;

    /** Load the bundled IBM Plex Mono once (SIL Open Font License, see resources/fonts); null when it cannot be read. */
    private static synchronized void loadDisplayFonts() {
        if (fontsTried) {
            return;
        }
        fontsTried = true;
        plexBold = load("/fonts/IBMPlexMono-Bold.ttf");
        plexSemi = load("/fonts/IBMPlexMono-SemiBold.ttf");
    }

    private static Font load(String res) {
        try (var in = Theme.class.getResourceAsStream(res)) {
            if (in == null) {
                return null;
            }
            Font f = Font.createFont(Font.TRUETYPE_FONT, in);
            java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().registerFont(f);
            return f;
        } catch (Exception e) {
            return null;
        }
    }

    /** IBM Plex Mono Bold, for the title and step numbers; sized for Burp's default and scaled with its font setting. */
    static Font display(float size) {
        loadDisplayFonts();
        float px = size * uiScale();
        return plexBold != null ? plexBold.deriveFont(px) : mono(size).deriveFont(Font.BOLD);
    }

    /** IBM Plex Mono SemiBold, for headings, section labels and buttons. */
    static Font displayMedium(float size) {
        loadDisplayFonts();
        float px = size * uiScale();
        return plexSemi != null ? plexSemi.deriveFont(px) : mono(size).deriveFont(Font.BOLD);
    }

    /** Small capitals spaced out a little: the section labels. */
    static Font tracked(Font f, float tracking) {
        return f.deriveFont(java.util.Map.of(java.awt.font.TextAttribute.TRACKING, tracking));
    }

    /** Burp's font size against the default 13 px: 1 normally, 2 when the user doubled it. */
    static float uiScale() {
        Font base = UIManager.getFont("Label.font");
        return base == null ? 1f : Math.max(1f, base.getSize2D() / 13f);
    }

    /** Smooth text with exact glyph spacing, for the display type. */
    static void textHints(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
    }

    /** The display font when it has every character of `text`, otherwise Burp's bold font at a similar size. */
    static Font displayOr(Font f, String text) {
        return f.canDisplayUpTo(text) < 0 ? f : font(f.getSize2D() / uiScale(), Font.BOLD);
    }

    static Font mono(float size) {
        return new Font(Font.MONOSPACED, Font.PLAIN, Math.round(size * uiScale()));
    }

    // ------------------------------------------------------------ meaning to colour

    static Color severity(String sev) {
        return switch (sev) {
            case "hot", "High" -> RED;
            case "warn", "Medium" -> AMBER;
            default -> BLUE;
        };
    }

    static Color state(String state) {
        return switch (state == null ? "" : state) {
            case "BOTH" -> GREEN;
            case "STATIC_ONLY" -> ACCENT;
            case "RUNTIME_ONLY" -> BLUE;
            default -> GRAY;
        };
    }

    static Color method(String m) {
        return switch (m == null ? "" : m) {
            case "GET", "HEAD" -> GREEN;
            case "POST" -> ACCENT;
            case "PUT", "PATCH" -> AMBER;
            case "DELETE" -> RED;
            case "OPTIONS" -> GRAY;
            default -> PURPLE;
        };
    }

    static Color status(int s) {
        if (s >= 500) {
            return RED;
        }
        if (s >= 400) {
            return AMBER;
        }
        if (s >= 300) {
            return BLUE;
        }
        if (s >= 200) {
            return GREEN;
        }
        return GRAY;
    }

    static Color type(String t) {
        return switch (t) {
            case "host" -> new Color(0x6B, 0x7F, 0xA3);
            case "route" -> GREEN;
            case "script" -> PURPLE;
            case "endpoint" -> BLUE;
            case "parameter" -> new Color(0x9C, 0xB8, 0xD8);
            case "third_party" -> AMBER;
            case "cookie", "auth", "role" -> new Color(0xC2, 0x8A, 0x1E);
            case "tech" -> new Color(0x4F, 0xC9, 0xA6);
            case "operation" -> new Color(0x5C, 0x9E, 0xE0);
            default -> GRAY;
        };
    }

    // ------------------------------------------------------------ drawing

    static void quality(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
    }

    /** A rounded pill with text; returns its width so callers can lay pills out in a row. */
    static int pill(Graphics2D g, String text, int x, int y, int h, Color fill, Color textColor) {
        FontMetrics fm = g.getFontMetrics();
        int w = fm.stringWidth(text) + h;
        g.setColor(fill);
        g.fill(new RoundRectangle2D.Float(x, y, w, h, h, h));
        g.setColor(textColor);
        g.drawString(text, x + h / 2, y + (h + fm.getAscent() - fm.getDescent()) / 2);
        return w;
    }
}
