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

    static Font font(float size, int style) {
        Font base = UIManager.getFont("Label.font");
        return (base == null ? new Font(Font.SANS_SERIF, Font.PLAIN, 12) : base).deriveFont(style, size);
    }

    // ------------------------------------------------------------------ pixel type (the welcome page)

    private static Font silkscreen;
    private static Font pixelify;
    private static boolean fontsTried;

    /** Load the bundled pixel fonts once (SIL Open Font License, see resources/fonts); null when they cannot be read. */
    private static synchronized void loadPixelFonts() {
        if (fontsTried) {
            return;
        }
        fontsTried = true;
        silkscreen = load("/fonts/Silkscreen-Regular.ttf");
        pixelify = load("/fonts/PixelifySans.ttf");
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

    /**
     * Silkscreen, for display text: titles, step numbers, small caps labels. Its pixel grid is 8 per em, so only
     * multiples of 8 px are crisp; `step` picks 8, 16, 24... scaled with Burp's font size.
     */
    static Font pixel(int step) {
        loadPixelFonts();
        float px = 8f * Math.max(1, Math.round(step * uiScale()));
        return silkscreen != null ? silkscreen.deriveFont(px) : font(px * 0.8f, Font.BOLD);
    }

    /** Pixelify Sans, for short headings and buttons: crisp at 20 px (and 40 px). */
    static Font pixelSans(boolean large) {
        loadPixelFonts();
        float px = 20f * (large ? 2 : 1) * Math.max(1, Math.round(uiScale()));
        return pixelify != null ? pixelify.deriveFont(px) : font(px * 0.75f, Font.BOLD);
    }

    /** Burp's font size against the default 13 px: 1 normally, 2 when the user doubled it. */
    static float uiScale() {
        Font base = UIManager.getFont("Label.font");
        return base == null ? 1f : Math.max(1f, base.getSize2D() / 13f);
    }

    /** Pixel type is drawn without smoothing, so every pixel of the glyph lands on a screen pixel. */
    static void pixelHints(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_OFF);
        g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_OFF);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_OFF);
    }

    /** A pixel font when it has every character of `text`, otherwise the ordinary bold font at a similar size. */
    static Font pixelOr(Font pixel, String text) {
        return pixel.canDisplayUpTo(text) < 0 ? pixel : font(pixel.getSize2D() * 0.75f, Font.BOLD);
    }

    static Font mono(float size) {
        return new Font(Font.MONOSPACED, Font.PLAIN, Math.round(size));
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
