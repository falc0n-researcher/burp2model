package burp2model.ui;

import java.awt.Component;
import javax.swing.Timer;

/** The map's camera: zoom and offset, fitting a box on screen, and the short eased move from one view to another. */
final class Viewport {
    double scale = 1;
    double ox;
    double oy;
    /** Whether the map has been fitted on screen since it last changed size. */
    boolean fitted;
    final Timer anim;
    private final Component canvas;
    private double tScale;
    private double tox;
    private double toy;
    private long animStart;
    private double fScale;
    private double fox;
    private double foy;

    Viewport(Component canvas) {
        this.canvas = canvas;
        anim = new Timer(14, e -> animTick());
    }

    /** The view that fits the box {minX, minY, maxX, maxY} on the canvas, with room for labels. */
    double[] fitting(double[] b, boolean flow) {
        double w = Math.max(1, b[2] - b[0]) + (flow ? 260 : 110);
        double h = Math.max(1, b[3] - b[1]) + 90;
        double s = Math.max(0.05, Math.min(flow ? 1.4 : 2.0, Math.min(canvas.getWidth() / w, canvas.getHeight() / h)));
        return new double[] {s, canvas.getWidth() / 2.0 - (b[0] + b[2]) / 2 * s, canvas.getHeight() / 2.0 - (b[1] + b[3]) / 2 * s};
    }

    void jumpTo(double[] view) {
        scale = view[0];
        ox = view[1];
        oy = view[2];
        canvas.repaint();
    }

    void animateTo(double s, double x, double y) {
        fScale = scale;
        fox = ox;
        foy = oy;
        tScale = s;
        tox = x;
        toy = y;
        animStart = System.nanoTime();
        anim.start();
    }

    /** Move so the map point (x, y) is in the middle, zoomed in at least to 0.9. */
    void centerOn(double x, double y) {
        double s = Math.max(scale, 0.9);
        animateTo(s, canvas.getWidth() / 2.0 - x * s, canvas.getHeight() / 2.0 - y * s);
    }

    private void animTick() {
        double t = Math.min(1.0, (System.nanoTime() - animStart) / 240_000_000.0);
        double e = 1 - Math.pow(1 - t, 3);
        scale = fScale + (tScale - fScale) * e;
        ox = fox + (tox - fox) * e;
        oy = foy + (toy - foy) * e;
        canvas.repaint();
        if (t >= 1.0) {
            anim.stop();
        }
    }
}
