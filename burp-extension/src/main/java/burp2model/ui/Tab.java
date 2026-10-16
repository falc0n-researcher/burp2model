package burp2model.ui;

import burp2model.engine.Model;
import java.awt.Component;

/** One tab of the burp2model panel: its component, and how to fill it from a model when it is shown. */
interface Tab {
    Component view();

    /** Fill from the current model (null when there is none yet); called when the tab is shown and out of date. */
    void fill(Model m);
}
