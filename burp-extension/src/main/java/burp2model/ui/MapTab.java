package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Model;
import java.awt.Component;
import java.util.Map;
import javax.swing.JSplitPane;

/** Map: the model as a network or a left-to-right flow, with the selected node's facts and requests. */
final class MapTab implements Tab {
    private final MainPanel app;
    private final GraphPanel graph = new GraphPanel();
    private final Facts graphFacts = new Facts();
    private final EvidenceViewer graphViewer = new EvidenceViewer();
    private final Component view;

    MapTab(MainPanel app) {
        this.app = app;
        this.view = build();
        graphFacts.onNode(app::goToNode);
    }

    /** Stop the map's timers (the extension is unloading). */
    void stop() {
        graph.stop();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        graphViewer.setModel(m);
        graph.setModel(m);
    }

    private Component build() {
        graph.onSelect(n -> {
            graphFacts.show(n, app.model());
            graphViewer.show(n.evidence, n.label);
        });
        graph.onOpen(n -> app.goToNode(n.id));
        JSplitPane top = split(JSplitPane.HORIZONTAL_SPLIT, graph, graphFacts, 0.74);
        JSplitPane sp = split(JSplitPane.VERTICAL_SPLIT, top, graphViewer, 0.68);
        return sp;
    }
}
