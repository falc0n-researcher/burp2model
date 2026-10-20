package burp2model.ui;

import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Session;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JFileChooser;

/** Import a HAR or Burp export into the model; export the model as JSON or a Markdown summary. All in the background. */
final class DataActions {
    private final MainPanel app;

    DataActions(MainPanel app) {
        this.app = app;
    }

    /** Save the whole model as JSON. */
    void exportModel() {
        Model m = app.model();
        if (m == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(m.name + "-model.json"));
        if (fc.showSaveDialog(app) == JFileChooser.APPROVE_OPTION) {
            java.nio.file.Path to = fc.getSelectedFile().toPath();
            app.async("Exporting the model…", () -> Files.writeString(to, Json.pretty(m.toMap()), StandardCharsets.UTF_8),
                    x -> app.setStatus("exported " + to, MainPanel.Level.OK), t -> app.sayError("could not export: " + MainPanel.messageOf(t)));
        }
    }

    /** Save a Markdown summary of the model. */
    void exportSummary() {
        Model m = app.model();
        if (m == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(m.name + "-summary.md"));
        if (fc.showSaveDialog(app) == JFileChooser.APPROVE_OPTION) {
            java.nio.file.Path to = fc.getSelectedFile().toPath();
            app.async("Writing the summary…", () -> Files.writeString(to, burp2model.engine.Markdown.summary(m), StandardCharsets.UTF_8),
                    x -> app.setStatus("exported " + to, MainPanel.Level.OK), t -> app.sayError("could not export: " + MainPanel.messageOf(t)));
        }
    }

    /** Add the requests in a HAR file (browser DevTools, Hetty, mitmproxy, ZAP) or a Burp "Save items" export to the model. */
    void importFile() {
        if (app.session == null) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import a HAR file or a Burp export");
        if (fc.showOpenDialog(app) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File f = fc.getSelectedFile();
        final MainPanel.Settings set = app.settings();
        app.working("Importing " + f.getName() + "…");
        app.host.background("burp2model-import", () -> {
            try {
                List<burp2model.engine.Parse.Raw> raws = burp2model.engine.Har.looksLike(f) ? burp2model.engine.Har.readRaw(f) : burp2model.engine.BurpXml.readRaw(f);
                int unreadable = 0;
                List<burp2model.engine.Parse.Raw> ok = new ArrayList<>();
                for (burp2model.engine.Parse.Raw r : raws) {
                    if (r == null) {
                        unreadable++;
                    } else {
                        ok.add(r);
                    }
                }
                Session target = app.session;
                target.scope = set.scope();
                Session.AddResult r = target.add(ok, set.role(), f.getName(), set.replaceRole());
                app.refresh();
                app.idle();
                app.say("imported " + f.getName() + ": added " + r.added() + (r.duplicates() > 0 ? ", " + r.duplicates() + " already in the model" : "")
                        + (r.skipped() + unreadable > 0 ? ", " + (r.skipped() + unreadable) + " could not be read" : "") + ".");
            } catch (Throwable t) {
                app.idle();
                app.sayError("could not import " + f.getName() + ": " + t.getMessage());
            }
        });
    }
}
