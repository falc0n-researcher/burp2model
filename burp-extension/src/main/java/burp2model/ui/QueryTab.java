package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Diff;
import burp2model.engine.Model;
import burp2model.engine.Query;
import burp2model.engine.Session;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/** Query: plain questions and BQL, run in the background, cancellable, with history. */
final class QueryTab implements Tab {
    private final MainPanel app;
    private final JTextField queryField = new JTextField();
    private final DefaultTableModel queryModel = Tables.model();
    private final JTable queryTable = Tables.table(queryModel);
    private final JLabel queryNote = new JLabel(" ");
    private final EvidenceViewer queryViewer = new EvidenceViewer();
    private final List<String> queryHistory = new ArrayList<>();
    private int historyPos;
    private Query.Result lastResult;
    private static final int QUERY_SECONDS = 20;
    private java.util.concurrent.atomic.AtomicBoolean queryStop;
    private int queryGen;
    private final JButton cancelQuery = new JButton("Cancel");
    private Query queryEngine;
    private Model queryEngineFor;
    private final Component view;

    QueryTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    void focusField() {
        queryField.requestFocusInWindow();
        queryField.selectAll();
    }

    /** Run a query as if it were typed. */
    void ask(String text) {
        queryField.setText(text);
        runQuery(text);
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        queryViewer.setModel(m);
    }

    /** Ready-made questions: what the button says, and the query it runs. */
    private static final String[][] EXAMPLES = {
        {"All endpoints", "list-apis"}, {"Code vs runtime", "reconcile"}, {"Named only in code", "static-only"},
        {"POSTs that failed", "req.method:POST AND resp.code.gte:400"}, {"Privileged paths", "privileged"}, {"Auth surface", "auth-surface"},
        {"Secrets (masked)", "secrets"}, {"Open questions", "unknowns"}, {"Third parties", "third-parties"},
        {"Since the last build", "changed-since previous"}, {"Stats", "stats"}};

    private final java.awt.CardLayout outCards = new java.awt.CardLayout();
    private final JPanel out = new JPanel(outCards);
    private final javax.swing.JTextPane answer = StyledText.pane();
    private final JLabel resultTitle = new JLabel(" ");
    private final JButton copy = new JButton("Copy");
    private final JButton csv = new JButton("Save CSV…");
    private JSplitPane split;

    private Component build() {
        JPanel top = new JPanel(new BorderLayout(8, 0));
        top.setBorder(BorderFactory.createEmptyBorder(10, 12, 6, 12));
        queryField.setFont(Theme.mono(13f));
        queryField.putClientProperty("JTextField.placeholderText", "Ask a question or write a BQL filter, then press Enter  (↑ for earlier ones)");
        queryField.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Theme.LINE), BorderFactory.createEmptyBorder(6, 9, 6, 9)));
        JButton run = new JButton("Run");
        run.setFont(Theme.font(12f, Font.BOLD));
        JButton help = new JButton("Help");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JButton b : new JButton[] {run, cancelQuery, help}) {
            buttons.add(b);
        }
        cancelQuery.setVisible(false);
        cancelQuery.addActionListener(e -> {
            if (queryStop != null) {
                queryStop.set(true);
            }
        });
        top.add(queryField, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);
        run.addActionListener(e -> runQuery(queryField.getText()));
        help.addActionListener(e -> app.ask("help"));
        queryField.addActionListener(e -> runQuery(queryField.getText()));
        queryField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_UP && historyPos > 0) {
                    queryField.setText(queryHistory.get(--historyPos));
                } else if (e.getKeyCode() == KeyEvent.VK_DOWN && historyPos < queryHistory.size() - 1) {
                    queryField.setText(queryHistory.get(++historyPos));
                }
            }
        });
        JPanel examples = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        examples.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 12));
        for (String[] ex : EXAMPLES) {
            JButton b = new JButton(ex[0]);
            b.setToolTipText(ex[1]);
            b.setFont(Theme.font(11f, Font.PLAIN));
            b.setMargin(new Insets(2, 8, 2, 8));
            b.addActionListener(e -> app.ask(ex[1]));
            examples.add(b);
        }
        JPanel head = new JPanel(new BorderLayout());
        head.add(top, BorderLayout.NORTH);
        head.add(examples, BorderLayout.CENTER);

        // the answer: a bar saying what it is (with copy and save), then a table or a text
        resultTitle.setFont(Theme.font(12f, Font.BOLD));
        queryNote.setFont(Theme.font(11f, Font.PLAIN));
        queryNote.setForeground(Theme.MUTED);
        JPanel says = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        says.setOpaque(false);
        says.add(resultTitle);
        says.add(queryNote);
        copy.setToolTipText("Copy the rows as tab-separated text");
        copy.addActionListener(e -> {
            Tables.copy(resultTsv());
            app.say("Copied " + queryModel.getRowCount() + " rows.");
        });
        csv.addActionListener(e -> saveCsv());
        JPanel acts = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        acts.setOpaque(false);
        for (JButton b : new JButton[] {copy, csv}) {
            b.setFont(Theme.font(11f, Font.PLAIN));
            b.setMargin(new Insets(1, 8, 1, 8));
            acts.add(b);
        }
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Theme.LINE),
                BorderFactory.createEmptyBorder(5, 4, 5, 8)));
        bar.add(says, BorderLayout.CENTER);
        bar.add(acts, BorderLayout.EAST);

        queryTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || lastResult == null) {
                return;
            }
            int i = Tables.selected(queryTable);
            if (i >= 0 && i < lastResult.rows().size()) {
                List<Integer> evs = evidenceOf(lastResult.rows().get(i));
                queryViewer.show(evs, queryModel.getColumnCount() == 0 ? "" : String.valueOf(queryModel.getValueAt(i, 0)));
            }
        });
        out.add(scroll(queryTable), "table");
        out.add(scroll(answer), "text");
        JPanel result = new JPanel(new BorderLayout());
        result.add(bar, BorderLayout.NORTH);
        result.add(out, BorderLayout.CENTER);
        // until the first query, the answer area says what to type instead of standing empty
        StyledText.set(answer, """
                ASK THE MODEL
                Every answer cites the requests behind it (ev_N), runs offline, and nothing leaves Burp.

                Questions:      list-apis · privileged · auth-surface · secrets · unknowns · third-parties · stats
                Filters (BQL):  req.method:POST AND resp.code.gte:400
                                node.type:endpoint AND node.state:STATIC_ONLY
                                resp.body.regex:"pass(word)?"
                Graph:          reach "POST /api/checkout"   ·   path <a> to <b>   ·   blast <node> depth 2
                History:        changed-since previous   ·   provenance <node>   ·   reaches-privileged user

                Click a question above, type help for everything, and press ↑ for earlier queries.""");
        showAs(false, "Ask something", "");
        split = split(JSplitPane.VERTICAL_SPLIT, result, queryViewer, 0.5, 0.55);
        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    /** Table answers keep the request viewer below them; text answers take the whole height. */
    private void showAs(boolean table, String title, String note) {
        resultTitle.setText(title);
        queryNote.setForeground(Theme.MUTED);
        queryNote.setText(note);
        copy.setVisible(table);
        csv.setVisible(table);
        outCards.show(out, table ? "table" : "text");
        if (split != null && queryViewer.isVisible() != table) {
            queryViewer.setVisible(table);
            if (table) {
                split.setDividerLocation(0.55);
            }
        }
    }

    private String resultTsv() {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < queryModel.getColumnCount(); c++) {
            sb.append(c > 0 ? "\t" : "").append(queryModel.getColumnName(c));
        }
        for (int r = 0; r < queryModel.getRowCount(); r++) {
            sb.append('\n');
            for (int c = 0; c < queryModel.getColumnCount(); c++) {
                sb.append(c > 0 ? "\t" : "").append(queryModel.getValueAt(r, c));
            }
        }
        return sb.toString();
    }

    private void saveCsv() {
        if (queryModel.getRowCount() == 0) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("burp2model-query.csv"));
        if (fc.showSaveDialog(app) == JFileChooser.APPROVE_OPTION) {
            StringBuilder sb = new StringBuilder();
            for (String line : resultTsv().split("\n")) {
                List<String> cells = new ArrayList<>();
                for (String c : line.split("\t", -1)) {
                    cells.add("\"" + c.replace("\"", "\"\"") + "\"");
                }
                sb.append(String.join(",", cells)).append('\n');
            }
            try {
                Files.writeString(fc.getSelectedFile().toPath(), sb.toString(), StandardCharsets.UTF_8);
                app.say("Saved " + fc.getSelectedFile());
            } catch (Exception ex) {
                app.sayError("could not save: " + ex.getMessage());
            }
        }
    }

    private static List<Integer> evidenceOf(Map<String, Object> row) {
        List<Integer> out = new ArrayList<>();
        for (String key : new String[] {"ev", "evidence"}) {
            Object v = row.get(key);
            List<?> items = v instanceof List<?> l ? l : v == null ? List.of() : List.of(v);
            for (Object o : items) {
                String s = String.valueOf(o);
                if (s.startsWith("ev_") && s.substring(3).matches("\\d+")) {
                    out.add(Integer.parseInt(s.substring(3)));
                }
            }
        }
        return out;
    }

    private void runQuery(String text) {
        Model m = app.model();
        if (m == null) {
            queryNote.setForeground(Theme.MUTED);
            queryNote.setText("Nothing to query yet. Send some requests first.");
            return;
        }
        if (text == null || text.isBlank()) {
            return;
        }
        if (queryHistory.isEmpty() || !queryHistory.get(queryHistory.size() - 1).equals(text)) {
            queryHistory.add(text);
        }
        historyPos = queryHistory.size();
        if (queryEngine == null || queryEngineFor != m) {
            queryEngine = new Query(m);
            queryEngineFor = m;
        }
        Query q = queryEngine;
        Session sess = app.session();
        q.history = id -> sess.historyOf(id);
        q.changedSince = ref -> {
            try {
                int older = resolveBuild(ref);
                int newer = sess.builds().size();
                if (older == newer) {
                    throw new Query.QueryError("build #" + older + " is the latest; nothing to compare yet");
                }
                return Diff.formatText(sess.diff(older, newer));
            } catch (java.io.IOException e) {
                throw new Query.QueryError(e.getMessage());
            }
        };
        // a new query stops the one still running; a query that runs past QUERY_SECONDS stops itself
        if (queryStop != null) {
            queryStop.set(true);
        }
        java.util.concurrent.atomic.AtomicBoolean stop = new java.util.concurrent.atomic.AtomicBoolean();
        queryStop = stop;
        long deadline = System.currentTimeMillis() + QUERY_SECONDS * 1000L;
        q.stop = () -> stop.get() || System.currentTimeMillis() > deadline;
        int gen = ++queryGen;
        queryNote.setForeground(Theme.MUTED);
        queryNote.setText("running…");
        cancelQuery.setVisible(true);
        app.async(null, () -> {
            synchronized (q) {
                return q.run(text);
            }
        }, r -> {
            if (gen == queryGen) {
                cancelQuery.setVisible(false);
                showResult(r);
            }
        }, t -> {
            if (gen != queryGen) {
                return;
            }
            cancelQuery.setVisible(false);
            lastResult = null;
            queryNote.setForeground(Theme.RED);
            if (t instanceof Query.Stopped) {
                queryNote.setText(stop.get() ? "stopped." : "stopped after " + QUERY_SECONDS + " s: narrow the filter, or simplify the regex.");
            } else {
                queryNote.setText("error: " + MainPanel.messageOf(t));
            }
        });
    }

    /** Columns that hold lists, even when an answer gives them as text. */
    private static final java.util.Set<String> LISTS = java.util.Set.of("statuses", "roles", "credentials", "params", "parameters", "ev",
            "evidence", "status_by_role", "names", "hosts");

    /** Put a query's answer on screen (Swing thread). */
    private void showResult(Query.Result r) {
        lastResult = r;
        queryModel.setRowCount(0);
        queryModel.setColumnCount(0);
        queryViewer.clear();
        if (r.kind().equals("text")) {
            StyledText.set(answer, r.note());
            showAs(false, queryField.getText().strip(), "");
            return;
        }
        for (String c : r.columns()) {
            queryModel.addColumn(c);
        }
        for (Map<String, Object> row : r.rows()) {
            Object[] cells = new Object[r.columns().size()];
            for (int i = 0; i < cells.length; i++) {
                String col = r.columns().get(i);
                Object v = row.get(col);
                cells[i] = LISTS.contains(col) ? Cells.listText(v) : Cells.text(v);
            }
            queryModel.addRow(cells);
        }
        Tables.render(queryTable, "method", Renderers.method());
        for (String col : new String[] {"status", "statuses", "status_by_role", "code"}) {
            Tables.render(queryTable, col, Renderers.codes());
        }
        Tables.render(queryTable, "state", Renderers.state());
        Tables.render(queryTable, "type", Renderers.type());
        Tables.render(queryTable, "ev", Renderers.ids());
        Tables.render(queryTable, "evidence", Renderers.ids());
        for (String col : new String[] {"label", "path", "endpoint", "from", "to", "src", "dst", "url"}) {
            Tables.render(queryTable, col, Renderers.path());
        }
        String note = r.note() == null ? "" : r.note();
        showAs(true, r.rows().size() + (r.total() > r.rows().size() ? " of " + r.total() : "") + (r.rows().size() == 1 ? " row" : " rows"),
                note + (r.rows().isEmpty() ? "" : "   ·   pick a row to see its request"));
        if (!r.rows().isEmpty()) {
            queryTable.setRowSelectionInterval(0, 0);
        }
    }

    private int resolveBuild(String ref) {
        List<Session.BuildInfo> bs = app.session().builds();
        String r = ref.strip().toLowerCase();
        if (r.equals("previous")) {
            if (bs.size() < 2) {
                throw new Query.QueryError("only one build so far");
            }
            return bs.size() - 1;
        }
        if (r.equals("first")) {
            return 1;
        }
        String num = r.startsWith("#") ? r.substring(1) : r;
        if (num.matches("\\d+")) {
            int n = Integer.parseInt(num);
            if (n >= 1 && n <= bs.size()) {
                return n;
            }
            throw new Query.QueryError("no build #" + n);
        }
        for (int i = bs.size() - 1; i >= 0; i--) {
            if (bs.get(i).label().equalsIgnoreCase(ref.strip())) {
                return bs.get(i).id();
            }
        }
        throw new Query.QueryError("no build matches '" + ref + "'");
    }
}
