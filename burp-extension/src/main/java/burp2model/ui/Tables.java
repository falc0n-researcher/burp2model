package burp2model.ui;

import java.awt.Font;
import java.util.List;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

/** Small helpers for read-only, sortable, filterable tables. */
final class Tables {
    private Tables() {}

    static DefaultTableModel model(String... columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int c) {
                return c == 0 && columns.length > 0 && columns[0].equals("#") ? Integer.class : String.class;
            }
        };
    }

    static JTable table(DefaultTableModel m) {
        JTable t = new JTable(m);
        t.setAutoCreateRowSorter(false);
        t.setRowSorter(new TableRowSorter<>(m));
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setFillsViewportHeight(true);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        return t;
    }

    @SuppressWarnings("unchecked")
    static void filter(JTable t, String text) {
        TableRowSorter<DefaultTableModel> s = (TableRowSorter<DefaultTableModel>) t.getRowSorter();
        if (text == null || text.isBlank()) {
            s.setRowFilter(null);
        } else {
            s.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text.strip())));
        }
    }

    static void widths(JTable t, int... w) {
        for (int i = 0; i < w.length && i < t.getColumnCount(); i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        }
    }

    static void fill(DefaultTableModel m, List<Object[]> rows) {
        m.setRowCount(0);
        rows.forEach(m::addRow);
    }

    static Font mono() {
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    /** The model row index behind the selected view row, or -1. */
    static int selected(JTable t) {
        int v = t.getSelectedRow();
        return v < 0 ? -1 : t.convertRowIndexToModel(v);
    }
}
