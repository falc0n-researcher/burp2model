package burp2model.ui;

import java.awt.Component;
import java.awt.Font;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JMenuItem;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

/** Read-only, sortable, striped tables with badge columns and a copy menu. */
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
        JTable t = new JTable(m) {
            @Override
            public Component prepareRenderer(TableCellRenderer r, int row, int col) {
                Component c = super.prepareRenderer(r, row, col);
                if (!isRowSelected(row) && c instanceof javax.swing.JComponent jc) {
                    jc.setOpaque(true);
                    c.setBackground(row % 2 == 0 ? getBackground() : Theme.dark() ? Theme.shift(getBackground(), 6) : Theme.shift(getBackground(), -5));
                }
                return c;
            }
        };
        t.setRowSorter(new TableRowSorter<>(m));
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setFillsViewportHeight(true);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        t.setRowHeight(Theme.rowHeight(Theme.font(12f, java.awt.Font.PLAIN), 26));
        t.setShowGrid(false);
        t.setIntercellSpacing(new java.awt.Dimension(0, 0));
        t.setDefaultRenderer(Object.class, Renderers.text());
        t.setDefaultRenderer(String.class, Renderers.text());
        t.setDefaultRenderer(Integer.class, Renderers.ids());
        JTableHeader h = t.getTableHeader();
        h.setReorderingAllowed(true);
        h.setPreferredSize(new java.awt.Dimension(10, Theme.rowHeight(Theme.font(11f, java.awt.Font.BOLD), 28)));
        DefaultTableCellRenderer hr = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tb, Object v, boolean s, boolean f, int r, int c) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(tb, v, false, false, r, c);
                l.setFont(Theme.font(11f, Font.BOLD));
                l.setForeground(Theme.MUTED);
                l.setBackground(Theme.surface2());
                l.setHorizontalAlignment(SwingConstants.LEFT);
                l.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE), BorderFactory.createEmptyBorder(0, 8, 0, 4)));
                l.setText(v == null ? "" : String.valueOf(v).toUpperCase());
                return l;
            }
        };
        h.setDefaultRenderer(hr);
        copyMenu(t);
        return t;
    }

    /** Right-click: copy the row, or the cell. */
    private static void copyMenu(JTable t) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem row = new JMenuItem("Copy row");
        JMenuItem cell = new JMenuItem("Copy cell");
        JMenuItem all = new JMenuItem("Copy all rows (TSV)");
        menu.add(row);
        menu.add(cell);
        menu.add(all);
        final int[] at = {-1, -1};
        t.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybe(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybe(e);
            }

            private void maybe(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = t.rowAtPoint(e.getPoint());
                    if (r >= 0) {
                        t.setRowSelectionInterval(r, r);
                        at[0] = r;
                        at[1] = t.columnAtPoint(e.getPoint());
                        menu.show(t, e.getX(), e.getY());
                    }
                }
            }
        });
        row.addActionListener(e -> copy(rowText(t, at[0], "\t")));
        cell.addActionListener(e -> copy(String.valueOf(t.getValueAt(at[0], at[1]))));
        all.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (int c = 0; c < t.getColumnCount(); c++) {
                sb.append(c > 0 ? "\t" : "").append(t.getColumnName(c));
            }
            for (int r = 0; r < t.getRowCount(); r++) {
                sb.append('\n').append(rowText(t, r, "\t"));
            }
            copy(sb.toString());
        });
    }

    private static String rowText(JTable t, int r, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < t.getColumnCount(); c++) {
            sb.append(c > 0 ? sep : "").append(t.getValueAt(r, c));
        }
        return sb.toString();
    }

    static void copy(String text) {
        try {
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ignored) {
            // headless or locked clipboard: nothing useful to do
        }
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

    static void render(JTable t, String column, TableCellRenderer r) {
        for (int i = 0; i < t.getColumnCount(); i++) {
            TableColumn tc = t.getColumnModel().getColumn(i);
            if (String.valueOf(tc.getHeaderValue()).equalsIgnoreCase(column)) {
                tc.setCellRenderer(r);
            }
        }
    }

    /** Replace every row at once: one change event, not one per row (the difference between instant and seconds on thousands of rows). */
    @SuppressWarnings("unchecked")
    static void fill(DefaultTableModel m, List<Object[]> rows) {
        java.util.Vector<java.util.Vector> data = m.getDataVector();
        data.clear();
        data.ensureCapacity(rows.size());
        for (Object[] r : rows) {
            java.util.Vector<Object> v = new java.util.Vector<>(r.length);
            for (Object o : r) {
                v.add(o);
            }
            data.add(v);
        }
        m.fireTableDataChanged();
    }

    static java.awt.Font mono() {
        return Theme.mono(12f);
    }

    /** The model row index behind the selected view row, or -1. */
    static int selected(JTable t) {
        int v = t.getSelectedRow();
        return v < 0 ? -1 : t.convertRowIndexToModel(v);
    }
}
