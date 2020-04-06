package ghidra.app.plugin.core.osgi;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableModel;

import docking.widgets.table.*;

/**
 * RowObjectSelectionManager attempts to repair selections in a filtered table
 * before and after filter events.  The additiona selection events, however, cause focus changes we don't want. 
 */
class LessFreneticGTable extends GTable {
	boolean chilled = false;

	private class MySelectionManager<T> extends RowObjectSelectionManager<T> {

		MySelectionManager(JTable table, RowObjectTableModel<T> model) {
			super(table, model);
		}

		@Override
		public void tableChanged(TableModelEvent e) {
			if (!chilled) {
				super.tableChanged(e);
			}
		}

	}

	public void chill() {
		chilled = true;
	}

	public void thaw() {
		chilled = false;
		notifyTableChanged(new TableModelEvent(getModel()));
	}

	LessFreneticGTable(TableModel dm) {
		super(dm);
	}

	@SuppressWarnings("unchecked")
	@Override
	protected <T> SelectionManager createSelectionManager(TableModel model) {
		return new MySelectionManager<T>(this, (RowObjectTableModel<T>) model);
	}
}