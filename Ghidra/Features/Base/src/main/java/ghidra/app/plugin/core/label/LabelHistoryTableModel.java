/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.label;

import java.util.Date;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.program.model.symbol.LabelHistory;

/**
 * Table model for showing label history.
 */
class LabelHistoryTableModel extends AbstractSortedTableModel<LabelHistory> {
	private static final long serialVersionUID = 1L;

	final static String ADDRESS = "Address";
	final static String ACTION = "Action";
	final static String LABEL = "Label";
	final static String USER = "User";
	final static String DATE = "Modification Date";

	// columns used in the getValueAt() method
	// Note: the address column may not exist
	private final static int ADDRESS_COL = 0;
	private final static int ACTION_COL = 1;
	private final static int LABEL_COL = 2;
	private final static int USER_COL = 3;
	private final static int DATE_COL = 4;

	private String[] columnNames = { ADDRESS, ACTION, LABEL, USER, DATE };

	private int[] columnNumbers = { ADDRESS_COL, ACTION_COL, LABEL_COL, USER_COL, DATE_COL };

	private final static String[] ACTION_NAMES = { "Add", "Remove", "Rename" };

	private List<LabelHistory> historyList;
	private boolean showAddress;

	LabelHistoryTableModel(List<LabelHistory> list, boolean showAddress) {
		historyList = list;
		this.showAddress = showAddress;
		if (!showAddress) {
			columnNames = new String[] { ACTION, LABEL, USER, DATE };
			columnNumbers = new int[] { ACTION_COL, LABEL_COL, USER_COL, DATE_COL };
		}
	}

	@Override
	public String getName() {
		return "Label History";
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		return historyList.size();
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnNumbers[columnIndex] == DATE_COL) {
			return Date.class;
		}
		return String.class;
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	int getDefaultSortColumn() {
		if (showAddress) {
			return ADDRESS_COL;
		}
		return columnNumbers.length - 1;
	}

	int getLabelColumn() {
		return columnNumbers.length - 3;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<LabelHistory> getModelData() {
		return historyList;
	}

	@Override
	public Object getColumnValueForRow(LabelHistory h, int columnIndex) {
		switch (columnNumbers[columnIndex]) {
			case ADDRESS_COL:
				return h.getAddress().toString();
			case ACTION_COL:
				return ACTION_NAMES[h.getActionID()];
			case LABEL_COL:
				return h.getLabelString();
			case USER_COL:
				return h.getUserName();
			case DATE_COL:
				return h.getModificationDate();
		}
		throw new ArrayIndexOutOfBoundsException("bad columnIndex");
	}
}
