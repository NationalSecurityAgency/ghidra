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
package ghidra.plugins.importer.batch;

import java.util.Comparator;
import java.util.List;

import javax.swing.table.TableModel;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.util.Msg;

/**
 * An adapter between {@link BatchInfo} and a {@link TableModel}.
 */
class BatchImportTableModel extends AbstractSortedTableModel<BatchGroup> {
	public static enum COLS {
		SELECTED("Selected", true),
		FILETYPE("File Type", false),
		LOADER("Loader", false),
		LANG("Language", true),
		FILES("Files", false);

		public final String columnLabel;
		public final boolean editable;
		private final static COLS[] staticvalues = values();
		public final static int count = staticvalues.length;
		public static final String UNKNOWN_COLUMN_LABEL = "<unknown>";

		public static String getColumnLabel(int i) {
			return (i >= 0 && i < count) ? staticvalues[i].columnLabel : UNKNOWN_COLUMN_LABEL;
		}

		public static COLS getCol(int i) {
			return (i >= 0 && i < count) ? staticvalues[i] : null;
		}

		private COLS(String colLabel, boolean editable) {
			this.columnLabel = colLabel;
			this.editable = editable;
		}
	}

	private BatchInfo batchInfo;
	private List<BatchGroup> list;

	public BatchImportTableModel(BatchInfo ibi) {
		this.batchInfo = ibi;
		this.list = batchInfo.getGroups();
	}

	@Override
	public String getName() {
		return "Batch Import";
	}

	public void refreshData() {
		this.list = batchInfo.getGroups();
		fireTableDataChanged();
	}

	@Override
	protected Comparator<BatchGroup> createSortComparator(int columnIndex) {
		Comparator<BatchGroup> comp = super.createSortComparator(columnIndex);
		if (COLS.getCol(columnIndex) == COLS.SELECTED) {
			// Special case column 0 (selected) to be reversed, and secondarily sorted on filecount.
			return comp.reversed().thenComparing((bg1, bg2) -> {
				return bg2.size() - bg1.size();
			});
		}
		return comp;
	}

	@Override
	public int getColumnCount() {
		return COLS.count;
	}

	@Override
	public String getColumnName(int column) {
		return COLS.getColumnLabel(column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (COLS.getCol(columnIndex)) {
			case SELECTED:
				return Boolean.class;
			case FILETYPE:
				return String.class;
			case LOADER:
				return String.class;
			case LANG:
				return BatchGroupLoadSpec.class;
			case FILES:
				return BatchGroup.class;
			default:
				return Object.class;
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return COLS.getCol(columnIndex).editable;
	}

	@Override
	public List<BatchGroup> getModelData() {
		return list;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (rowIndex >= list.size()) {
			return;
		}

		BatchGroup row = list.get(rowIndex);
		switch (COLS.getCol(columnIndex)) {
			case SELECTED:
				boolean newValue = (Boolean) aValue;
				// dont allow enable unless there is a lang chosen
				if (newValue == true && row.getSelectedBatchGroupLoadSpec() == null) {
					Msg.showWarn(this, null, "Missing language",
						"Select a language for this group before enabling");
					return;
				}

				row.setEnabled(newValue);
				break;
			case LANG:
				row.setSelectedBatchGroupLoadSpec((BatchGroupLoadSpec) aValue);
				break;
			case FILES:
				// ignore
				break;
			default:
				throw new RuntimeException("bad column");
		}
	}

	@Override
	public Object getColumnValueForRow(BatchGroup row, int column) {
		switch (COLS.getCol(column)) {
			case SELECTED:
				return Boolean.valueOf(row.isEnabled());
			case FILETYPE:
				return StringUtils.defaultString(row.getCriteria().getFileExt(), "<no ext>");
			case LOADER:
				return row.getCriteria().getLoader();
			case LANG:
				return row.getSelectedBatchGroupLoadSpec();
			case FILES:
				return row;
			default:
				return "unknown col";
		}
	}

}
