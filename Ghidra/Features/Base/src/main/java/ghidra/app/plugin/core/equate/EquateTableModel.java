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
package ghidra.app.plugin.core.equate;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import util.CollectionUtils;

class EquateTableModel extends AbstractSortedTableModel<Equate> {
	static final String NAME_COL_NAME = "Name";
	static final String VALUE_COL_NAME = "Value";
	static final String REFS_COL_NAME = "# Refs";

	static final int NAME_COL = 0;
	static final int VALUE_COL = 1;
	static final int REFS_COL = 2;

	private EquateTablePlugin plugin;
	private List<Equate> equateList = new ArrayList<>();

	private Comparator<Equate> NAME_COMPARATOR = new Comparator<Equate>() {
		@Override
		public int compare(Equate eq1, Equate eq2) {
			return eq1.getName().compareTo(eq2.getName());
		}
	};
	private Comparator<Equate> VALUE_COMPARATOR = new Comparator<Equate>() {
		@Override
		public int compare(Equate eq1, Equate eq2) {
			Long long1 = new Long(eq1.getValue());
			Long long2 = new Long(eq2.getValue());
			return long1.compareTo(long2);
		}
	};
	private Comparator<Equate> REFS_COMPARATOR = new Comparator<Equate>() {
		@Override
		public int compare(Equate eq1, Equate eq2) {
			Integer int1 = new Integer(eq1.getReferenceCount());
			Integer int2 = new Integer(eq2.getReferenceCount());
			return int1.compareTo(int2);
		}
	};

	EquateTableModel(EquateTablePlugin plugin) {
		this.plugin = plugin;
	}

	private void populateEquates() {

		// 1st clean up any existing symbols
		//
		equateList.clear();

		Program program = plugin.getProgram();
		if (program == null) {
			fireTableDataChanged();
			return;
		}

		EquateTable equateTable = program.getEquateTable();

		for (Equate equate : CollectionUtils.asIterable(equateTable.getEquates())) {
			equateList.add(equate);
		}

		fireTableDataChanged();
	}

	@Override
	protected Comparator<Equate> createSortComparator(int columnIndex) {
		switch (columnIndex) {
			case NAME_COL:
				return NAME_COMPARATOR;
			case VALUE_COL:
				return VALUE_COMPARATOR;
			case REFS_COL:
				return REFS_COMPARATOR;
			default:
				return super.createSortComparator(columnIndex);
		}
	}

	void update() {
		populateEquates();
	}

	@Override
	public String getName() {
		return "Equates";
	}

	@Override
	public int getColumnCount() {
		return 3;
	}

	@Override
	public String getColumnName(int column) {
		String names[] = { NAME_COL_NAME, VALUE_COL_NAME, REFS_COL_NAME };

		if (column < 0 || column > 2) {
			return "UNKNOWN";
		}

		return names[column];
	}

	/**
	 *  Returns Object.class by default
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0) {
			return String.class;
		}
		return Equate.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex != 0) {
			return false;
		}
		return !getEquate(rowIndex).getName().startsWith(EquateManager.DATATYPE_TAG);
	}

	@Override
	public int getRowCount() {
		return equateList.size();
	}

	public Equate getEquate(int rowIndex) {
		return equateList.get(rowIndex);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (columnIndex != NAME_COL) {
			return;
		}
		plugin.renameEquate(equateList.get(rowIndex), (String) aValue);

	}

	@Override
	public Object getColumnValueForRow(Equate eq, int columnIndex) {
		return (columnIndex >= 0 && columnIndex <= 2) ? eq : "UNKNOWN";
	}

	@Override
	public List<Equate> getModelData() {
		return equateList;
	}

}
