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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.table.ProgramTableModel;

class EquateReferenceTableModel extends AbstractSortedTableModel<EquateReference>
		implements ProgramTableModel {
	private static final Comparator<EquateReference> ADDRESS_COMPARATOR = (er1, er2) -> {
		Address addr1 = er1.getAddress();
		Address addr2 = er2.getAddress();
		return addr1.compareTo(addr2);
	};

	private static final Comparator<EquateReference> OPERAND_COMPARATOR = (er1, er2) -> {
		short opIndex1 = er1.getOpIndex();
		short opIndex2 = er2.getOpIndex();
		if (opIndex1 < opIndex2) {
			return -1;
		}
		if (opIndex1 > opIndex2) {
			return 1;
		}
		return 0;
	};

	static final String ADDR_COL_NAME = "Ref Addr";
	static final String OPINDEX_COL_NAME = "Op Index";

	static final int ADDR_COL = 0;
	static final int OPINDEX_COL = 1;

	private EquateTablePlugin plugin;
	private List<EquateReference> referenceList = new ArrayList<>();
	private Equate equate;

	EquateReferenceTableModel(EquateTablePlugin plugin) {
		this.plugin = plugin;
	}

	Equate getEquate() {
		return equate;
	}

	void setEquate(Equate equate) {
		this.equate = equate;

		populateReferences();

		fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Equate References";
	}

	@Override
	public String getColumnName(int column) {
		String names[] = { ADDR_COL_NAME, OPINDEX_COL_NAME };

		if (column < 0 || column > 1) {
			return "UNKNOWN";
		}

		return names[column];
	}

	@Override
	public int findColumn(String columnName) {
		if (columnName.equals(ADDR_COL_NAME)) {
			return 0;
		}
		else if (columnName.equals(OPINDEX_COL_NAME)) {
			return 1;
		}
		return 0;
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return EquateReference.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public int getColumnCount() {
		return 2;
	}

	@Override
	public int getRowCount() {
		return referenceList.size();
	}

	@Override
	protected Comparator<EquateReference> createSortComparator(int columnIndex) {
		switch (columnIndex) {
			case ADDR_COL:
				return ADDRESS_COMPARATOR;
			case OPINDEX_COL:
				return OPERAND_COMPARATOR;
			default:
				return super.createSortComparator(columnIndex);
		}
	}

	@Override
	public Object getColumnValueForRow(EquateReference eqref, int columnIndex) {
		switch (columnIndex) {
			case 0:
			case 1:
				return eqref;
			default:
				return "UNKNOWN";
		}
	}

	@Override
	public List<EquateReference> getModelData() {
		return referenceList;
	}

	private void populateReferences() {
		referenceList.clear();

		Program program = getProgram();
		if (program == null) {
			return;
		}

		EquateTable equateTable = program.getEquateTable();
		if (equateTable == null || equate == null) {
			return;
		}

		EquateReference[] refs = equate.getReferences();
		for (EquateReference ref : refs) {
			referenceList.add(ref);
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		EquateReference reference = getRowObject(row);
		OperandFieldLocation loc = new OperandFieldLocation(getProgram(), reference.getAddress(),
			null, null, null, reference.getOpIndex(), 0);
		return loc;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet addressSet = new AddressSet();
		for (int row : rows) {
			EquateReference reference = getRowObject(row);
			Address addr = reference.getAddress();
			addressSet.addRange(addr, addr);
		}
		return new ProgramSelection(addressSet);
	}

	@Override
	public Program getProgram() {
		return plugin.getProgram();
	}

}
