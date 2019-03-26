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
package ghidra.app.plugin.core.references;

import java.util.Arrays;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.cmd.refs.EditRefTypeCmd;
import ghidra.app.cmd.refs.SetPrimaryRefCmd;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.table.field.AddressBasedLocation;

class EditReferencesModel extends AbstractSortedTableModel<Reference> {

	static final String OPERAND = "Operand";
	static final String LOCATION = "Destination";
	static final String LABEL = "Label";
	static final String REF_TYPE = "Ref-Type";
	static final String IS_PRIMARY = "Primary?";
	static final String REF_SOURCE = "Source";

	static final int OPERAND_COL = 0;
	static final int LOCATION_COL = 1;
	static final int LABEL_COL = 2;
	static final int REF_TYPE_COL = 3;
	static final int IS_PRIMARY_COL = 4;
	static final int REF_SOURCE_COL = 5;

	static final int DEFAULT_SORT_COL = OPERAND_COL;

	private static final String[] COLUMN_NAMES =
		new String[] { OPERAND, LOCATION, LABEL, REF_TYPE, IS_PRIMARY, REF_SOURCE, };

	private static final Class<?>[] COLUMN_CLASSES = new Class[] { String.class,
		AddressBasedLocation.class, String.class, RefType.class, Boolean.class, SourceType.class, };

	private ReferencesPlugin plugin;
	private CodeUnit cu;
	private BrowserCodeUnitFormat cuFormat;

	private Reference[] refs = new Reference[0];

	EditReferencesModel(ReferencesPlugin plugin) {
		super(DEFAULT_SORT_COL);

		this.plugin = plugin;
		this.cuFormat = plugin.getCodeUnitFormat();
	}

	void setCodeUnitLocation(CodeUnit cu) {
		this.cu = cu;
		if (cu == null) {
			refs = new Reference[0];
		}
		else {
			refs = cu.getReferencesFrom();
		}
		fireTableDataChanged();
	}

	Program getProgram() {
		return cu != null ? cu.getProgram() : null;
	}

	@Override
	public String getName() {
		return "Edit References";
	}

	/**
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	/**
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		return refs.length;
	}

	/**
	 * @see javax.swing.table.AbstractTableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return COLUMN_CLASSES[columnIndex];
	}

	/**
	 * @see javax.swing.table.AbstractTableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == IS_PRIMARY_COL || columnIndex == REF_TYPE_COL) {
			if (rowIndex >= refs.length) {
				return false;
			}
			Address toAddr = refs[rowIndex].getToAddress();
			if (toAddr.isMemoryAddress()) {
				return true;
			}
			if (columnIndex == REF_TYPE_COL) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Object getColumnValueForRow(Reference reference, int columnIndex) {

		switch (columnIndex) {
			case OPERAND_COL:
				int opIndex = reference.getOperandIndex();
				if (opIndex == CodeUnit.MNEMONIC) {
					return "MNEMONIC";
				}
				return "OP-" + opIndex;
			case LOCATION_COL:
				return new AddressBasedLocation(getProgram(), reference,
					cuFormat.getShowBlockName());
			case LABEL_COL:
				return getToLabel(reference);
			case REF_TYPE_COL:
				return reference.getReferenceType();
			case IS_PRIMARY_COL:
				return Boolean.valueOf(reference.isPrimary());
			case REF_SOURCE_COL:
				return reference.getSource();
		}
		return null;
	}

	@Override
	public List<Reference> getModelData() {
		return Arrays.asList(this.refs);
	}

	/**
	 * @see javax.swing.table.AbstractTableModel#setValueAt(java.lang.Object,
	 *      int, int)
	 */
	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (rowIndex >= refs.length) {
			return;
		}
		Reference ref = refs[rowIndex];
		switch (columnIndex) {

			case REF_TYPE_COL:
				if (ref.getReferenceType() != value) {
					Command cmd = new EditRefTypeCmd(ref, (RefType) value);
					plugin.getTool().execute(cmd, cu.getProgram());
				}
				break;

			case IS_PRIMARY_COL:
				Command cmd = new SetPrimaryRefCmd(ref, ((Boolean) value).booleanValue());
				plugin.getTool().execute(cmd, cu.getProgram());
				break;

			default:
				throw new RuntimeException("Column is not editable");
		}
	}

	private String getToLabel(Reference ref) {
		if (cu == null) {
			return null;
		}
		return cuFormat.getReferenceRepresentationString(cu, ref);
	}

	@Override
	public String getColumnName(int columnIndex) {
		return COLUMN_NAMES[columnIndex];
	}

	/**
	 * Returns the row number containing the specified reference or -1 if not
	 * found.
	 * 
	 * @param ref reference to find
	 * @return the row
	 */
	int getRow(Reference ref) {
		for (int row = 0; row < refs.length; row++) {
			if (refs[row].compareTo(ref) == 0) {
				return row;
			}
		}
		return -1;
	}

	Reference getReference(int row) {
		return row < refs.length ? refs[row] : null;
	}

	static RefType[] getAllowedRefTypes(Program program, Reference ref) {
		Address toAddr = ref.getToAddress();
		if (toAddr.isStackAddress()) {
			return RefTypeFactory.getStackRefTypes();
		}
		if (toAddr.isRegisterAddress()) {
			return RefTypeFactory.getDataRefTypes();
		}
		if (toAddr.isMemoryAddress()) {
			if (program.getAddressFactory().getDefaultAddressSpace() == toAddr.getAddressSpace() ||
				isComputedFlow(program, ref)) {
				return RefTypeFactory.getMemoryRefTypes();
			}
			return RefTypeFactory.getDataRefTypes();
		}
		if (toAddr.isExternalAddress()) {
			return RefTypeFactory.getExternalRefTypes();
		}
		throw new IllegalArgumentException("Unsupported reference");
	}

	private static boolean isComputedFlow(Program program, Reference ref) {
		Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
		return instr != null && instr.getFlowType().isComputed();
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}
}
