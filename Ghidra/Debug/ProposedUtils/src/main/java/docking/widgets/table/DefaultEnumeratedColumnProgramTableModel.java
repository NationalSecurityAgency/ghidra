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
package docking.widgets.table;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class DefaultEnumeratedColumnProgramTableModel<C extends Enum<C> & EnumeratedTableColumn<C, ? super R>, R>
		extends DefaultEnumeratedColumnTableModel<C, R>
		implements EnumeratedColumnProgramTableModel<R> {
	protected final C selColumn;

	private Program program;

	public DefaultEnumeratedColumnProgramTableModel(String name, Class<C> colType, C selColumn) {
		super(name, colType);
		if (selColumn != null) {
			Class<?> valueClass = selColumn.getValueClass();
			if (!Address.class.isAssignableFrom(valueClass) &&
				!AddressRange.class.isAssignableFrom(valueClass) &&
				!AddressSetView.class.isAssignableFrom(valueClass)) {
				throw new IllegalArgumentException(
					"Address-selection column must have Address, AddressRange, " +
						"or AddressSetView type");
			}
		}
		this.selColumn = selColumn;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Class<?> columnClass = getColumnClass(column);
		if (!Address.class.isAssignableFrom(columnClass) &&
			!ProgramLocation.class.isAssignableFrom(columnClass)) {
			return null;
		}
		Object value = getValueAt(row, column);
		if (value instanceof Address) {
			return new ProgramLocation(program, (Address) value);
		}
		if (value instanceof ProgramLocation) {
			return (ProgramLocation) value;
		}
		throw new AssertionError();
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		if (selColumn == null) {
			return null;
		}
		AddressSet sel = new AddressSet();
		for (int r : rows) {
			Object value = selColumn.getValueOf(getRowObject(r));
			if (value instanceof Address) {
				sel.add((Address) value);
			}
			else if (value instanceof AddressRange) {
				sel.add((AddressRange) value);
			}
			else if (value instanceof AddressSetView) {
				sel.add((AddressSetView) value);
			}
			else {
				throw new AssertionError();
			}
		}
		return new ProgramSelection(sel);
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public void setProgram(Program program) {
		this.program = program;
	}
}
