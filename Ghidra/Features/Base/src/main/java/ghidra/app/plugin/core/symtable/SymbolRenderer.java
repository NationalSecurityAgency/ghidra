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
package ghidra.app.plugin.core.symtable;

import java.awt.Color;
import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.SymbolInspector;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.util.table.GhidraTableCellRenderer;

class SymbolRenderer extends GhidraTableCellRenderer {
	private SymbolInspector inspector;

	SymbolRenderer() {
		super();
	}

	void setSymbolInspector(SymbolInspector inspector) {
		this.inspector = inspector;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		int column = data.getColumnModelIndex();
		boolean isSelected = data.isSelected();

		if (value == null && column == SymbolTableModel.LABEL_COL) {
			setText("<< REMOVED >>");
		}
		else if (value instanceof Symbol) {
			handleSymbol(value, isSelected);
		}
		else if (value instanceof Address) {
			setText(getAddressString((Address) value));
		}
		else if (value instanceof ProgramLocation) {
			setText(getLocationString((ProgramLocation) value));
		}

		return this;
	}

	private String getLocationString(ProgramLocation location) {
		if (location instanceof VariableNameFieldLocation) {
			VariableNameFieldLocation varLoc = (VariableNameFieldLocation) location;
			Variable variable = varLoc.getVariable();
			return variable.getVariableStorage().toString();
		}
		return getAddressString(location.getAddress());
	}

	private void handleSymbol(Object value, boolean isSelected) {
		setBold();
		Color color =
			(inspector != null) && (value instanceof Symbol) ? inspector.getColor((Symbol) value)
					: Color.BLACK;

		if (!isSelected) {
			setForeground(color);
		}
	}

	private String getAddressString(Address address) {
		if (address.isStackAddress()) {
			return getStackAddressString(address);
		}
		else if (address.isRegisterAddress()) {
			return getRegisterAddressString(address);
		}
		else if (address.isExternalAddress() || address == Address.NO_ADDRESS) {
			return "";
		}
		return address.toString();
	}

	private String getRegisterAddressString(Address address) {
		Program program = inspector.getProgram();
		if (program != null) {
			Register register = program.getRegister(address);
			if (register != null) {
				return register.toString();
			}
		}
		return "";
	}

	private String getStackAddressString(Address address) {
		long offset = address.getOffset();
		if (offset < 0) {
			return "Stack[-0x" + Long.toHexString(-offset) + "]";
		}
		return "Stack[0x" + Long.toHexString(offset) + "]";
	}

}
