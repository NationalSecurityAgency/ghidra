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
package ghidra.util.table.field;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;

/**
 * This table column displays the Label for either the program location or the address
 * associated with a row in the table.
 */
public class LabelTableColumn
		extends ProgramLocationTableColumnExtensionPoint<ProgramLocation, String> {

	@Override
	public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {

		Symbol symbol = getSymbol(rowObject, program);

		if (symbol != null) {
			return symbol.getProgramLocation();
		}
		return rowObject;
	}

	@Override
	public String getColumnName() {
		return "Label";
	}

	@Override
	public String getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		if (rowObject instanceof LabelFieldLocation) {
			LabelFieldLocation labelFieldLocation = (LabelFieldLocation) rowObject;
			return labelFieldLocation.getSymbolPath().getName();
		}
		Symbol symbol = getSymbol(rowObject, program);
		if (symbol != null) {
			return symbol.getName();
		}
		return null;
	}

	private Symbol getSymbol(ProgramLocation rowObject, Program program)
			throws IllegalArgumentException {
		ProgramLocation location = rowObject;
		if (rowObject instanceof VariableLocation) {
			Variable var = ((VariableLocation) rowObject).getVariable();
			if (var != null) {
				return var.getSymbol();
			}
		}
		Address address = location.getAddress();
		SymbolTable symbolTable = program.getSymbolTable();

		return symbolTable.getPrimarySymbol(address);
	}

	@Override
	public int getColumnPreferredWidth() {
		// make this big enough for normal labels values to display
		return 200;
	}
}
