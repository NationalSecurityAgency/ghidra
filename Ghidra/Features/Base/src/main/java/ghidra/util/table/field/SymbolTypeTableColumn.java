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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;

public class SymbolTypeTableColumn
		extends ProgramBasedDynamicTableColumnExtensionPoint<ProgramLocation, String> {

	public SymbolTypeTableColumn() {
		super();
	}

	@Override
	public String getColumnName() {
		return "Symbol Type";
	}

	@Override
	public String getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		if (rowObject instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) rowObject;
			return varLoc.isParameter() ? SymbolType.PARAMETER.toString()
					: SymbolType.LOCAL_VAR.toString();
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol;
		if (rowObject instanceof LabelFieldLocation) {
			LabelFieldLocation labLoc = (LabelFieldLocation) rowObject;
			symbol = labLoc.getSymbol();
		}
		else {
			symbol = symbolTable.getPrimarySymbol(rowObject.getAddress());
		}
		if (symbol == null) {
			return null;
		}

		return SymbolUtilities.getSymbolTypeDisplayName(symbol);
	}

}
