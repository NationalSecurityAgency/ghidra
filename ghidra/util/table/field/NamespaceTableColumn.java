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
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;

public class NamespaceTableColumn
		extends ProgramBasedDynamicTableColumnExtensionPoint<ProgramLocation, String> {

	@Override
	public String getColumnName() {
		return "Namespace";
	}

	@Override
	public String getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		if (rowObject instanceof LabelFieldLocation) {
			LabelFieldLocation labelFieldLocation = (LabelFieldLocation) rowObject;
			String parentPath = labelFieldLocation.getSymbolPath().getParentPath();
			return parentPath == null ? GlobalNamespace.GLOBAL_NAMESPACE_NAME : parentPath;
		}
		Symbol symbol = getSymbol(rowObject, program);
		if (symbol != null) {
			return symbol.getParentNamespace().getName(true);
		}
		Function function =
			program.getFunctionManager().getFunctionContaining(rowObject.getAddress());
		if (function != null) {
			return function.getSymbol().getName(true);
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
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		if (symbol != null) {
			return symbol;
		}
		return null;
	}

}
