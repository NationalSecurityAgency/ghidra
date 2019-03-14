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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;

public class SourceTypeTableColumn extends
		ProgramBasedDynamicTableColumnExtensionPoint<ProgramLocation, String> {

	@Override
	public String getColumnName() {
		return "Symbol Source";
	}

	@Override
	public String getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(rowObject.getAddress());
		if (primarySymbol != null) {
			return primarySymbol.getSource().toString();
		}
		return null;
	}

}
