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

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;

/**
 * This table field displays the primary symbol at the FromAddress
 * for the reference or possible reference address pair
 * associated with a row in the table.
 */
public class ReferenceFromLabelTableColumn 
        extends ProgramLocationTableColumnExtensionPoint<ReferenceAddressPair, String> {

    @Override
    public String getColumnDisplayName(Settings settings) {
        return getColumnName();
    }
	
	@Override
    public String getColumnName() {
		return "Label";
	}

	@Override
    public String getValue(ReferenceAddressPair rowObject, Settings settings, 
	        Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {

		Symbol s = getSymbol( rowObject, program );
		if (s != null) {
			return s.getName(true);
		}
		return null;
	}

	private Symbol getSymbol( ReferenceAddressPair rowObject, Program program ) {
	    Address fromAddress = rowObject.getSource();
        SymbolTable symbolTable = program.getSymbolTable();
        return symbolTable.getPrimarySymbol(fromAddress);
	}

	public ProgramLocation getProgramLocation(ReferenceAddressPair rowObject, 
	        Settings settings, Program program, ServiceProvider serviceProvider) {
	    Symbol symbol = getSymbol( rowObject, program );
	    if ( symbol != null ) {
	        return symbol.getProgramLocation();
	    }

		return null;
	}
}
