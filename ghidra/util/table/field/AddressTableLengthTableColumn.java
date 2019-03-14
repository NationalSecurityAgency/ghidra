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

import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * This table field displays size of the address table associated with a row in the table.
 */
public class AddressTableLengthTableColumn 
        extends ProgramLocationTableColumnExtensionPoint<AddressTable, Integer> {

	@Override
    public String getColumnDisplayName(Settings settings) {
        return getColumnName();
    }

	@Override
    public String getColumnName() {
		return "Length";
	}

	@Override
    public Integer getValue(AddressTable rowObject, Settings settings, Program pgm, 
	        ServiceProvider serviceProvider) throws IllegalArgumentException {
		return new Integer(rowObject.getNumberAddressEntries());
	}
	
    public ProgramLocation getProgramLocation(AddressTable rowObject, Settings settings, 
	        Program program, ServiceProvider serviceProvider) {
		return new ProgramLocation(program, rowObject.getTopAddress());
	}
}
