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
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * This table field displays Address associated with a row in the table.
 */
public class AddressTableColumn
		extends ProgramLocationTableColumnExtensionPoint<Address, AddressBasedLocation> {

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnName() {
		return "Location";
	}

	@Override
	public AddressBasedLocation getValue(Address rowObject, Settings settings, Program pgm,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return new AddressBasedLocation(pgm, rowObject);
	}

	@Override
	public ProgramLocation getProgramLocation(Address rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) {
		return new AddressFieldLocation(program, rowObject);
	}

	@Override
	public int getColumnPreferredWidth() {
		// make this big enough for normal address values to display
		return 200;
	}
}
