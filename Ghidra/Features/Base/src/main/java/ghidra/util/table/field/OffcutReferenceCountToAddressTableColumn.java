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
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * This table field displays the number of references to the location that was found
 */
public class OffcutReferenceCountToAddressTableColumn extends
		ProgramBasedDynamicTableColumnExtensionPoint<Address, Integer> {

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnName() {
		return "Offcut Reference Count";
	}

	@Override
	public Integer getValue(Address address, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		int count = 0;
		if (address.isMemoryAddress()) {
			CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
			if (codeUnit != null) {
				AddressSet set =
					new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
				set.deleteRange(address, address);
				ReferenceManager referenceManager = program.getReferenceManager();
				AddressIterator it = referenceManager.getReferenceDestinationIterator(set, true);
				while (it.hasNext()) {
					it.next();
					count++;
				}
			}
		}
		return Integer.valueOf(count);
	}
}
