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
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * This table field displays the number of references to the location that was found
 */
public class ReferenceCountToAddressTableColumn extends
		ProgramBasedDynamicTableColumnExtensionPoint<Address, Integer> {

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnName() {
		return "Reference Count";
	}

	@Override
	public Integer getValue(Address rowObject, Settings settings, Program pgm,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		ReferenceManager referenceManager = pgm.getReferenceManager();
		int referenceCount = referenceManager.getReferenceCountTo(rowObject);
		if (referenceCount != 0) {
			return referenceCount;
		}

		// get the function containing the address and show the number of references to that
		FunctionManager functionManager = pgm.getFunctionManager();
		Function function = functionManager.getFunctionContaining(rowObject);
		if (function == null) {
			return 0;
		}
		return referenceManager.getReferenceCountTo(function.getEntryPoint());
	}
}
