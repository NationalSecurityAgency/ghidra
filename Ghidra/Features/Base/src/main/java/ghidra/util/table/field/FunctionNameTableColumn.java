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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionNameFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * This table field displays the Function Name containing either the program location or the address
 * associated with a row in the table.
 */
public class FunctionNameTableColumn extends
		ProgramLocationTableColumnExtensionPoint<Address, String> {

	@Override
	public String getColumnName() {
		return "Function Name";
	}

	@Override
	public String getValue(Address rowObject, Settings settings, Program pgm,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		Function function = getFunctionContaining(rowObject, pgm);
		if (function != null) {
			return function.getName(true);
		}
		return null;
	}

	private Function getFunctionContaining(Object rowObject, Program pgm) {
		Address addr = (Address) rowObject;
		return pgm.getFunctionManager().getFunctionContaining(addr);
	}

	@Override
	public ProgramLocation getProgramLocation(Address rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		Function function = getFunctionContaining(rowObject, program);
		if (function != null) {
			return new FunctionNameFieldLocation(program, function.getEntryPoint(), 0,
				function.getPrototypeString(false, false), function.getName());
		}
		return null;
	}
}
