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

public class FunctionParameterCountTableColumn extends
		ProgramLocationTableColumnExtensionPoint<Address, Integer> {

	@Override
	public String getColumnDescription() {
		return "The number of parameters for the function containing the given address";
	}

	@Override
	public String getColumnName() {
		return "Param Count";
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

	private Function getFunctionContaining(Object rowObject, Program pgm) {
		Address addr = (Address) rowObject;
		return pgm.getFunctionManager().getFunctionContaining(addr);
	}

	@Override
	public Integer getValue(Address rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		Function function = getFunctionContaining(rowObject, program);
		if (function != null) {
			return function.getParameterCount();
		}
		return null;
	}

}
