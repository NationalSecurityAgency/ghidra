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
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionCallingConventionFieldLocation;
import ghidra.program.util.ProgramLocation;

public class FunctionCallingConventionTableColumn extends
		ProgramLocationTableColumnExtensionPoint<Function, String> {

	@Override
	public String getColumnDescription() {
		return "Function calling convention for the containing function";
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		return "Call Conv";
	}

	@Override
	public String getColumnName() {
		return "Function Calling Convention";
	}

	@Override
	public String getValue(Function rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		if (rowObject == null) {
			return null;
		}
		PrototypeModel callingConvention = rowObject.getCallingConvention();
		if (callingConvention == null) {
			return Function.UNKNOWN_CALLING_CONVENTION_STRING;
		}
		return callingConvention.getName();
	}

	@Override
	public ProgramLocation getProgramLocation(Function rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		if (rowObject == null) {
			return null;
		}

		Address address = rowObject.getEntryPoint();
		String signature = rowObject.getSignature().getPrototypeString();
		return new FunctionCallingConventionFieldLocation(program, address, address, 0, signature);
	}
}
