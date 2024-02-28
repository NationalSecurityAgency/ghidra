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
package ghidra.app.util.demangler;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * A class to represent a {@link DemangledObject} that should get represented as a Ghidra label
 */
public class DemangledLabel extends DemangledObject {

	/**
	 * Creates a new {@link DemangledLabel}
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The label name
	 */
	public DemangledLabel(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled);
		setName(name);
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {
		Symbol symbol = applyDemangledName(address, true, false, program);
		return symbol != null;
	}

	@Override
	public String getSignature(boolean format) {
		return getName();
	}

}
