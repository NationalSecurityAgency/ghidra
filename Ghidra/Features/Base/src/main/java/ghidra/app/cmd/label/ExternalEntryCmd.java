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
package ghidra.app.cmd.label;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Command for setting/unsetting an external entry point.
 */
public class ExternalEntryCmd implements Command<Program> {

	private Address addr;
	private boolean isEntry;

	/**
	 * Construct a new command for setting/unsetting an external entry point
	 * @param addr address to set or unset as an external entry point.
	 * @param isEntry true if the address is to be an entry. Otherwise, false.
	 */
	public ExternalEntryCmd(Address addr, boolean isEntry) {
		this.addr = addr;
		this.isEntry = isEntry;
	}

	@Override
	public boolean applyTo(Program program) {
		SymbolTable st = program.getSymbolTable();
		if (isEntry) {
			st.addExternalEntryPoint(addr);
		}
		else {
			st.removeExternalEntryPoint(addr);
		}
		return true;
	}

	@Override
	public String getName() {
		return "Set External" + isEntry;
	}

	@Override
	public String getStatusMsg() {
		return "";
	}

}
