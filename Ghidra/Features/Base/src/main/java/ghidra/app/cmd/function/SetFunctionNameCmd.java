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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * Command to set the name of a function.
 */
public class SetFunctionNameCmd implements Command<Program> {
	private Address entry;
	private String name;
	private String msg;
	private SourceType source;

	/**
	 * Constructs a new command for setting the name of a function.
	 * @param entry the address of the function to be renamed.
	 * @param newName the new name for the function.
	 * @param source the source of this function name
	 */
	public SetFunctionNameCmd(Address entry, String newName, SourceType source) {
		this.entry = entry;
		this.name = newName;
		this.source = source;
	}

	@Override
	public boolean applyTo(Program program) {

		if (name.length() <= 0) {
			name = null;
		}

		Function f = program.getListing().getFunctionAt(entry);
		if (f == null) {
			return true;
		}
		try {
			f.setName(name, source);
		}
		catch (Exception e) {
			msg = e.getMessage();
			return false;
		}
		return true;

	}

	@Override
	public String getName() {
		return "Rename Function";
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

}
