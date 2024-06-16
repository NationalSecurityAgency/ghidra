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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to update the name for an external program.
 * 
 */
public class AddExternalNameCmd implements Command<Program> {

	private String name;
	private SourceType source;

	private String status;

	/**
	 * Constructs a new command for adding the name of an external program.
	 * @param name the new name to be used for the external program link.
	 * @param source the source of this external name
	 */
	public AddExternalNameCmd(String name, SourceType source) {
		this.name = name;
		this.source = source;
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("name is invalid: " + name);
		}
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			program.getExternalManager().addExternalLibraryName(name, source);
			return true;
		}
		catch (DuplicateNameException e) {
			status = name + " already exists";
		}
		catch (InvalidInputException e) {
			status = e.getMessage();
		}
		return false;
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Add External Program Name";
	}

}
