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
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to clear the external program path associated with an external Library.
 * 
 */
public class ClearExternalPathCmd implements Command<Program> {

	private String externalName;
	private String status;
	private boolean userDefined = true;

	/**
	 * Constructs a new command for clearing the external program path associated with a
	 * specified external Library.
	 * @param externalName external Library name
	 */
	public ClearExternalPathCmd(String externalName) {
		this.externalName = externalName;
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			// Avoid creating the Library if it does not already exist
			ExternalManager externalManager = program.getExternalManager();
			Library lib = externalManager.getExternalLibrary(externalName);
			if (lib != null) {
				externalManager.setExternalPath(externalName, null, userDefined);
				return true;
			}
			status = "Library not found: " + externalName;
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
		return "Clear External Library Path";
	}

}
