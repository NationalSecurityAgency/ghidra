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
public class UpdateExternalNameCmd implements Command<Program> {

	private String oldName;
	private String newName;
	private SourceType source;

	private String status;

	/**
	 * Constructs a new command for updating the name of an external program.
	 * @param oldName the current name of the external program link.
	 * @param newName the new name to be used for the external program link.
	 * @param source the source of this external name
	 */
	public UpdateExternalNameCmd(String oldName, String newName, SourceType source) {
		this.oldName = oldName;
		this.newName = newName;
		this.source = source;
		if (newName == null || newName.length() == 0) {
			throw new IllegalArgumentException("newName is invalid");
		}
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			program.getExternalManager().updateExternalLibraryName(oldName, newName, source);
			return true;
		}
		catch (DuplicateNameException e) {
			status = newName + " already exists";
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
		return "Update External Program Name";
	}

}
