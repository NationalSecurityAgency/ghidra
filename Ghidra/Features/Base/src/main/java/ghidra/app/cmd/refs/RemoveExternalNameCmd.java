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
import ghidra.program.model.symbol.ExternalManager;

/**
 * Command to remove an external program name from the reference manager.
 * 
 */
public class RemoveExternalNameCmd implements Command<Program> {

	private String externalName;
	private String status;

	/**
	 * Constructs a new command removing an external program name.
	 * @param externalName the name of the external program name to be removed.
	 */
	public RemoveExternalNameCmd(String externalName) {
		this.externalName = externalName;
	}

	@Override
	public boolean applyTo(Program program) {
		ExternalManager extMgr = program.getExternalManager();
		if (!extMgr.removeExternalLibrary(externalName)) {
			status = externalName + " can not be removed";
			return false;
		}
		return true;
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Remove External Program Name";
	}

}
