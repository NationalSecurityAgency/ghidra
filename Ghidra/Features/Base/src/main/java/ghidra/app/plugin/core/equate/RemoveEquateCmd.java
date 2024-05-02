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
package ghidra.app.plugin.core.equate;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.Msg;

/**
 * Command for removing all references to an equate.
 */
class RemoveEquateCmd implements Command<Program> {

	private String[] equateNames;

	private String msg;

	/**
	 * Constructor
	 * @param equateNames one or more equate names to be removed.
	 */
	RemoveEquateCmd(String... equateNames) {
		this.equateNames = equateNames;
	}

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Remove Equate" + (equateNames.length > 1 ? "s" : "");
	}

	@Override
	public boolean applyTo(Program program) {

		EquateTable etable = program.getEquateTable();
		boolean success = true;
		for (String name : equateNames) {
			if (!etable.removeEquate(name)) {
				Msg.error(this, "Failed to remove equate: " + name);
				success = false;
			}
		}
		if (!success) {
			msg = "Failed to remove one or more equates";
		}
		return success;
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

}
