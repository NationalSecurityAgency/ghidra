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
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.EquateTable;

/**
 * Command for removing all references to an equate.
 */
class RemoveEquateCmd implements Command {

	private String[] equateNames;

	private String msg;
	private PluginTool tool;

	/**
	 * Constructor
	 * @param equateName name of equate to be removed.
	 */
	RemoveEquateCmd(String equateName, PluginTool tool) {
		this.equateNames = new String[] { equateName };
		this.tool = tool;
	}

	/**
	 * Constructor
	 * @param equateName name of equate to be removed.
	 */
	RemoveEquateCmd(String[] equateNames, PluginTool tool) {
		this.equateNames = equateNames;
		this.tool = tool;
	}

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Remove Equate" + (equateNames.length > 1 ? "s" : "");
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.plugintool.PluginTool, ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		EquateTable etable = ((Program) obj).getEquateTable();
		boolean success = true;
		for (int i = 0; i < equateNames.length; i++) {
			String name = equateNames[i];
			if (!etable.removeEquate(name)) {
				tool.setStatusInfo("Unable to remove equate: " + name);
				success = false;
			}
		}
		if (!success) {
			msg = "Failed to remove one or more equates";
		}
		return success;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return msg;
	}

}
