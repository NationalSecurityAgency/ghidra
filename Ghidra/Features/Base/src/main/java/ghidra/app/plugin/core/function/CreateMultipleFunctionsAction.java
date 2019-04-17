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
package ghidra.app.plugin.core.function;

import docking.action.MenuData;
import ghidra.app.cmd.function.CreateMultipleFunctionsCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramSelection;

/**
 * <CODE>CreateMultipleFunctionsAction</CODE> allows the user to create functions from the 
 * selection in the browser. This tries to create functions by working from the minimum address 
 * to the maximum address in the selection. Any addresses in the selection that are already in 
 * existing functions are discarded. Every time a function is created, all the other addresses 
 * for that function are also discarded.<BR>
 * Action in FunctionPlugin.
 */
class CreateMultipleFunctionsAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	CreateMultipleFunctionsAction(String name, FunctionPlugin plugin) {
		super(name, plugin.getName());
		this.funcPlugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { name }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP,
				MenuData.NO_MNEMONIC, FunctionPlugin.FUNCTION_SUBGROUP_BEGINNING));

		setEnabled(true);
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		if (!isEnabledForContext(context)) {
			return;
		}
		Program currentProgram = context.getProgram();
		if (currentProgram == null) {
			return;
		}

		CreateMultipleFunctionsCmd cmd =
			new CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED);
		funcPlugin.execute(currentProgram, cmd);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (!context.hasSelection()) {
			return false;
		}
		return true;
	}

}
