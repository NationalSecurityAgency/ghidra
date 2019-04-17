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
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.cmd.function.SetFunctionPurgeCommand;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * An action to set the stack purge of the function at the current 
 * location. 
 * 
 * 
 * @since  Tracker Id 548
 */
public class EditFunctionPurgeAction extends ListingContextAction {

	private FunctionPlugin functionPlugin;

	public EditFunctionPurgeAction(FunctionPlugin plugin) {
		super("Edit Function Purge", plugin.getName());
		functionPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
			"Edit Function Purge..." }, null, FunctionPlugin.STACK_MENU_SUBGROUP));

		setHelpLocation(new HelpLocation("FunctionPlugin", "Function_Purge"));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = functionPlugin.getFunction(context);
		if (function != null) {
			showDialog(function);
		}
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation location = context.getLocation();
		return (location instanceof FunctionLocation);
	}

	private void showDialog(Function function) {
		int currentFunctionPurgeSize = function.getStackPurgeSize();

		if (currentFunctionPurgeSize == Function.INVALID_STACK_DEPTH_CHANGE ||
			currentFunctionPurgeSize == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
			currentFunctionPurgeSize = 0;
		}
		NumberInputDialog numberInputDialog = new NumberInputDialog("Please Enter Function Purge",
			"Enter Function Purge", currentFunctionPurgeSize, -1048576, 1048576, false);
		numberInputDialog.setHelpLocation(new HelpLocation("FunctionPlugin", "Function_Purge"));

		if (!numberInputDialog.show()) {
			functionPlugin.getTool().setStatusInfo("User cancelled function purge");
			return;
		}
		int newFunctionPurgeSize = numberInputDialog.getValue();

		if (newFunctionPurgeSize != currentFunctionPurgeSize) {
			Command command = new SetFunctionPurgeCommand(function, newFunctionPurgeSize);

			PluginTool tool = functionPlugin.getTool();
			Program program = function.getProgram();

			if (!tool.execute(command, program)) {
				tool.setStatusInfo("Unable to set function purge on " + "function: " +
						function.getName());
			}
		}
	}

}
