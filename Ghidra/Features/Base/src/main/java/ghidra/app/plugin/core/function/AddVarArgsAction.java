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
import ghidra.app.cmd.function.SetFunctionVarArgsCommand;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 * Action that changes a Function so that it has VarArgs (a variable argument list).
 */
public class AddVarArgsAction extends ListingContextAction {
	FunctionPlugin functionPlugin;

	AddVarArgsAction(FunctionPlugin plugin) {
		super("Add VarArgs", plugin.getName());
		functionPlugin = plugin;
		updatePopupMenu(true);

		// set the help location
		setHelpLocation(new HelpLocation("FunctionPlugin", "Add_VarArgs"));
	}

	private void updatePopupMenu(boolean isSignatureAction) {
		if (isSignatureAction) {
			setPopupMenuData(new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
				"Add VarArgs" }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));
		}
		else {
			setPopupMenuData(new MenuData(new String[] { FunctionPlugin.VARIABLE_MENU_PULLRIGHT,
				"Add VarArgs" }, null, FunctionPlugin.VARIABLE_MENU_SUBGROUP));
		}
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();

		if ((loc instanceof FunctionSignatureFieldLocation) || (loc instanceof VariableLocation)) {

			Function function = functionPlugin.getFunction(context);
			if ((function != null) && (!function.hasVarArgs())) {
				Command command = new SetFunctionVarArgsCommand(function, true);

				PluginTool tool = functionPlugin.getTool();
				Program program = context.getProgram();

				if (!tool.execute(command, program)) {
					tool.setStatusInfo("Unable to add function varArgs on " + "function: " +
						function.getName());
				}
			}
		}
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection()) {
			return false;
		}
		ProgramLocation loc = context.getLocation();
		if (!(loc instanceof VariableLocation) && !(loc instanceof FunctionSignatureFieldLocation)) {
			return false;
		}

		if (loc instanceof FunctionSignatureFieldLocation) {
			updatePopupMenu(true);
		}
		else {
			updatePopupMenu(false);
		}

		Function function = functionPlugin.getFunction(context);
		return ((function != null) && (!function.hasVarArgs()));
	}
}
