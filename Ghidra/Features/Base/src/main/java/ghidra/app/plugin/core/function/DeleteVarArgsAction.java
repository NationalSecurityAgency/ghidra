/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.cmd.function.SetFunctionVarArgsCommand;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import docking.action.MenuData;

/**
 * Action that changes a Function so that it has VarArgs (a variable argument list).
 */
public class DeleteVarArgsAction extends ListingContextAction {
	private static final long serialVersionUID = 1L;
	FunctionPlugin functionPlugin;

	DeleteVarArgsAction(FunctionPlugin plugin) {
		super("Delete VarArgs", plugin.getName());
		functionPlugin = plugin;

		updatePopupMenu(true);

		setHelpLocation(new HelpLocation("FunctionPlugin", "Delete_VarArgs"));
	}

	private void updatePopupMenu(boolean isSignatureAction) {
		if (isSignatureAction) {
			setPopupMenuData(new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
				"Delete VarArgs" }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));
		}
		else {
			setPopupMenuData(new MenuData(new String[] { FunctionPlugin.VARIABLE_MENU_PULLRIGHT,
				"Delete VarArgs" }, null, FunctionPlugin.VARIABLE_MENU_SUBGROUP));
		}
	}

	/**
	 * Method called when the action is invoked.
	 * @param ev details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = functionPlugin.getFunction(context);
		if ((function != null) && (function.hasVarArgs())) {
			Command command = new SetFunctionVarArgsCommand(function, false);

			PluginTool tool = functionPlugin.getTool();
			Program program = context.getProgram();

			if (!tool.execute(command, program)) {
				tool.setStatusInfo("Unable to delete function varArgs on " + "function: " +
					function.getName());
			}
		}
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation location = context.getLocation();
		if (!(location instanceof VariableLocation) &&
			!(location instanceof FunctionSignatureFieldLocation)) {
			return false;
		}

		if (location instanceof FunctionSignatureFieldLocation) {
			updatePopupMenu(true);
		}
		else {
			updatePopupMenu(false);
		}

		Function function = functionPlugin.getFunction(context);
		return ((function != null) && (function.hasVarArgs()));
	}
}
