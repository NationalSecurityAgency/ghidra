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

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocation;

/**
 * <CODE>CreateFunctionAction</CODE> allows the user to create a function from
 * a selection in the browser. The AddressSet indicates the function body and
 * the minimum address is used as the entry point to the function.<BR>
 * Action in FunctionPlugin.
 */
class VariableCommentAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	VariableCommentAction(FunctionPlugin plugin) {
		super("Edit Variable Comment", plugin.getName());
		this.funcPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.VARIABLE_MENU_PULLRIGHT,
			"Edit Comment..." }, null, FunctionPlugin.VARIABLE_MENU_SUBGROUP));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_SEMICOLON, 0));

	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = funcPlugin.getFunction(context);
		Variable var = getVariable(function, context.getLocation());
		if (var == null) {
			return;
		}
		VariableCommentDialog dialog = funcPlugin.getVariableCommentDialog();
		if (dialog == null) {
			dialog = new VariableCommentDialog(funcPlugin);
		}
		dialog.showDialog(function.getProgram(), var);
	}

	/////////////////////////////////////////////////////////////
	/**
	 * Get a variable using the current location.
	 * @param function
	 * @return null if function is null or if current location is not
	 * a stack variable location.
	 */
	private Variable getVariable(Function function, ProgramLocation currentLocation) {
		if (function == null) {
			return null;
		}
		if (currentLocation instanceof VariableLocation) {
			return ((VariableLocation) currentLocation).getVariable();
		}
		return null;
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation loc = context.getLocation();

		if (!(loc instanceof VariableLocation)) {
			return false;
		}
		VariableLocation varLoc = (VariableLocation) loc;
		Variable var = varLoc.getVariable();
		if (var == null || varLoc.isReturn()) {
			return false;
		}
		return true;
	}

}
