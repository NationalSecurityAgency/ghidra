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
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.*;

/**
 * <CODE>DeleteFunctionAction</CODE> allows the user to Delete a function at
 * the entry point of the function.
 */
class DeleteFunctionAction extends ListingContextAction {
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	DeleteFunctionAction(FunctionPlugin plugin) {
		super("Delete Function", plugin.getName());
		this.funcPlugin = plugin;
		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
			"Delete Function" }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = funcPlugin.getFunction(context);
		if (function == null) {
			return;
		}
		Address entry = function.getEntryPoint();
		funcPlugin.execute(context.getProgram(), new DeleteFunctionCmd(entry));
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation location = context.getLocation();
		if (location instanceof FunctionLocation && !(location instanceof VariableLocation)) {
			// Don't allow delete function unless we are on the real function
			return location.getAddress().equals(((FunctionLocation) location).getFunctionAddress());
		}
		return false;
	}

}
