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
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.cmd.function.RemoveStackDepthChangeCommand;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * <CODE>RemoveStackDepthChangeAction</CODE> allows the user to delete a stack depth change value 
 * at the current address.
 */
class RemoveStackDepthChangeAction extends ListingContextAction {

	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	RemoveStackDepthChangeAction(FunctionPlugin plugin) {
		super("Remove Stack Depth Change", plugin.getName());
		this.funcPlugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, "Remove Stack Depth Change" },
			null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Program program = context.getProgram();
		Address address = context.getAddress();

		if (CallDepthChangeInfo.getStackDepthChange(program, address) == null) {
			return; // nothing to remove.
		}
		funcPlugin.execute(program, new RemoveStackDepthChangeCommand(program, address));
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		return CallDepthChangeInfo.getStackDepthChange(context.getProgram(),
			context.getAddress()) != null;

	}
}
