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

import ghidra.app.cmd.function.CreateFunctionDefinitionCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.FunctionSignatureFieldLocation;
import docking.action.MenuData;

/**
 * <CODE>CreateFunctionDefinitionAction</CODE> allows the user to create a 
 * function definition data type from a function's signature.
 */
class CreateFunctionDefinitionAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	CreateFunctionDefinitionAction(FunctionPlugin plugin) {
		super("Create Function Definition", plugin.getName());
		this.funcPlugin = plugin;
		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
			"Create Function Definition" }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = funcPlugin.getFunction(context);
		if (function == null) {
			return;
		}
		Address entry = function.getEntryPoint();
		funcPlugin.execute(context.getProgram(), new CreateFunctionDefinitionCmd(entry,
			funcPlugin.getTool()));
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		return context.getLocation() instanceof FunctionSignatureFieldLocation;
	}
}
