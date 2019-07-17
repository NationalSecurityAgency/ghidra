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
package ghidra.app.plugin.core.stackeditor;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.FunctionLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import docking.action.MenuData;

/**
 * <CODE>EditStackAction</CODE> allows the user to edit a function's stack frame.
 */
public class EditStackAction extends ListingContextAction {
	/** the plugin associated with this action. */
	StackEditorManagerPlugin plugin;
	DataTypeManagerService dtmService;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 * @param dtmService the data type manager service that tracks favorites and
	 * data type changes.
	 */
	EditStackAction(StackEditorManagerPlugin plugin, DataTypeManagerService dtmService) {
		super("Edit Stack Frame", plugin.getName());
		this.plugin = plugin;
		this.dtmService = dtmService;
		setPopupMenuData(new MenuData(new String[] { "Function", "Edit Stack Frame..." }, null,
			"Stack"));

		setHelpLocation(new HelpLocation("StackEditor", "Stack_Editor"));
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = getFunction(context);
		if (function == null) {
			return;
		}
		plugin.edit(function);
	}

	private Function getFunction(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		Address entry;
		if (loc instanceof FunctionLocation) {
			entry = ((FunctionLocation) loc).getFunctionAddress();
		}
		else {
			entry = context.getAddress();
		}
		if (entry == null) {
			return null;
		}
		return context.getProgram().getListing().getFunctionAt(entry);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection()) {
			return true;
		}
		Function func = getFunction(context);
		if (func != null) {
			return !func.isExternal();
		}
		return false;
	}

}
