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
import docking.action.KeyBindingType;
import ghidra.app.cmd.function.SetVariableCommentCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.*;

/**
 * <CODE>VariableCommentDeleteAction</CODE> allows the user to delete a function variable comment.
 */
class VariableCommentDeleteAction extends ListingContextAction {

	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	VariableCommentDeleteAction(FunctionPlugin plugin) {
		super("Delete Function Variable Comment", plugin.getName(), KeyBindingType.SHARED);
		this.funcPlugin = plugin;
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Function function = funcPlugin.getFunction(context);
		if (function == null) {
			return;
		}
		ProgramLocation currentLocation = context.getLocation();
		Variable var = getVariable(function, currentLocation);
		if (var == null) {
			return;
		}
		if (var.getComment().equals("")) {
			return;
		}
		if (currentLocation instanceof VariableCommentFieldLocation) {
			funcPlugin.execute(context.getProgram(), new SetVariableCommentCmd(var, ""));
		}
	}

	/**
	 * Get a variable using the current location.
	 * 
	 * @param function
	 * @return null if function is null or if current location is not a stack variable location.
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

		return (loc instanceof VariableCommentFieldLocation);
	}

}
