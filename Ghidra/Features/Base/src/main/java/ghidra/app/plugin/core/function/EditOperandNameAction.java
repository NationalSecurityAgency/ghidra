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

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.util.AddEditDialog;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;

/**
 * <CODE>EditNameAction</CODE> allows the user to rename a function.
 * Action in FunctionPlugin.
 */
class EditOperandNameAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin functionPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	EditOperandNameAction(FunctionPlugin plugin) {
		super("Rename Function Variable", plugin.getName());
		this.functionPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.VARIABLE_MENU_PULLRIGHT,
			"Rename Variable..." }, null, FunctionPlugin.VARIABLE_MENU_SUBGROUP));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));

	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		if (isEnabled()) {
			Variable var = getVariable(context);
			if (var != null) {
				Symbol s = var.getSymbol();
				if (s == null) {
					Msg.showError(this, null, "Edit Failed", "Variable may not be modified");
					return;
				}
				AddEditDialog dialog =
					new AddEditDialog("Edit Variable Name", functionPlugin.getTool());
				dialog.editLabel(s, context.getProgram());
			}
		}
	}

	private Variable getVariable(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return null;
		}
		ProgramLocation loc = context.getLocation();
		Program program = context.getProgram();
		if (!(loc instanceof OperandFieldLocation)) {
			return null;
		}
		OperandFieldLocation oloc = (OperandFieldLocation) loc;
		Instruction inst = program.getListing().getInstructionAt(oloc.getAddress());
		if (inst != null) {
			VariableOffset variableOffset = oloc.getVariableOffset();
			if (variableOffset != null) {
				return variableOffset.getVariable();
			}
		}
		return null;
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		Variable v = getVariable(context);
		return (v != null) && (v.getSymbol() != null);
	}

}
