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
import ghidra.app.util.AddEditDialog;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * <CODE>EditNameAction</CODE> allows the user to rename a function.
 * Action in FunctionPlugin.
 */
class EditNameAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin functionPlugin;
	private boolean isFunction;

	EditNameAction(boolean isFunction, FunctionPlugin plugin) {
		super(isFunction ? "Rename Function" : "Rename Variable", plugin.getName());
		this.functionPlugin = plugin;
		this.isFunction = isFunction;
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));

		if (isFunction) {
			setPopupMenuPath("Function", FunctionPlugin.FUNCTION_MENU_PULLRIGHT,
				FunctionPlugin.FUNCTION_MENU_SUBGROUP);
			setHelpLocation(new HelpLocation(functionPlugin.getName(), "Rename_Function"));
		}
		else {
			setPopupMenuPath("Variable", FunctionPlugin.VARIABLE_MENU_PULLRIGHT,
				FunctionPlugin.VARIABLE_MENU_SUBGROUP);
			setHelpLocation(new HelpLocation(functionPlugin.getName(), "Rename_Variable"));
		}
	}

	private void setPopupMenuPath(String itemName, String pullright, String group) {
		setPopupMenuData(
			new MenuData(new String[] { pullright, "Rename " + itemName + "..." }, null, group));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		Program program = context.getProgram();
		if (loc instanceof FunctionSignatureFieldLocation) {
			Function function = functionPlugin.getFunction(context);
			if (function != null) {
				AddEditDialog dialog =
					new AddEditDialog("Edit Function Name", functionPlugin.getTool());
				dialog.editLabel(function.getSymbol(), program);
			}
		}
		else if (loc instanceof VariableLocation) {
			Variable variable = ((VariableLocation) loc).getVariable();
			Symbol s = variable.getSymbol();
			if (s == null) {
				Msg.showError(this, null, "Edit Failed", "Variable may not be modified");
				return;
			}
			AddEditDialog dialog =
				new AddEditDialog("Edit Variable Name", functionPlugin.getTool());
			dialog.editLabel(s, program);
		}
		else if (loc instanceof OperandFieldLocation) {
			Function function =
				functionPlugin.getFunctionInOperandField(program, (OperandFieldLocation) loc);
			if (function != null) {
				AddEditDialog dialog =
					new AddEditDialog("Edit Function Name", functionPlugin.getTool());
				dialog.editLabel(function.getSymbol(), program);
			}
		}
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation loc = context.getLocation();
		if (!isFunction && loc instanceof VariableLocation) {
			Variable variable = ((VariableLocation) loc).getVariable();
			if (variable.getSymbol() == null) {
				return false; // return param has no symbol and can't be renamed
			}
			setPopupMenuPath((variable instanceof Parameter) ? "Parameter" : "Local Variable",
				FunctionPlugin.VARIABLE_MENU_PULLRIGHT, FunctionPlugin.VARIABLE_MENU_SUBGROUP);
			return true;
		}
		else if (isFunction && loc instanceof FunctionSignatureFieldLocation) {
			return true;
		}
		else if (isFunction && loc instanceof OperandFieldLocation) {
			Function function = functionPlugin.getFunctionInOperandField(context.getProgram(),
				(OperandFieldLocation) loc);
			return function != null && !function.isExternal();
		}
		return false;
	}

}
