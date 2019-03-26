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
import docking.widgets.OptionDialog;
import ghidra.app.context.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.HelpLocation;

/**
 * <CODE>RevertThunkFunctionAction</CODE> allows the user to modify the function
 * referenced by this function
 */
class RevertThunkFunctionAction extends ProgramContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Create a new action, to revert a thunk function at the current location
	 * to a normal function
	 * @param functionPlugin 
	 */
	public RevertThunkFunctionAction(FunctionPlugin plugin) {
		super("Revert Thunk Function", plugin.getName());
		this.funcPlugin = plugin;

		// top-level item usable only on a function
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, "Revert Thunk Function..." },
			null, FunctionPlugin.THUNK_FUNCTION_MENU_SUBGROUP));

		setHelpLocation(new HelpLocation("FunctionPlugin", "ThunkFunctions"));

		setEnabled(true);
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ProgramActionContext context) {

		Program program = context.getProgram();

		FunctionManager functionMgr = program.getFunctionManager();
		Function func;
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			func = functionMgr.getFunctionAt(listingContext.getAddress());
		}
		else if (context instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			Symbol symbol = symbolContext.getFirstSymbol();
			if (symbol == null) {
				return; // assume symbol removed
			}
			func = (Function) symbol.getObject();
		}
		else {
			throw new RuntimeException("Invalid context for action");
		}

		if (func == null || !func.isThunk()) {
			return;
		}

		int resp = OptionDialog.showYesNoDialog(funcPlugin.getTool().getActiveWindow(),
			"Revert Thunk Confirmation",
			"Do you wish to revert function '" + func.getName() + "' to a non-thunk Function?");
		if (resp != OptionDialog.YES_OPTION) {
			return;
		}

		int txId = program.startTransaction("Revert Thunk");
		try {
			func.setThunkedFunction(null);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {

		Program program = context.getProgram();
		if (program == null) {
			return false;
		}

		FunctionManager functionMgr = program.getFunctionManager();
		Function func;
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			func = functionMgr.getFunctionAt(listingContext.getAddress());
		}
		else if (context instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			if (symbolContext.getSymbolCount() != 1) {
				return false;
			}
			Symbol s = symbolContext.getFirstSymbol();
			if (s == null || s.getSymbolType() != SymbolType.FUNCTION) {
				return false;
			}
			func = (Function) s.getObject();
		}
		else {
			return false;
		}
		return func != null && func.isThunk();
	}
}
