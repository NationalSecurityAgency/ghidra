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
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.context.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.HelpLocation;

class EditThunkFunctionAction extends ProgramContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Create a new action, to edit a thunk function at the current location
	 * @param plugin  does checking for this action
	 */
	public EditThunkFunctionAction(FunctionPlugin plugin) {
		super("Set Thunked Function", plugin.getName());
		this.funcPlugin = plugin;

		// top-level item usable only on a function
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, "Set Thunked Function..." },
			null, FunctionPlugin.THUNK_FUNCTION_MENU_SUBGROUP));

		setHelpLocation(new HelpLocation("FunctionPlugin", "ThunkFunctions"));

		setEnabled(true);
	}

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

		if (func == null) {
			return;
		}
		Address funcEntry = func.getEntryPoint();

		Function refFunc = func.getThunkedFunction(false);		
		if (refFunc == null) {
			// if not already thunked, fill in a possible value from functions instructions
			Address thunkAddr = CreateThunkFunctionCmd.getThunkedAddr(program, funcEntry, false);
			if (thunkAddr != null) {
				refFunc = functionMgr.getFunctionAt(thunkAddr);
			}
		}		
		Symbol refSymbol = (refFunc == null ? null : refFunc.getSymbol());

		// Prompt for function referenced by thunk
		ThunkReferenceAddressDialog dialog = new ThunkReferenceAddressDialog(funcPlugin.getTool());
		dialog.showDialog(program, funcEntry, refSymbol);
		Symbol referencedSymbol = dialog.getSymbol();
		Address referencedFunctionAddr = dialog.getAddress();

		CreateThunkFunctionCmd cmd;
		if (referencedSymbol != null) {
			cmd = new CreateThunkFunctionCmd(funcEntry, null, referencedSymbol);
		}
		else if (referencedFunctionAddr != null) {
			cmd = new CreateThunkFunctionCmd(funcEntry, null, referencedFunctionAddr);
		}
		else {
			return; // cancelled
		}
		funcPlugin.execute(context.getProgram(), cmd);
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
			if (s == null || s.isExternal() || s.getSymbolType() != SymbolType.FUNCTION) {
				return false;
			}
			func = (Function) s.getObject();
		}
		else {
			return false;
		}
		return func != null;
	}
}
