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
import ghidra.app.context.*;
import ghidra.app.plugin.core.function.editor.FunctionEditorDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

public class EditFunctionAction extends ProgramContextAction {
	FunctionPlugin functionPlugin;

	EditFunctionAction(FunctionPlugin plugin) {
		super("Edit Function", plugin.getName());
		functionPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Edit Function..." }, null,
			FunctionPlugin.FUNCTION_MENU_SUBGROUP, MenuData.NO_MNEMONIC,
			FunctionPlugin.FUNCTION_SUBGROUP_BEGINNING));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, 0));

		setHelpLocation(new HelpLocation("FunctionPlugin", "Edit_Function"));
	}

	/**
	 * Method called when the action is invoked.
	 * @param ev details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ProgramActionContext context) {

		Function function = null;
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			ProgramLocation loc = listingContext.getLocation();
			if (loc instanceof FunctionLocation) {
				function = functionPlugin.getFunction(listingContext);
			}
			else if (loc instanceof OperandFieldLocation) {
				function = functionPlugin.getFunctionInOperandField(context.getProgram(),
					(OperandFieldLocation) loc);
			}
		}
		else {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			Symbol symbol = symbolContext.getFirstSymbol();
			if (symbol == null) {
				return; // assume symbol removed
			}
			function = (Function) symbol.getObject();
		}
		if (function != null) {
			PluginTool tool = functionPlugin.getTool();
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			FunctionEditorDialog dialog = new FunctionEditorDialog(service, function);
			tool.showDialog(dialog, context.getComponentProvider());
		}
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {

		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			if (listingContext.hasSelection() || listingContext.getAddress() == null) {
				return false;
			}
			ProgramLocation location = listingContext.getLocation();
			if ((location instanceof FunctionLocation)) {
				return true;
			}
			if (location instanceof OperandFieldLocation) {
				Function function = functionPlugin.getFunctionInOperandField(context.getProgram(),
					(OperandFieldLocation) location);
				return function != null;
			}
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
			Function function = (Function) s.getObject();
			return function != null;
		}
		return false;
	}
}
