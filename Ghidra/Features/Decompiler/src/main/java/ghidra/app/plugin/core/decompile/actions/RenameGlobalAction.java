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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighCodeSymbol;
import ghidra.program.model.pcode.HighFunctionShellSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.*;

/**
 * Action triggered from a specific token in the decompiler window to rename a global variable.
 * The variable is associated with an address. There may already be a symbol in the database
 * there, in which case the symbol is simply renamed. Otherwise a new symbol is added.
 */
public class RenameGlobalAction extends AbstractDecompilerAction {

	public RenameGlobalAction() {
		super("Rename Global");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameGlobal"));
		setPopupMenuData(new MenuData(new String[] { "Rename Global" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			return false;
		}
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol == null || highSymbol instanceof HighFunctionShellSymbol) {
			return false;
		}
		return highSymbol.isGlobal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		final ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		Symbol symbol = null;
		if (highSymbol instanceof HighCodeSymbol) {
			symbol = ((HighCodeSymbol) highSymbol).getCodeSymbol();
			if (symbol == null) {
				// Try to get the dynamic symbol
				Address addr = ((HighCodeSymbol) highSymbol).getStorage().getMinAddress();
				SymbolTable symbolTable = context.getProgram().getSymbolTable();
				symbol = symbolTable.getPrimarySymbol(addr);
			}
		}
		if (symbol == null) {
			Msg.showError(this, tool.getToolFrame(), "Rename Failed",
				"Memory storage not found for global variable");
			return;
		}
		AddEditDialog dialog = new AddEditDialog("Rename Global", context.getTool());
		dialog.editLabel(symbol, context.getProgram());
	}
}
