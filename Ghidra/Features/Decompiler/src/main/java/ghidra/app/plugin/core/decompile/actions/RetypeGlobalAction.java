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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * Action triggered from a specific token in the decompiler window to change the data-type
 * associated with a global variable. If the variable does not already exist in the program database,
 * it will be created using storage address the decompiler has assigned to the variable within its model.
 * In either case, there is a preexisting notion of variable storage. This action may allow the newly
 * selected data-type to be of a different size relative to this preexisting storage, constrained by
 * other global variables that might already consume storage.
 */
public class RetypeGlobalAction extends AbstractDecompilerAction {

	public RetypeGlobalAction() {
		super("Retype Global");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeGlobal"));
		setPopupMenuData(new MenuData(new String[] { "Retype Global" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
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
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			return false;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol == null) {
			return false;
		}
		return highSymbol.isGlobal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();
		ClangToken tokenAtCursor = context.getTokenAtCursor();

		DataType dataType = null;
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol == null) {
			return;
		}
		dataType = chooseDataType(tool, program, highSymbol.getDataType());

		if (dataType == null) {
			return;
		}

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean successfulMod = false;
		int transaction = program.startTransaction("Retype Global");
		try {
			if (dataType.getDataTypeManager() != dataTypeManager) {
				dataType = dataTypeManager.resolve(dataType, null);
			}
			HighFunctionDBUtil.updateDBVariable(highSymbol, null, dataType,
				SourceType.USER_DEFINED);
			successfulMod = true;
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception", e);
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type variable '" + highSymbol.getName() + "': " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, successfulMod);
		}
	}
}
