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
import docking.widgets.OptionDialog;
import ghidra.app.decompiler.ClangReturnType;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * Action triggered from a specific token in the decompiler window to change the return type of
 * the function. The user selected data-type is permanently set as the return type. As the
 * return type is part of the function prototype and is forcing on the decompiler,
 * this action may trigger input parameters to be committed to the database as well. This situation
 * currently triggers a confirmation dialog.  If new input parameters need to be committed, their
 * name and data-type are taken from the decompiler model.
 */
public class RetypeReturnAction extends AbstractDecompilerAction {

	public RetypeReturnAction() {
		super("Retype Return");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeReturn"));
		setPopupMenuData(new MenuData(new String[] { "Retype Return" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		return (tokenAtCursor.Parent() instanceof ClangReturnType);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighFunction highFunction = context.getHighFunction();
		Function function = highFunction.getFunction();
		DataTypeManager dataTypeManager = program.getDataTypeManager();

		ClangReturnType parent = (ClangReturnType) tokenAtCursor.Parent();
		DataType dataType = chooseDataType(tool, program, parent.getDataType());
		if (dataType == null) {
			return;
		}
		boolean commitRequired = checkFullCommit(null, highFunction);
		if (commitRequired) {
			int resp = OptionDialog.showOptionDialog(tool.getToolFrame(),
				"Parameter Commit Required",
				"Retyping the return value requires all other parameters to be committed!\nContinue with retype?",
				"Continue");
			if (resp != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		boolean successfulMod = false;
		int transactionID = program.startTransaction("Retype return type");
		try {
			if (dataType.getDataTypeManager() != dataTypeManager) {
				dataType = dataTypeManager.resolve(dataType, null);
			}
			if (commitRequired) {
				try {
					HighFunctionDBUtil.commitParamsToDatabase(highFunction, true,
						SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Unexpected exception", e);
				}
				catch (InvalidInputException e) {
					Msg.showError(this, null, "Parameter Commit Failed", e.getMessage());
				}
			}
			function.setReturnType(dataType, SourceType.USER_DEFINED);
			successfulMod = true;
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type return type '" + getName() + "': " + e.getMessage());
		}
		program.endTransaction(transactionID, successfulMod);
	}
}
