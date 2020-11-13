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
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * Action triggered from a specific token in the decompiler window to change the data-type
 * associated with a variable in the local scope of the function. This can be an input parameter,
 * a stack variable, a variable associated with a register, or a "dynamic" variable. If the
 * variable does not already exist in the program database, it will be created using storage the
 * decompiler has assigned to the variable within its model. In either case, there is a preexisting
 * notion of variable storage. This action may allow the newly selected data-type to be of a
 * different size relative to this preexisting storage, constrained by other variables that might
 * already consume storage.
 * 
 * If the selected variable is an input parameter, other input parameters within the decompiler
 * model will need to be committed, if they do not already exist in the database, as any parameters
 * committed to the database are forcing on the decompiler. Any new parameters committed this way
 * inherit their name from the decompiler model, but the parameters will not be type-locked, allowing
 * their data-type to "float".
 * 
 */
public class RetypeLocalAction extends AbstractDecompilerAction {

	public RetypeLocalAction() {
		super("Retype Variable");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeVariable"));
		setPopupMenuData(new MenuData(new String[] { "Retype Variable" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
	}

	private void retypeSymbol(Program program, HighSymbol highSymbol, Varnode exactSpot,
			DataType dt, PluginTool tool) {
		HighFunction hfunction = highSymbol.getHighFunction();

		boolean commitRequired = checkFullCommit(highSymbol, hfunction);
		if (commitRequired) {
			exactSpot = null;		// Don't try to split out if commit is required
		}

		if (exactSpot != null) { // The user pointed at a particular usage, not just the vardecl
			try {
				HighVariable var = hfunction.splitOutMergeGroup(exactSpot.getHigh(), exactSpot);
				highSymbol = var.getSymbol();
			}
			catch (PcodeException e) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed", e.getMessage());
				return;
			}
		}
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean successfulMod = false;
		int transaction = program.startTransaction("Retype Variable");
		try {
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dataTypeManager.resolve(dt, null);
			}
			if (commitRequired) {
				// Don't use datatypes of other parameters if the datatypes were floating.
				// Datatypes were floating if signature source was DEFAULT
				boolean useDataTypes =
					hfunction.getFunction().getSignatureSource() != SourceType.DEFAULT;
				try {
					HighFunctionDBUtil.commitParamsToDatabase(hfunction, useDataTypes,
						SourceType.USER_DEFINED);
					if (useDataTypes) {
						HighFunctionDBUtil.commitReturnToDatabase(hfunction,
							SourceType.USER_DEFINED);
					}
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Unexpected exception", e);
				}
				catch (InvalidInputException e) {
					Msg.showError(this, null, "Parameter Commit Failed", e.getMessage());
				}
			}
			HighFunctionDBUtil.updateDBVariable(highSymbol, null, dt, SourceType.USER_DEFINED);
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
		return !highSymbol.isGlobal();
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
		retypeSymbol(program, highSymbol, tokenAtCursor.getVarnode(), dataType, tool);
	}
}
