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
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.*;

/**
 * Action to shift a pointer by a specific offset
 */
public class ShiftPointerAction extends AbstractDecompilerAction {

	public ShiftPointerAction() {
		super("Shift Pointer");
		setDescription("Shift selected pointer by an offset");
		setPopupMenuData(new MenuData(new String[] { "Shift Pointer" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
	}

	/**
	 * Retype a global or local symbol
	 * @param program the program
	 * @param highSymbol the symbol to retype
	 * @param exactSpot the exact spot to retype
	 * @param dt the new data type
	 * @param tool the PluginTool
	 */
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
				Msg.showError(this, tool.getToolFrame(), "Shift Failed", e.getMessage());
				return;
			}
		}
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean successfulMod = false;
		int transaction = program.startTransaction("Shift Pointer");
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
			Msg.showError(this, tool.getToolFrame(), "Shift Failed",
				"Failed to shift pointer '" + highSymbol.getName() + "': " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, successfulMod);
		}
	}

	/**
	 * Retype a function return value
	 * @param program the program
	 * @param highFunction the function to retype
	 * @param dt the new datatype
	 * @param tool the PluginTool
	 */
	private void retypeReturn(Program program, HighFunction highFunction, DataType dt, PluginTool tool) { 
		boolean commitRequired = checkFullCommit(null, highFunction);
		if (commitRequired) {
			int resp = OptionDialog.showOptionDialog(tool.getToolFrame(),
				"Parameter Commit Required",
				"Shifting the pointer requires all other parameters to be committed!\nContinue with shift?",
				"Continue");
			if (resp != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		boolean successfulMod = false;
		int transactionID = program.startTransaction("Shift Pointer");
		try {
			if (dt.getDataTypeManager() != program.getDataTypeManager()) {
				dt = program.getDataTypeManager().resolve(dt, null);
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
			highFunction.getFunction().setReturnType(dt, SourceType.USER_DEFINED);
			successfulMod = true;
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Shift Failed",
				"Failed to shift pointer '" + getName() + "': " + e.getMessage());
		}
		program.endTransaction(transactionID, successfulMod);
	}
	
	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken token = context.getTokenAtCursor();
		if (token.Parent() instanceof ClangReturnType) {
			if (((ClangReturnType) token.Parent()).getDataType() instanceof Pointer) {
				return true;
			}
		}
		
		DataType dt = DecompilerUtils.getDataType(context);
		return dt instanceof Pointer;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		boolean isReturn = tokenAtCursor.Parent() instanceof ClangReturnType;
		HighSymbol highSymbol = null;
		
		Pointer origPointer;
		if (isReturn) {
			origPointer = (Pointer) ((ClangReturnType) tokenAtCursor.Parent()).getDataType();
		} else {
			origPointer = (Pointer) DecompilerUtils.getDataType(context);
			highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
			if (highSymbol == null) return;
		}
		
		NumberInputDialog dialog = new NumberInputDialog("Shift Pointer", "Offset:", origPointer.getShiftOffset(), Integer.MIN_VALUE, Integer.MAX_VALUE, true);
		tool.showDialog(dialog);
		if (!dialog.wasCancelled()) {
			Pointer shiftedPointer = new PointerDataType(origPointer.getDataType(), dialog.getValue(), origPointer.isDynamicallySized() ? -1 : origPointer.getLength(), origPointer.getDataTypeManager());
			if (isReturn) retypeReturn(program, context.getHighFunction(), shiftedPointer, tool);
			else retypeSymbol(program, highSymbol, tokenAtCursor.getVarnode(), shiftedPointer, tool);
		}
	} 
}
