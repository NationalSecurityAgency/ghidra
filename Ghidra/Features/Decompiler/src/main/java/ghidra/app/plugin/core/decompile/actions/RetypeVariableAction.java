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
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.*;

public class RetypeVariableAction extends AbstractDecompilerAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public RetypeVariableAction(PluginTool tool, DecompilerController controller) {
		super("Retype Variable");
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Retype Variable" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));

	}

	private void retypeReturnType(DataType dataType, ClangReturnType parent) {
		Program program = controller.getProgram();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		HighFunction hfunction = getHighFunctionFromReturnTypeToken(parent);
		if (hfunction == null) {
			return;
		}
		boolean commitRequired = checkFullCommit(null, hfunction);
		if (commitRequired) {
			int resp = OptionDialog.showOptionDialog(tool.getToolFrame(),
				"Parameter Commit Required",
				"Retyping the return value requires all other parameters to be committed!\nContinue with retype?",
				"Continue");
			if (resp != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		Function function = hfunction.getFunction();
		boolean successfulMod = false;
		int transactionID = program.startTransaction("Retype return type");
		try {
			if (dataType.getDataTypeManager() != dataTypeManager) {
				dataType = dataTypeManager.resolve(dataType, null);
			}
			if (commitRequired) {
				try {
					HighFunctionDBUtil.commitParamsToDatabase(hfunction, true,
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

	private HighFunction getHighFunctionFromReturnTypeToken(ClangReturnType returnType) {
		Varnode varnode = returnType.getVarnode();
		// varnode is null for void return type
		if (varnode == null) {
			ClangNode proto = returnType.Parent();
			if (proto instanceof ClangFuncProto) {
				ClangFunction func = ((ClangFuncProto) proto).getClangFunction();
				if (func == null) {
					return null;
				}
				return func.getHighFunction();
			}
			return null;
		}
		HighVariable high = varnode.getHigh();
		return high.getHighFunction();
	}

	private DataType chooseDataType(DataType currentDataType) {
		Program program = controller.getProgram();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataTypeSelectionDialog chooserDialog = new DataTypeSelectionDialog(tool, dataTypeManager,
			Integer.MAX_VALUE, AllowedDataTypes.FIXED_LENGTH);
		chooserDialog.setInitialDataType(currentDataType);
		tool.showDialog(chooserDialog);
		return chooserDialog.getUserChosenDataType();
	}

	private void retypeVariable(HighVariable var, Varnode exactSpot, DataType dt) {
		HighFunction hfunction = var.getHighFunction();

		boolean commitRequired = checkFullCommit(var, hfunction);
		if (commitRequired) {
			int resp = OptionDialog.showOptionDialog(tool.getToolFrame(),
				"Parameter Commit Required",
				"Retyping a parameter requires all other parameters to be committed!\nContinue with retype?",
				"Continue");
			if (resp != OptionDialog.OPTION_ONE) {
				return;
			}
			exactSpot = null;		// Don't try to split out if commit is required
		}

		if (exactSpot != null) { // The user pointed at a particular usage, not just the vardecl
			try {
				var = hfunction.splitOutMergeGroup(var, exactSpot);
			}
			catch (PcodeException e) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed", e.getMessage());
				return;
			}
		}
		Program program = controller.getProgram();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean successfulMod = false;
		int transaction = program.startTransaction("Retype Variable");
		try {
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dataTypeManager.resolve(dt, null);
			}
			if (commitRequired) {
				try {
					HighFunctionDBUtil.commitParamsToDatabase(hfunction, true,
						SourceType.USER_DEFINED);
					HighFunctionDBUtil.commitReturnToDatabase(hfunction, SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Unexpected exception", e);
				}
				catch (InvalidInputException e) {
					Msg.showError(this, null, "Parameter Commit Failed", e.getMessage());
				}
			}
			HighFunctionDBUtil.updateDBVariable(var, null, dt, SourceType.USER_DEFINED);
			successfulMod = true;
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception", e);
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type variable '" + var.getName() + "': " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, successfulMod);
		}
	}

	/**
	 * Return the index of the last component that would be overwritten by a new datatype, if we started overwriting
	 * with at a specific component. All components, except the first, must be undefined datatypes or we return -1
	 * @param struct is the structure we are testing
	 * @param comp is the starting component to overwrite
	 * @param newtype is the datatype to overwrite with
	 * @return the index of the last component overwritten or -1
	 */
	private int getEndComponentIndex(Structure struct, DataTypeComponent comp, DataType newtype) {
		int newlen = newtype.getLength();
		if (newlen <= 0) {
			return -1; // Don't support variable length types
		}
		DataType curtype = comp.getDataType();
		newlen -= curtype.getLength();
		int index = comp.getOrdinal();
		while (newlen > 0) {
			index += 1;
			if (index >= struct.getNumComponents()) {
				return -1; // Not enough space in the structure
			}
			comp = struct.getComponent(index);
//			String nm = comp.getFieldName();
//			if ((nm !=null)&&(nm.length()!=0))
//				return -1;
			curtype = comp.getDataType();
//			if (!Undefined.isUndefined(curtype))
//				return -1;						// Overlaps non-undefined datatype
			if (curtype != DataType.DEFAULT) {
				return -1; // Only allow overwrite of placeholder components
			}
			newlen -= curtype.getLength();
		}
		return index;
	}

	private void retypeStructVariable(Structure dt, DataTypeComponent comp, DataType newtype) {
		Program program = controller.getProgram();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean successfulMod = false;
		if (comp == null) {
			if (!dt.isNotYetDefined()) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Could not find component of '" + dt.getName() + "' to retype");
				return;
			}
			// note if we reach here the offset must be zero, so assume we are inserting newtype
			int transaction = program.startTransaction("Retype Structure Field");
			try {
				// Make sure datatype is using the program's data organization before testing fit
				if (newtype.getDataTypeManager() != dataTypeManager) {
					newtype = dataTypeManager.resolve(newtype, null);
				}
				dt.insert(0, newtype);
				successfulMod = true;
			}
			finally {
				program.endTransaction(transaction, successfulMod);
			}
			return;
		}
		int transaction = program.startTransaction("Retype Structure Field");
		try {
			// Make sure datatype is using the program's data organization before testing fit
			if (newtype.getDataTypeManager() != dataTypeManager) {
				newtype = dataTypeManager.resolve(newtype, null);
			}
			int startind = comp.getOrdinal();
			int endind = getEndComponentIndex(dt, comp, newtype);
			if (endind < 0) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Failed to re-type structure '" + dt.getName() + "': Datatype did not fit");
				return;
			}
			for (int i = endind; i > startind; --i) { // Clear all but first field
				dt.clearComponent(i);
			}
			dt.replaceAtOffset(comp.getOffset(), newtype, newtype.getLength(), comp.getFieldName(),
				comp.getComment());
			successfulMod = true;
		}
		finally {
			program.endTransaction(transaction, successfulMod);
		}
	}

	/**
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific parameter is being changed,
	 * it can be passed in indicating that slot can be skipped during the comparison.
	 * @param var (if not null) is a specific parameter to skip the check for
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	public static boolean checkFullCommit(HighVariable var, HighFunction hfunction) {
		if ((var != null) && (!(var instanceof HighParam))) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighParam param = localSymbolMap.getParam(i);
			if (param.getSlot() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			if (!storage.equals(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			DataType dt = RenameVariableAction.getStructDataType(tokenAtCursor);
			if (dt == null) {
				return false;
			}
			getPopupMenuData().setMenuItemName("Retype Field");
			return true;
		}
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			getPopupMenuData().setMenuItemName("Retype Return");
			return true;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		HighVariable variable = tokenAtCursor.getHighVariable();
		if (variable == null) {
			Address addr = RenameVariableAction.getStorageAddress(tokenAtCursor, controller);
			if (addr == null) {
				return false;
			}
			variable = RenameVariableAction.forgeHighVariable(addr, controller);
			if (variable == null) {
				return false;
			}
		}
		if (variable instanceof HighConstant) {
//		getPopupMenuData().setMenuItemName("Retype Constant");
//		return true;
		}
		else if (variable instanceof HighLocal) {
			getPopupMenuData().setMenuItemName("Retype Variable");
			return true;
		}
		else if (variable instanceof HighGlobal) {
			getPopupMenuData().setMenuItemName("Retype Global");
			return true;
		}
		return false;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		HighVariable variable = null;
		Structure struct = null;
		DataTypeComponent comp = null;

		DataType dataType = null;
		if (tokenAtCursor instanceof ClangFieldToken) {
			struct = RenameVariableAction.getStructDataType(tokenAtCursor);
			int offset = RenameVariableAction.getDataTypeOffset(tokenAtCursor);
			if (struct == null) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Failed to re-type structure");
				return;
			}
			if (offset < 0 || offset >= struct.getLength()) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Failed to re-type structure: " + struct.getName());
				return;
			}
			comp = struct.getComponentAt(offset);
			if (comp == null) {
				dataType = chooseDataType(DataType.DEFAULT);
			}
			else {
				dataType = chooseDataType(comp.getDataType());
			}
		}
		else if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			ClangReturnType parent = (ClangReturnType) tokenAtCursor.Parent();
			dataType = chooseDataType(parent.getDataType());
			if (dataType == null) {
				return;
			}
			retypeReturnType(dataType, parent);
			return;
		}
		else {
			variable = tokenAtCursor.getHighVariable();
			if (variable == null) {
				Address addr = RenameVariableAction.getStorageAddress(tokenAtCursor, controller);
				if (addr == null) {
					return;
				}
				variable = RenameVariableAction.forgeHighVariable(addr, controller);
				if (variable == null) {
					return;
				}
			}
			dataType = chooseDataType(variable.getDataType());
		}

		if (dataType == null) {
			return;
		}
		if (struct != null) {
			retypeStructVariable(struct, comp, dataType);
		}
		else {
			retypeVariable(variable, tokenAtCursor.getVarnode(), dataType);
		}
	}
}
