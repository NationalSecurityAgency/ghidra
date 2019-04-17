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

import docking.ActionContext;
import docking.action.*;
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

public class RetypeVariableAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public RetypeVariableAction(String owner, PluginTool tool, DecompilerController controller) {
		super("Retype Variable", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Retype Variable" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));

	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			DataType dt = RenameVariableAction.getStructDataType(tokenAtCursor);
			if (dt == null)
				return false;
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
			if (addr == null)
				return false;
			variable = RenameVariableAction.forgeHighVariable(addr, controller);
			if (variable == null)
				return false;
		}
		if (variable instanceof HighConstant) {
//			getPopupMenuData().setMenuItemName("Retype Constant");
//			return true;
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
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

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
			if (comp == null)
				dataType = chooseDataType(DataType.DEFAULT);
			else
				dataType = chooseDataType(comp.getDataType());
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
				if (addr == null)
					return;
				variable = RenameVariableAction.forgeHighVariable(addr, controller);
				if (variable == null)
					return;
			}
			dataType = chooseDataType(variable.getDataType());
		}
		if (dataType == null)
			return;
		if (struct != null)
			retypeStructVariable(struct, comp, dataType);
		else
			retypeVariable(variable, tokenAtCursor.getVarnode(), dataType);
	}

	private void retypeReturnType(DataType dataType, ClangReturnType parent) {
		Program program = controller.getProgram();
		HighFunction hfunction = getHighFunctionFromReturnTypeToken(parent);
		if (hfunction == null) {
			return;
		}
		boolean commitRequired = checkFullCommit(null, hfunction);
		if (commitRequired) {
			int resp =
				OptionDialog.showOptionDialog(
					tool.getToolFrame(),
					"Parameter Commit Required",
					"Retyping the return value requires all other parameters to be committed!\nContinue with retype?",
					"Continue");
			if (resp != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		Function function = hfunction.getFunction();
		int transactionID = program.startTransaction("Retype return type");
		try {
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
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type return type '" + getName() + "': " + e.getMessage());
		}
		program.endTransaction(transactionID, true);
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
		DataTypeSelectionDialog chooserDialog =
			new DataTypeSelectionDialog(tool, dataTypeManager, Integer.MAX_VALUE,
				AllowedDataTypes.FIXED_LENGTH);
		chooserDialog.setInitialDataType(currentDataType);
		tool.showDialog(chooserDialog);
		return chooserDialog.getUserChosenDataType();
	}

	private void retypeVariable(HighVariable var, Varnode exactSpot, DataType dt) {
		HighFunction hfunction = var.getHighFunction();

		boolean commitRequired = checkFullCommit(var, hfunction);
		if (commitRequired) {
			int resp =
				OptionDialog.showOptionDialog(
					tool.getToolFrame(),
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
		int transaction = program.startTransaction("Retype Variable");
		try {
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
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception", e);
		}
		catch (InvalidInputException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type variable '" + var.getName() + "': " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, true);
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
		if (newlen <= 0)
			return -1; // Don't support variable length types
		DataType curtype = comp.getDataType();
		newlen -= curtype.getLength();
		if (newlen < 0)
			return -1; // new size is smaller than original size
		int index = comp.getOrdinal();
		while (newlen > 0) {
			index += 1;
			if (index >= struct.getNumComponents())
				return -1; // Not enough space in the structure
			comp = struct.getComponent(index);
//			String nm = comp.getFieldName();
//			if ((nm !=null)&&(nm.length()!=0))
//				return -1;
			curtype = comp.getDataType();
//			if (!Undefined.isUndefined(curtype))
//				return -1;						// Overlaps non-undefined datatype
			if (curtype != DataType.DEFAULT)
				return -1; // Only allow overwrite of placeholder components
			newlen -= curtype.getLength();
		}
		if (newlen < 0)
			return -1; // Partial field
		return index;
	}

	private void retypeStructVariable(Structure dt, DataTypeComponent comp, DataType newtype) {
		Program program = controller.getProgram();
		if (comp == null) {
			if (!dt.isNotYetDefined()) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
						"Could not find component of '" + dt.getName() + "' to retype");
				return;
			}
			// note if we reach here the offset must be zero, so assume we are inserting newtype
			int transaction = program.startTransaction("Retype Structure Field");
			try {
				dt.insert(0, newtype);
			}
			finally {
				program.endTransaction(transaction, true);
			}
			return;
		}
		int startind = comp.getOrdinal();
		int endind = getEndComponentIndex(dt, comp, newtype);
		if (endind < 0) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure '" + dt.getName() + "': Datatype did not fit");
			return;
		}
		int transaction = program.startTransaction("Retype Structure Field");
		try {
			for (int i = endind; i > startind; --i) { // Clear all but first field
				dt.clearComponent(i);
			}
			dt.replaceAtOffset(comp.getOffset(), newtype, newtype.getLength(), comp.getFieldName(),
				comp.getComment());
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	/**
	 * Compare a HighFunction's idea of what the signature is versus what the underlying Function thinks
	 * and returns true if there is a difference.  If all the input parameters have the same storage and type,
	 * @param var
	 * @param hfunction
	 * @return true if a full commit is required
	 */
	public static boolean checkFullCommit(HighVariable var, HighFunction hfunction) {
		if ((var != null) && (!(var instanceof HighParam)))
			return false;
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length)
			return true;

		int skipslot = -1;
		if (var != null)
			skipslot = ((HighParam) var).getSlot();
		for (int i = 0; i < numParams; i++) {
			HighParam param = localSymbolMap.getParam(i);
			if (param.getSlot() != i)		// Slot must match
				return true;
			VariableStorage storage = param.getStorage();
			if (!storage.equals(parameters[i].getVariableStorage()))		// Storage must match
				return true;
			if (skipslot != i) {	// Compare datatypes unless it is the specific -var- we are skipping
				if (!param.getDataType().isEquivalent(parameters[i].getDataType()))
					return true;
			}
		}

		if (var != null) {		// A null var indicates we are changing the returntype anyway, so we don't need to check it
			DataType funcReturnType = function.getReturnType();
			if (funcReturnType != DataType.DEFAULT) {
				DataType hfuncReturnType = hfunction.getFunctionPrototype().getReturnType();
				if (!funcReturnType.equals(hfuncReturnType))
					return true;
			}
		}

		return false;
	}
}
