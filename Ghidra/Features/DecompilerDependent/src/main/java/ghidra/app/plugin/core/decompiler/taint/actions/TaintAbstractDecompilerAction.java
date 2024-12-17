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
package ghidra.app.plugin.core.decompiler.taint.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.UndefinedFunction;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * User action(s) associated with the Source-Sink Taint Menu. This menu is brought up by Right-Clicking 
 * elements in the Decompiler window.
 * 
 * <p>
 * This is implemented by the remaining actions in this package.
 */
public abstract class TaintAbstractDecompilerAction extends DockingAction {

	/**
	 * Get the structure/union associated with a field token
	 * @param tok is the token representing a field
	 * @return the structure/union which contains this field
	 */
	public static Composite getCompositeDataType(ClangToken tok) {
		// We already know tok is a ClangFieldToken
		ClangFieldToken fieldtok = (ClangFieldToken) tok;
		DataType dt = fieldtok.getDataType();

		if (dt == null) {
			return null;
		}

		while (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}

		if (dt instanceof Composite) {
			return (Composite) dt;
		}

		return null;
	}

	/**
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
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
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

	protected static DataType chooseDataType(PluginTool tool, Program program,
			DataType currentDataType) {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataTypeSelectionDialog chooserDialog = new DataTypeSelectionDialog(tool, dataTypeManager,
			Integer.MAX_VALUE, AllowedDataTypes.FIXED_LENGTH);
		chooserDialog.setInitialDataType(currentDataType);
		tool.showDialog(chooserDialog);
		return chooserDialog.getUserChosenDataType();
	}

	public TaintAbstractDecompilerAction(String name) {
		super(name, DecompilePlugin.class.getSimpleName());
	}

	public TaintAbstractDecompilerAction(String name, KeyBindingType kbType) {
		super(name, DecompilePlugin.class.getSimpleName(), kbType);
	}

	/**
	 * Can only be used within the Decompiler?
	 */
	@Override
	public boolean isValidContext(ActionContext context) {
		return context instanceof DecompilerActionContext;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		return decompilerContext.checkActionEnablement(() -> {
			return isEnabledForDecompilerContext(decompilerContext);
		});
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		decompilerContext.performAction(() -> {
			decompilerActionPerformed(decompilerContext);
		});
	}

	protected Symbol getSymbol(DecompilerActionContext context) {

		// prefer the decompiler's function reference over the program location's address
		Function function = getFunction(context);
		if (function != null && !(function instanceof UndefinedFunction)) {
			return function.getSymbol();
		}

		Program program = context.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Address address = context.getAddress();
		if (address == null) {
			return null;
		}
		return symbolTable.getPrimarySymbol(address);
	}

	/**
	 * Get the function corresponding to the specified decompiler context.
	 * 
	 * @param context decompiler action context
	 * @return the function associated with the current context token or null if none identified.
	 */
	protected Function getFunction(DecompilerActionContext context) {
		ClangToken token = context.getTokenAtCursor();

		Function f = null;
		if (token instanceof ClangFuncNameToken) {
			f = DecompilerUtils.getFunction(context.getProgram(), (ClangFuncNameToken) token);
		}
		else {
			HighSymbol highSymbol = token.getHighSymbol(context.getHighFunction());
			if (highSymbol instanceof HighFunctionShellSymbol) {
				f = (Function) highSymbol.getSymbol().getObject();
			}
		}
		while (f != null && f.isThunk() && f.getSymbol().getSource() == SourceType.DEFAULT) {
			f = f.getThunkedFunction(false);
		}
		return f;
	}

	protected abstract boolean isEnabledForDecompilerContext(DecompilerActionContext context);

	protected abstract void decompilerActionPerformed(DecompilerActionContext context);
}
