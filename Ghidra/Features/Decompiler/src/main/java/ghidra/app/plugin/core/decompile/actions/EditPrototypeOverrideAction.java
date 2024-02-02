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

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

public class EditPrototypeOverrideAction extends AbstractDecompilerAction {

	public EditPrototypeOverrideAction() {
		super("Edit Signature Override");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionEditOverride"));
		setPopupMenuData(new MenuData(new String[] { "Edit Signature Override" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		Symbol sym = OverridePrototypeAction.getSymbol(function, context.getTokenAtCursor());
		if (sym == null) {
			return false;
		}

		return HighFunctionDBUtil.readOverride(sym) != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Function function = context.getFunction();
		Symbol sym = OverridePrototypeAction.getSymbol(function, context.getTokenAtCursor());
		if (sym == null) {
			return;
		}
		DataTypeSymbol dts = HighFunctionDBUtil.readOverride(sym);
		if (dts == null) {
			return;
		}

		Function func = context.getFunction();
		Program program = func.getProgram();
		PcodeOp op = OverridePrototypeAction.getCallOp(program, context.getTokenAtCursor());
		Function calledFunc = null;
		if (op != null) {
			calledFunc = OverridePrototypeAction.getCalledFunction(program, op);
		}

		FunctionDefinition updatedFuncDef = null;
		try {
			// Copy is used for edit so we can adjust name
			FunctionDefinition funcDef =
				(FunctionDefinition) dts.getDataType().copy(program.getDataTypeManager());
			funcDef.setName(calledFunc != null ? calledFunc.getName() : "func");
			updatedFuncDef = OverridePrototypeAction.editSignature(context, calledFunc,
				funcDef.getPrototypeString());
			if (updatedFuncDef == null) {
				return;
			}
			// TODO: should use comparison to see if funcDef was changed.
			// Should be able to use equals method after fixing category and name, however
			// it does not check param names.
		}
		catch (InvalidNameException | DuplicateNameException e) {
			Msg.error(this, "Unexpected error", e);
		}

		int transaction = program.startTransaction("Override Signature");
		try {
			Address addr = sym.getAddress();
			sym.delete(); // delete old marker symbol
			HighFunctionDBUtil.writeOverride(func, addr, updatedFuncDef);
			dts.cleanupUnusedOverride();
		}
		catch (Exception e) {
			Msg.showError(getClass(), context.getDecompilerPanel(), "Override Signature Failed",
				"Error overriding signature: " + e);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

}
