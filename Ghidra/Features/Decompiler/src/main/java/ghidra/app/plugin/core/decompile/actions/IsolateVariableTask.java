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

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class IsolateVariableTask extends RenameTask {

	private HighSymbol highSymbol;
	private HighFunction highFunction;
	private Function function;
	private SourceType srcType;
	private String originalName;
	private boolean nameIsReserved;
	private boolean instanceIsMapped;

	public IsolateVariableTask(PluginTool tool, Program program, DecompilerPanel panel,
			ClangToken token, HighSymbol sym, SourceType st) {
		super(tool, program, panel, token, "");
		highSymbol = sym;
		highFunction = highSymbol.getHighFunction();
		function = highFunction.getFunction();
		srcType = st;
		originalName = highSymbol.getName();
		nameIsReserved = highSymbol.isNameLocked();
		instanceIsMapped = false;
		if (nameIsReserved) {
			Varnode vn = token.getVarnode();
			if (vn != null) {
				instanceIsMapped =
					(vn.getMergeGroup() == vn.getHigh().getRepresentative().getMergeGroup());
			}
		}
		if (!nameIsReserved || instanceIsMapped) {
			// We can keep the current name if
			// either no locked symbol is using it, or if this instance is directly mapped to it
			oldName = originalName;
		}
	}

	@Override
	public String getTransactionName() {
		return "Name New Variable";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		if (newName.equals(originalName)) {
			if (nameIsReserved && !instanceIsMapped) {
				errorMsg = "The name \"" + originalName + "\" is attached to another instance";
				return false;
			}
			return true;
		}
		LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
		if (localSymbolMap.containsVariableWithName(newName) ||
			isSymbolInFunction(function, newName)) {
			errorMsg = "Duplicate name";
			return false;
		}
		return true;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		// Split out the specific instance into its own symbol
		Varnode vn = tokenAtCursor.getVarnode();
		try {
			HighVariable highVariable = highFunction.splitOutMergeGroup(vn.getHigh(), vn);
			highSymbol = highVariable.getSymbol();
		}
		catch (PcodeException e) {
			Msg.showError(this, tool.getToolFrame(), "New Variable Failed", e.getMessage());
			return;
		}

		DataType dataType = highSymbol.getDataType();
		if (Undefined.isUndefined(dataType)) {
			// An undefined datatype will not be considered typelocked. Since the new variable
			// needs to be typelocked we use an unsigned integer of equivalent size
			dataType = AbstractIntegerDataType.getUnsignedDataType(dataType.getLength(),
				program.getDataTypeManager());
		}

		// Create the new variable, typelocking in a new data-type
		HighFunctionDBUtil.updateDBVariable(highSymbol, newName, dataType, srcType);
	}

}
