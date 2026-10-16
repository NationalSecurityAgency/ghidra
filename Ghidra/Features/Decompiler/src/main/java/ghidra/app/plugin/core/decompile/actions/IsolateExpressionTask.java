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

import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.*;

public class IsolateExpressionTask extends RenameTask {

	private final HighOther highOther;
	private final Function function;
	private final SourceType srcType;

	public IsolateExpressionTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangOpToken token, HighOther ho, SourceType st) {
		super(tool, program, provider, token, "");
		highOther = ho;
		function = ho.getHighFunction().getFunction();
		srcType = st;
	}

	@Override
	public String getTransactionName() {
		return "Name New Expression";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		if (isSymbolInFunction(function, newName)) {
			errorMsg = "Duplicate name";
			return false;
		}
		return true;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		HighSymbol hs;
		try {
			hs = highOther.getHighFunction().highOtherSymbol(highOther);
		} catch (PcodeException e) {
			Msg.showError(this, tool.getToolFrame(), "New Expression Failed", e.getMessage());
			return;
		}

		DataType dt = highOther.getDataType();
		if (Undefined.isUndefined(dt)) {
			// An undefined datatype will not be considered typelocked. Since the new variable
			// needs to be typelocked we use an unsigned integer of equivalent size
			dt = AbstractIntegerDataType.getUnsignedDataType(highOther.getSize(),
				program.getDataTypeManager());
		}

		// Create the new variable, typelocking in a new data-type
		HighFunctionDBUtil.updateDBVariable(hs, newName, dt, srcType);
	}

}
