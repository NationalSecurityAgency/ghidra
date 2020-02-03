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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameVariableTask extends RenameTask {

	private HighSymbol highSymbol;
	private Varnode exactSpot;
	private HighFunction hfunction;
	private Function function;
	private boolean commitRequired; // Set to true if all parameters are committed before renaming
	private SourceType srctype;		// Desired source type for the variable being renamed
	private SourceType signatureSrcType;	// Signature source type of the function (which will be preserved)

	public RenameVariableTask(PluginTool tool, Program program, DecompilerPanel panel,
			ClangToken token, HighSymbol sym, SourceType st) {
		super(tool, program, panel, token, sym.getName());
		highSymbol = sym;
		exactSpot = token.getVarnode();
		hfunction = sym.getHighFunction();
		function = hfunction.getFunction();
		srctype = st;
		signatureSrcType = function.getSignatureSource();
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		if (commitRequired) {
			HighFunctionDBUtil.commitParamsToDatabase(hfunction, false, signatureSrcType);
			if (signatureSrcType != SourceType.DEFAULT) {
				HighFunctionDBUtil.commitReturnToDatabase(hfunction, signatureSrcType);
			}
		}
		HighFunctionDBUtil.updateDBVariable(highSymbol, newName, null, srctype);
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		if (localSymbolMap.containsVariableWithName(newName) ||
			isSymbolInFunction(function, newName)) {
			errorMsg = "Duplicate name";
			return false;
		}
		commitRequired = AbstractDecompilerAction.checkFullCommit(highSymbol, hfunction);
		if (commitRequired) {
			exactSpot = null; // Don't try to split out if we need to commit
		}

		if (exactSpot != null && !highSymbol.isNameLocked()) { // The user pointed at a particular usage, not just the vardecl
			try {
				HighVariable var = hfunction.splitOutMergeGroup(exactSpot.getHigh(), exactSpot);
				highSymbol = var.getSymbol();
			}
			catch (PcodeException e) {
				errorMsg = "Rename Failed: " + e.getMessage();
				return false;
			}
		}
		if (highSymbol == null) {
			errorMsg = "Rename Failed: No symbol";
			return false;
		}
		return true;
	}

	@Override
	public String getTransactionName() {
		return "Rename Local Variable";
	}
}
