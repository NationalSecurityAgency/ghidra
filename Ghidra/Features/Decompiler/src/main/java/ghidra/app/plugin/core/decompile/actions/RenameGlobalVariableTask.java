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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameGlobalVariableTask extends RenameTask {
	private Address address; // Address of global variable
	private SymbolTable symboltable;
	private Symbol symbol;

	public RenameGlobalVariableTask(PluginTool tool, Program program, DecompilerPanel panel,
			ClangToken token, Address addr) {
		super(tool, program, panel, token, token.getText());
		address = addr;
		symboltable = program.getSymbolTable();
		symbol = null;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		if (symbol != null) {
			symbol.setName(newName, SourceType.USER_DEFINED);
		}
		else {
			symboltable.createLabel(address, newName, SourceType.USER_DEFINED);
		}
	}

	@Override
	public String getTransactionName() {
		return "Rename Global Variable";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		Symbol dupsym = symboltable.getGlobalSymbol(newName, address);
		if (dupsym != null) {
			errorMsg = "Duplicate symbol name";
			return false;
		}
		symbol = symboltable.getPrimarySymbol(address);

		return true;
	}

}
