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
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.*;
import ghidra.util.*;

public class DeletePrototypeOverrideAction extends AbstractDecompilerAction {

	public DeletePrototypeOverrideAction() {
		super("Remove Signature Override");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRemoveOverride"));
		setPopupMenuData(new MenuData(new String[] { "Remove Signature Override" }, "Decompile"));
	}

	public static CodeSymbol getSymbol(Function func, ClangToken tokenAtCursor) {
		if (tokenAtCursor == null) {
			return null;
		}
		Address addr = tokenAtCursor.getMinAddress();
		if (addr == null) {
			return null;
		}
		Namespace overspace = HighFunction.findOverrideSpace(func);
		if (overspace == null) {
			return null;
		}
		SymbolTable symtab = func.getProgram().getSymbolTable();
		SymbolIterator iter = symtab.getSymbols(overspace);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!sym.getName().startsWith("prt")) {
				continue;
			}
			if (!(sym instanceof CodeSymbol)) {
				continue;
			}
			if (!sym.getAddress().equals(addr)) {
				continue;
			}
			return (CodeSymbol) sym;
		}
		return null;

	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {

		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		return getSymbol(function, context.getTokenAtCursor()) != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Function func = context.getFunction();
		CodeSymbol sym = getSymbol(func, context.getTokenAtCursor());
		Program program = func.getProgram();
		SymbolTable symtab = program.getSymbolTable();
		int transaction = program.startTransaction("Remove Override Signature");
		boolean commit = true;
		if (!symtab.removeSymbolSpecial(sym)) {
			commit = false;
			Msg.showError(getClass(), context.getDecompilerPanel(),
				"Removing Override Signature Failed", "Error removing override signature");
		}
		program.endTransaction(transaction, commit);

	}
}
