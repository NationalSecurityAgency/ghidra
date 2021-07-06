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

import java.util.List;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.HelpLocation;

public class RemoveEquateAction extends AbstractDecompilerAction {

	public RemoveEquateAction() {
		super("Remove Equate");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRemoveEquate"));
		setPopupMenuData(new MenuData(new String[] { "Remove Convert/Equate" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangVariableToken)) {
			return false;
		}
		Varnode convertVn = tokenAtCursor.getVarnode();
		if (convertVn == null || !convertVn.isConstant()) {
			return false;
		}
		HighSymbol symbol = convertVn.getHigh().getSymbol();
		return (symbol instanceof EquateSymbol);
	}

	private void removeReference(Program program, Equate equate, Address refAddr,
			long convertHash) {
		int transaction = program.startTransaction("Remove Equate Reference");
		boolean commit = false;
		try {
			if (equate.getReferenceCount() <= 1) {
				program.getEquateTable().removeEquate(equate.getName());
			}
			else {
				equate.removeReference(convertHash, refAddr);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}

	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangVariableToken)) {
			return;
		}
		Varnode convertVn = tokenAtCursor.getVarnode();
		if (convertVn == null || !convertVn.isConstant()) {
			return;
		}
		HighSymbol convertSymbol = convertVn.getHigh().getSymbol();
		if (convertSymbol instanceof EquateSymbol) {
			Address convertAddr = convertSymbol.getPCAddress();
			SymbolEntry entry = convertSymbol.getFirstWholeMap();
			if (!(entry instanceof DynamicEntry)) {
				return;
			}
			long convertHash = ((DynamicEntry) entry).getHash();
			Program program = context.getProgram();
			EquateTable equateTable = program.getEquateTable();
			List<Equate> equates = equateTable.getEquates(convertAddr);
			for (Equate equate : equates) {
				if (equate.getValue() != convertVn.getOffset()) {
					continue;
				}
				removeReference(program, equate, convertAddr, convertHash);
				break;
			}
		}
	}

}
