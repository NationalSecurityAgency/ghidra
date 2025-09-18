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
package ghidra.app.plugin.core.symboltree.actions;

import docking.action.MenuData;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.context.ProgramSymbolContextAction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.HelpLocation;

public class PinSymbolAction extends ProgramSymbolContextAction {

	public PinSymbolAction(String owner, String popupGroup) {
		super("Pin Symbol", owner);
		setPopupMenuData(new MenuData(new String[] { "Set Pinned" }, popupGroup));
		setDescription(
			"Pins the symbol(s) to the address so that it is unaffected by memory block moves or image base changes.");
		setHelpLocation(new HelpLocation("SymbolTablePlugin", "Pinning a Symbol"));
	}

	private boolean canPinSymbol(Symbol symbol) {
		SymbolType type = symbol.getSymbolType();
		return (type == SymbolType.LABEL || type == SymbolType.FUNCTION) && !symbol.isExternal() &&
			!symbol.isPinned();
	}

	@Override
	protected void actionPerformed(ProgramSymbolActionContext context) {
		Program program = context.getProgram();
		int transactionID = program.startTransaction("Pin Symbol(s)");
		try {
			for (Symbol symbol : context.getSymbols()) {
				if (canPinSymbol(symbol)) {
					symbol.setPinned(true);
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	@Override
	protected boolean isEnabledForContext(ProgramSymbolActionContext context) {
		for (Symbol symbol : context.getSymbols()) {
			if (canPinSymbol(symbol)) {
				return true;
			}
		}
		return false;
	}

}
