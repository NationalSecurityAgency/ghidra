/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.context.ProgramSymbolContextAction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import docking.action.MenuData;

public class ClearPinSymbolAction extends ProgramSymbolContextAction {

	public ClearPinSymbolAction(String owner, String popupGroup) {
		super("Clear Pinned Symbol", owner);
		setPopupMenuData(new MenuData(new String[] { "Clear Pinned Symbol(s)" }, popupGroup));
		setDescription("Unpins symbol(s) so that the symbol moves with memory block moves or image base changes.");
		setHelpLocation(new HelpLocation("SymbolTablePlugin", "Pinning a Symbol"));
	}

	@Override
	protected void actionPerformed(ProgramSymbolActionContext context) {
		Program program = context.getProgram();
		int transactionID = program.startTransaction("Clear Pinned");
		try {
			for (Symbol symbol : context.getSymbols()) {
				if (symbol.isPinned()) {
					symbol.setPinned(false);
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
			if (symbol.isPinned()) {
				return true;
			}
		}
		return false;
	}

}
