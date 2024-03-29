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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class DeletePrototypeOverrideAction extends AbstractDecompilerAction {

	public DeletePrototypeOverrideAction() {
		super("Remove Signature Override");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRemoveOverride"));
		setPopupMenuData(new MenuData(new String[] { "Remove Signature Override" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {

		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		return OverridePrototypeAction.getSymbol(function, context.getTokenAtCursor()) != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Function func = context.getFunction();
		Symbol sym = OverridePrototypeAction.getSymbol(func, context.getTokenAtCursor());
		if (sym == null) {
			return;
		}
		Program program = func.getProgram();
		int txId = program.startTransaction("Remove Override Signature");
		try {
			DataTypeSymbol dts = HighFunctionDBUtil.readOverride(sym);
			sym.delete();
			dts.cleanupUnusedOverride();
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

}
