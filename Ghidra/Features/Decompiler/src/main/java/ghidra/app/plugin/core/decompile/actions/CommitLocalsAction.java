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
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;

public class CommitLocalsAction extends AbstractDecompilerAction {

	public CommitLocalsAction() {
		super("Commit Locals");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionCommitLocals"));
		setPopupMenuData(new MenuData(new String[] { "Commit Local Names" }, "Commit"));
		setDescription(
			"Save Local variable names from Decompiler window to Program");
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}
		return context.getHighFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		int transaction = program.startTransaction("Commit Local Names");
		try {
			HighFunction hfunc = context.getHighFunction();
			HighFunctionDBUtil.commitLocalNamesToDatabase(hfunc, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}
}
