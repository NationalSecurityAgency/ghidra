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
import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UndefinedFunction;

public class CommitLocalsAction extends AbstractDecompilerAction {
	private final DecompilerController controller;

	public CommitLocalsAction(PluginTool tool, DecompilerController controller) {
		super("Commit Locals");
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Commit Locals" }, "Commit"));
		setDescription(
			"Save Local variable definitions to Program, locking them into their current type definitions");
	}

	private HighFunction getHighFunction() {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return null;
		}
		ClangFunction clfunc = tokenAtCursor.getClangFunction();
		if (clfunc == null) {
			return null;
		}
		return clfunc.getHighFunction();
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = controller.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}
		return getHighFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = controller.getProgram();
		int transaction = program.startTransaction("Commit Params/Return");
		try {
			HighFunction hfunc = getHighFunction();
			HighFunctionDBUtil.commitLocalsToDatabase(hfunc, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}
}
