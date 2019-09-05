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

import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;
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
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.*;

public class CommitParamsAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public CommitParamsAction(String owner, PluginTool tool, DecompilerController controller) {
		super("Commit Params/Return", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Commit Params/Return" }, "Commit"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, 0));
		setDescription(
			"Save Parameters/Return definitions to Program, locking them into their current type definitions");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		Function function = controller.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}
		return getHighFunction() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		Program program = controller.getProgram();
		int transaction = program.startTransaction("Commit Params/Return");
		try {
			HighFunction hfunc = getHighFunction();
			SourceType source = SourceType.ANALYSIS;
			if (hfunc.getFunction().getSignatureSource() == SourceType.USER_DEFINED) {
				source = SourceType.USER_DEFINED;
			}
			
			HighFunctionDBUtil.commitReturnToDatabase(hfunc, source);
			HighFunctionDBUtil.commitParamsToDatabase(hfunc, true, source);
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception", e);
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Parameter Commit Failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private HighFunction getHighFunction() {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();

		// getTokenAtCursor can explicitly return null, so we must check here
		// before dereferencing it.
		if (tokenAtCursor == null) {
			return null;
		}

		ClangFunction clfunc = tokenAtCursor.getClangFunction();
		if (clfunc == null) {
			return null;
		}
		return clfunc.getHighFunction();
	}
}
