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
package ghidra.app.plugin.core.decompile.actions;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.AddEditDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;

import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;

public class RenameFunctionAction extends DockingAction {

	private final DecompilerController controller;
	private final PluginTool tool;

	public RenameFunctionAction(String owner, PluginTool tool, DecompilerController controller) {
		super("Rename Function", owner);
		this.tool = tool;
		this.controller = controller;

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
		setPopupMenuData(new MenuData(new String[] { "Rename Function" }, "Decompile"));
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

		return getFunction() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(),
				context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked", "You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		Function function = getFunction();
		AddEditDialog dialog = new AddEditDialog("Edit Function Name", tool);
		dialog.editLabel(function.getSymbol(), controller.getProgram());
	}

	private Function getFunction() {
		// try to look up the function that is at the current cursor location
		//   If there isn't one, just use the function we are in.
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return DecompilerUtils.getFunction(controller.getProgram(),
				(ClangFuncNameToken) tokenAtCursor);
		}
		return null;
	}
}
