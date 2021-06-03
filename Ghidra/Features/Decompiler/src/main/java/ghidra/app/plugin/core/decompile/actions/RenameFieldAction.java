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

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.*;

/**
 * Action triggered from a specific token in the decompiler window to rename a field within
 * a structure data-type. If the field already exists within the specific structure, it is
 * simply renamed. Otherwise, if the decompiler has discovered an undefined structure offset, a new
 * field is added to the structure with this offset and the user selected name. In either case,
 * the altered structure is committed permanently to the program's database.
 */
public class RenameFieldAction extends AbstractDecompilerAction {

	public RenameFieldAction() {
		super("Rename Field");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameField"));
		setPopupMenuData(new MenuData(new String[] { "Rename Field" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		return (tokenAtCursor instanceof ClangFieldToken);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		final ClangToken tokenAtCursor = context.getTokenAtCursor();

		Structure dt = getStructDataType(tokenAtCursor);
		if (dt == null) {
			Msg.showError(this, tool.getToolFrame(), "Rename Failed",
				"Could not find structure datatype");
			return;
		}
		int offset = ((ClangFieldToken) tokenAtCursor).getOffset();
		if (offset < 0 || offset >= dt.getLength()) {
			Msg.showError(this, tool.getToolFrame(), "Rename Failed",
				"Could not resolve field within structure");
			return;
		}
		RenameStructureFieldTask nameTask =
			new RenameStructureFieldTask(tool, context.getProgram(), context.getDecompilerPanel(),
				tokenAtCursor, dt, offset);
		nameTask.runTask(true);
	}
}
