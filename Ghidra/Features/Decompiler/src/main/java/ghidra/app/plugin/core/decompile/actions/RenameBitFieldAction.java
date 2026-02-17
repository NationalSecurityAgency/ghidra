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
import ghidra.app.decompiler.ClangBitFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class RenameBitFieldAction extends AbstractDecompilerAction {

	public RenameBitFieldAction() {
		super("Rename BitField");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameField"));
		setPopupMenuData(new MenuData(new String[] { "Rename BitField" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		return (tokenAtCursor instanceof ClangBitFieldToken);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		ClangBitFieldToken tokenAtCursor = (ClangBitFieldToken) context.getTokenAtCursor();

		RenameTask nameTask = new RenameStructBitFieldTask(tool, context.getProgram(),
			context.getComponentProvider(), tokenAtCursor);
		nameTask.runTask(true);
	}

}
