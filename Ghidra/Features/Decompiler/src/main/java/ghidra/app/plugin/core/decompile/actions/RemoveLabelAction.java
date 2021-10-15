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

import javax.swing.KeyStroke;

import docking.action.*;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.decompiler.ClangLabelToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;

public class RemoveLabelAction extends AbstractDecompilerAction {

	private static final String[] POPUP_PATH = { "Remove Label" };
	private static final KeyStroke KEYBINDING = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);

	public RemoveLabelAction() {
		super("Remove Label", KeyBindingType.SHARED);

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRemoveLabel"));

		// same keybinding as the other remove actions
		setPopupMenuData(new MenuData(POPUP_PATH, "Decompile"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangLabelToken)) {
			return false;
		}

		Symbol symbol = getSymbol(context);
		return canRemoveSymbol(symbol);
	}

	private boolean canRemoveSymbol(Symbol s) {
		return s != null && s.getSource() != SourceType.DEFAULT && !s.isExternal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Symbol s = getSymbol(context);
		Command cmd = new DeleteLabelCmd(s.getAddress(), s.getName(), s.getParentNamespace());
		PluginTool tool = context.getTool();
		if (!tool.execute(cmd, context.getProgram())) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}
}
