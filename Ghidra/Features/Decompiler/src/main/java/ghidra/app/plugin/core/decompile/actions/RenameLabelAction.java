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
import ghidra.app.decompiler.ClangLabelToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;

public class RenameLabelAction extends AbstractDecompilerAction {

	public RenameLabelAction() {
		super("Rename Label");

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameLabel"));

		// same keybinding as the other rename actions
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
		setPopupMenuData(new MenuData(new String[] { "Rename Label" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		return (tokenAtCursor instanceof ClangLabelToken);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Symbol s = getSymbol(context);
		if (s != null) {
			AddEditDialog dialog = new AddEditDialog("Add/Edit Label", context.getTool());
			if (s.getSource() == SourceType.DEFAULT && s.getSymbolType() == SymbolType.LABEL) {
				dialog.addLabel(s.getAddress(), context.getProgram());
			}
			else {
				dialog.editLabel(s, context.getProgram());
			}
		}
	}

}
