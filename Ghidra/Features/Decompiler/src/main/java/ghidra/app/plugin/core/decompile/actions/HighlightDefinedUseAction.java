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

import java.util.HashSet;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.pcode.Varnode;

public class HighlightDefinedUseAction extends AbstractDecompilerAction {
	private final DecompilerController controller;

	public HighlightDefinedUseAction(DecompilerController controller) {
		super("Highlight Defined Use");
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Highlight Def-use" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		return varnode != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		if (varnode != null) {
			HashSet<Varnode> varnodes = new HashSet<Varnode>();
			varnodes.add(varnode);
			decompilerPanel.clearHighlights();
			decompilerPanel.addVarnodeHighlights(varnodes,
				decompilerPanel.getDefaultHighlightColor(), varnode, varnode.getDef(),
				decompilerPanel.getDefaultSpecialColor());
			decompilerPanel.repaint();
		}
	}

}
