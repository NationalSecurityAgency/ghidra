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

import java.util.Set;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.HelpLocation;

public class ForwardSliceAction extends AbstractDecompilerAction {

	public ForwardSliceAction() {
		super("Highlight Forward Slice");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionHighlight"));
		setPopupMenuData(new MenuData(new String[] { "Highlight", "Forward Slice" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		return varnode != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		if (varnode == null) {
			return;
		}

		PcodeOp op = tokenAtCursor.getPcodeOp();
		Set<Varnode> forwardSlice = DecompilerUtils.getForwardSlice(varnode);
		DecompilerPanel decompilerPanel = context.getDecompilerPanel();
		decompilerPanel.clearPrimaryHighlights();

		SliceHighlightColorProvider colorProvider =
			new SliceHighlightColorProvider(decompilerPanel, forwardSlice, varnode, op);
		decompilerPanel.addVarnodeHighlights(forwardSlice, colorProvider);
	}

}
