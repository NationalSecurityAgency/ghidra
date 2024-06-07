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
package ghidra.features.codecompare.decompile;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.event.KeyEvent;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.widgets.FindDialog;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.actions.DecompilerSearcher;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

public class DecompilerDiffViewFindAction extends DockingAction {

	private Duo<FindDialog> findDialogs;
	private PluginTool tool;

	public DecompilerDiffViewFindAction(String owner, PluginTool tool) {
		super("Find", owner, true);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));
		setPopupMenuData(new MenuData(new String[] { "Find..." }, "Decompile"));
		setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_F, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		setEnabled(true);
		this.tool = tool;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof DualDecompilerActionContext);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return (context instanceof DualDecompilerActionContext);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DualDecompilerActionContext dualContext = (DualDecompilerActionContext) context;
		DecompilerCodeComparisonPanel decompilerCompPanel =
			dualContext.getCodeComparisonPanel();

		Side focusedSide = decompilerCompPanel.getActiveSide();
		DecompilerPanel focusedPanel = decompilerCompPanel.getDecompilerPanel(focusedSide);
		FindDialog dialog = findDialogs.get(focusedSide);
		if (dialog == null) {
			dialog = createFindDialog(focusedPanel, focusedSide);
			findDialogs = findDialogs.with(focusedSide, dialog);
		}

		String text = focusedPanel.getSelectedText();
		if (!StringUtils.isBlank(text)) {
			dialog.setSearchText(text);
		}
		tool.showDialog(dialog);
	}

	private FindDialog createFindDialog(DecompilerPanel decompilerPanel, Side side) {
		String title = (side == LEFT ? "Left" : "Right");
		title += " Decompiler Find Text";

		FindDialog dialog = new FindDialog(title, new DecompilerSearcher(decompilerPanel)) {
			@Override
			protected void dialogClosed() {
				// clear the search results when the dialog is closed
				decompilerPanel.setSearchResults(null);
			}
		};
		dialog.setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));

		return dialog;
	}

}
