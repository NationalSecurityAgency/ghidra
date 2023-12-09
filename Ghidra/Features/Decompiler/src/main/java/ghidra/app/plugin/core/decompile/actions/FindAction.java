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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import org.apache.commons.lang3.StringUtils;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.FindDialog;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

public class FindAction extends AbstractDecompilerAction {
	private FindDialog findDialog;

	public FindAction() {
		super("Find");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));
		setPopupMenuData(new MenuData(new String[] { "Find..." }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));
		setEnabled(true);
	}

	@Override
	public void dispose() {
		if (findDialog != null) {
			findDialog.dispose();
		}
		super.dispose();
	}

	protected FindDialog getFindDialog(DecompilerPanel decompilerPanel) {
		if (findDialog == null) {
			findDialog =
				new FindDialog("Decompiler Find Text", new DecompilerSearcher(decompilerPanel)) {
					@Override
					protected void dialogClosed() {
						// clear the search results when the dialog is closed
						decompilerPanel.setSearchResults(null);
					}
				};
			findDialog.setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));
		}
		return findDialog;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		DecompilerPanel decompilerPanel = context.getDecompilerPanel();
		FindDialog dialog = getFindDialog(decompilerPanel);
		String text = decompilerPanel.getSelectedText();
		if (text == null) {
			text = decompilerPanel.getHighlightedText();

			// note: if we decide to grab the text under the cursor, then use
			// text = decompilerPanel.getTextUnderCursor();
		}

		if (!StringUtils.isBlank(text)) {
			dialog.setSearchText(text);
		}

		// show over the root frame, so the user can still see the Decompiler window
		context.getTool().showDialog(dialog);
	}
}
