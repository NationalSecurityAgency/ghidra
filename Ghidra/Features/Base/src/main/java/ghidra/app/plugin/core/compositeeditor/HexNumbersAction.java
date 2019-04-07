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
package ghidra.app.plugin.core.compositeeditor;

import javax.swing.JMenuItem;

import docking.ActionContext;
import docking.DockingCheckBoxMenuItem;
import docking.action.ToggleDockingActionIf;
import docking.menu.DockingCheckboxMenuItemUI;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class HexNumbersAction extends CompositeEditorAction implements ToggleDockingActionIf {

	private final static String ACTION_NAME = "Show Numbers In Hex";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static String defaultDescription = "Show Numbers in Hexadecimal";
	private static String[] defaultPath = new String[] { defaultDescription };
	private boolean isSelected;

	/**
	 * @param name
	 * @param group
	 * @param owner
	 * @param popupPath
	 * @param menuPath
	 * @param icon
	 * @param useToolbar
	 * @param checkBox
	 */
	public HexNumbersAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, defaultPath, defaultPath,
			null);
		setDescription(defaultDescription);
		setEnabled(true);
		setSelected(model.isShowingNumbersInHex());
	}

	/* (non-Javadoc)
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		model.displayNumbersInHex(!model.isShowingNumbersInHex());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.compositeeditor.CompositeEditorAction#adjustEnablement()
	 */
	@Override
	public void adjustEnablement() {
		// Always enabled.
	}

	public boolean isSelected() {
		return isSelected;
	}

	public void setSelected(boolean newValue) {
		isSelected = newValue;
		firePropertyChanged(SELECTED_STATE_PROPERTY, !isSelected, isSelected);
	}

	@Override
	protected JMenuItem doCreateMenuItem() {
		DockingCheckBoxMenuItem menuItem = new DockingCheckBoxMenuItem(isSelected);
		menuItem.setUI((DockingCheckboxMenuItemUI) DockingCheckboxMenuItemUI.createUI(menuItem));
		return menuItem;
	}
}
