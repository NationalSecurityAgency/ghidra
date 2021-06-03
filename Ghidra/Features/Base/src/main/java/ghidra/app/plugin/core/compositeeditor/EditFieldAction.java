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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class EditFieldAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Edit Component Field";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static String DESCRIPTION =
		"Edit the first editable field of the selected component.";
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_F2, 0);
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };
	private static String[] MENU_PATH = new String[] { ACTION_NAME };

	public EditFieldAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, MENU_PATH, null);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (model != null) {
			int row = model.getRow();
			int column = model.getColumn();
			if (model.isCellEditable(row, column)) {
				model.beginEditingField(row, column);
				return;
			}

			// just go to the first editable cell, since the current one is not editable
			int firstEditableColumn = model.getFirstEditableColumn(row);
			model.beginEditingField(row, firstEditableColumn);
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		boolean shouldEnableEdit = false;
		if (model.isSingleRowSelection()) {
			int[] rows = model.getSelectedRows();
			int firstEditableColumn = model.getFirstEditableColumn(rows[0]);
			shouldEnableEdit = model.isEditFieldAllowed(rows[0], firstEditableColumn);
		}
		setEnabled(shouldEnableEdit);
	}

}
