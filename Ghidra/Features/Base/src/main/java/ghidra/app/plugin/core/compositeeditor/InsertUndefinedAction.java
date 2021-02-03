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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import ghidra.program.model.data.*;
import ghidra.util.exception.UsrException;
import resources.ResourceManager;

/**
 * Action for use in the structure data type editor.
 * This action has help associated with it.
 */
public class InsertUndefinedAction extends CompositeEditorTableAction {

	private final static ImageIcon ICON =
		ResourceManager.loadImage("images/Plus.png");
	public final static String ACTION_NAME = "Insert Undefined Byte";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Insert an undefined byte before the selection";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	private final static KeyStroke KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_U, InputEvent.ALT_DOWN_MASK);

	public InsertUndefinedAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			boolean isContiguousSelection = model.getSelection().getNumRanges() == 1;
			if (isContiguousSelection) {
				int index = model.getMinIndexSelected();
				if (index >= 0) {
					DataType undefinedDt =
						model.viewComposite.isPackingEnabled() ? Undefined1DataType.dataType
								: DataType.DEFAULT;
					DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(undefinedDt, -1);
					model.insert(index, dti.getDataType(), dti.getLength());
				}
			}
		}
		catch (UsrException e1) {
			model.setStatus(e1.getMessage());
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		boolean enabled = false;
		if (model.viewComposite instanceof Structure) {
			boolean isContiguousSelection = model.getSelection().getNumRanges() == 1;
			DataType undefinedDt =
				model.viewComposite.isPackingEnabled() ? Undefined1DataType.dataType
						: DataType.DEFAULT;
			enabled = isContiguousSelection &&
				model.isInsertAllowed(model.getMinIndexSelected(), undefinedDt);
		}
		setEnabled(enabled);
	}

}
