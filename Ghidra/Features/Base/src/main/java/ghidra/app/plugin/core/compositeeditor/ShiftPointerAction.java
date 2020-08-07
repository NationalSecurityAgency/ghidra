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

import static docking.KeyBindingPrecedence.*;

import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.UsrException;
import resources.ResourceManager;

/**
 * Action to shift a pointer by a specific offset
 */
public class ShiftPointerAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Shift Pointer";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Shift selected pointer by an offset";
	private final static ImageIcon ICON = ResourceManager.loadImage("images/red-cross.png");
	private final static String[] POPUP_PATH = new String[] { "Shift Pointer" };
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_T, 0);

	public ShiftPointerAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE, DefaultLevel));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			int row = model.getRow();
			if (row < model.getNumComponents()) {
				DataTypeComponent comp = model.getComponent(row);
				Pointer origPointer = (Pointer) comp.getDataType();
				NumberInputDialog dialog = new NumberInputDialog("Shift Pointer", "Offset:", origPointer.getShiftOffset(), Integer.MIN_VALUE, Integer.MAX_VALUE, true);
				tool.showDialog(dialog);
				if (!dialog.wasCancelled()) {
					Pointer shiftedPointer = new PointerDataType(origPointer.getDataType(), dialog.getValue(), origPointer.isDynamicallySized() ? -1 : origPointer.getLength(), origPointer.getDataTypeManager());
					model.setComponentDataType(row, shiftedPointer);
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
		boolean enabled = true;
		enabled &= model.isEditComponentAllowed();
		int row = model.getRow();
		if (row < model.getNumComponents()) {
			DataTypeComponent comp = model.getComponent(row);
			enabled &= comp.getDataType() instanceof Pointer;
		}
		setEnabled(enabled);
	}
}
