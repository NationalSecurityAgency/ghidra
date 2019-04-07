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

import java.awt.event.*;

import javax.swing.JTextField;

import docking.widgets.table.GTableTextCellEditor;

/**
 * ComponentCellEditor provides the editor for each editable field in a 
 * component of a composite data type.
 */
class ComponentCellEditor extends GTableTextCellEditor {

	private KeyListener keyListener;
	ComponentCellEditorListener listener;

	public ComponentCellEditor(JTextField field) {
		super(field);
		keyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keycode = e.getKeyCode();
				switch (keycode) {
					case KeyEvent.VK_TAB:
						if (e.isShiftDown()) {
							move(ComponentCellEditorListener.PREVIOUS);
						}
						else {
							move(ComponentCellEditorListener.NEXT);
						}
						e.consume();
						break;
					case KeyEvent.VK_DOWN:
						move(ComponentCellEditorListener.DOWN);
						e.consume();
						break;
					case KeyEvent.VK_UP:
						move(ComponentCellEditorListener.UP);
						e.consume();
						break;
					default:
						break;
				}
			}
		};
		field.addKeyListener(keyListener);
	}

	private void move(int direction) {
		if (listener != null) {
			JTextField textField = (JTextField) this.getComponent();
			listener.moveCellEditor(direction, textField.getText());
		}
	}

	void setComponentCellEditorListener(ComponentCellEditorListener listener) {
		this.listener = listener;
	}

	void removeComponentCellEditorListener() {
		this.listener = null;
	}
}
