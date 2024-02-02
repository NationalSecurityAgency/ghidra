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
package ghidra.framework.options;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyEditor;

import javax.swing.JCheckBox;

/**
 * A basic editor for booleans.
 */
public class PropertyBoolean extends JCheckBox implements ItemListener {

	private PropertyEditor editor;
	private boolean notifyEditorOfChanges = true;

	/**
	 * Constructor
	 * @param pe bean property editor that is used to get the value to show in the text field
	 */
	public PropertyBoolean(PropertyEditor pe) {
		editor = pe;
		setSelected((Boolean) pe.getValue());
		addItemListener(this);

		editor.addPropertyChangeListener(evt -> {
			Object value = editor.getValue();
			if ((value instanceof Boolean) && !value.equals(getText())) {
				notifyEditorOfChanges = false;
				try {
					setSelected((Boolean) value);
				}
				finally {
					notifyEditorOfChanges = true;
				}
			}
		});
	}

	@Override
	public void itemStateChanged(ItemEvent e) {
		if (notifyEditorOfChanges) {
			editor.setValue(isSelected() ? Boolean.TRUE : Boolean.FALSE);
		}
	}
}
