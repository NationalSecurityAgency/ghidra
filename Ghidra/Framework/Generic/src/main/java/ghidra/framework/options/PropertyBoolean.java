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

// Support for a PropertyEditor that uses text.

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.*;

import javax.swing.JCheckBox;

/**
 * An implementation of PropertyComponent that is represented as a text field.
 */
public class PropertyBoolean extends JCheckBox implements ItemListener {

	private PropertyEditor editor;
	private boolean notifyEditorOfChanges = true;

	/**
	 * Constructor new PropertyText.
	 * @param pe bean property editor that is used to get the value
	 * to show in the text field
	 */
	public PropertyBoolean(PropertyEditor pe) {
		super();
		setSelected((Boolean) pe.getValue());

		editor = pe;
		addItemListener(this);

		editor.addPropertyChangeListener(new PropertyChangeListener() {
			@Override
			public void propertyChange(PropertyChangeEvent evt) {
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
			}
		});
	}

	//----------------------------------------------------------------------
	// Change listener methods.
	@Override
	public void itemStateChanged(ItemEvent e) {
		if (notifyEditorOfChanges) {
			try {
				editor.setValue(isSelected() ? Boolean.TRUE : Boolean.FALSE);
			}
			catch (IllegalArgumentException ex) {
				// Quietly ignore.
			}
		}
	}

}
