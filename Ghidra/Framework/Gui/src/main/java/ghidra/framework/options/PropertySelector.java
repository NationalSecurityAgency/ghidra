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

// Support for PropertyEditors that use tags.
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.*;

import javax.swing.JComboBox;

/**
 * An implementation of a PropertyComponent that is represented as a
 * combo box.
 */
public class PropertySelector extends JComboBox<String> implements ItemListener {

	private PropertyEditor propertyEditor;
	private boolean notifyEditorOfChanges = true;

	/**
	 * Constructor.
	 * @param pe bean property editor that is updated when the state
	 * changes in the combo box
	 */
	public PropertySelector(PropertyEditor pe) {
		propertyEditor = pe;
		String tags[] = propertyEditor.getTags();
		for (String tag : tags) {
			addItem(tag);
		}

		setSelectedIndex(0);

		// This is a no-op if the getAsText is not a tag that we set from getTags() above
		setSelectedItem(propertyEditor.getAsText());
		addItemListener(this);
		invalidate();

		propertyEditor.addPropertyChangeListener(new PropertyChangeListener() {
			@Override
			public void propertyChange(PropertyChangeEvent evt) {
				String value = propertyEditor.getAsText();
				if (!value.equals(getSelectedItem())) {
					notifyEditorOfChanges = false;
					try {
						setSelectedItem(value);
					}
					finally {
						notifyEditorOfChanges = true;
					}
				}
			}
		});
	}

	@Override
	public void itemStateChanged(ItemEvent evt) {
		if (!notifyEditorOfChanges) {
			return;
		}

		String s = (String) getSelectedItem();
		if (s != null) {
			propertyEditor.setAsText(s);
		}
	}
}
