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
package ghidra.framework.options;

// Support for a PropertyEditor that uses text.

import java.beans.*;

import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * An implementation of PropertyComponent that is represented as a text field.
 */
public class PropertyText extends JTextField {

	private final static int NUMBER_OF_COLUMNS = 12;
	private PropertyEditor editor;
	private boolean isEditing = false;

	/**
	 * Constructor new PropertyText.
	 * @param pe bean property editor that is used to get the value
	 * to show in the text field
	 */
	public PropertyText(PropertyEditor pe) {
		super(pe.getAsText(), NUMBER_OF_COLUMNS);
		int len = getText().length();
		len = Math.max(NUMBER_OF_COLUMNS, len);
		len = Math.min(len, 40);
		setColumns(len);

		editor = pe;
		getDocument().addDocumentListener(new UpdateDocumentListener());

		editor.addPropertyChangeListener(new PropertyChangeListener() {
			@Override
			public void propertyChange(PropertyChangeEvent evt) {
				if (!isEditing) {
					setText(editor.getAsText());
				}
			}
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class UpdateDocumentListener implements DocumentListener {
		@Override
		public void insertUpdate(DocumentEvent e) {
			update();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			update();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			update();
		}

		private void update() {
			isEditing = true;
			try {
				editor.setAsText(getText());
			}
			catch (IllegalArgumentException ex) {
				// ignore
			}
			finally {
				isEditing = false;
			}
		}
	}
}
