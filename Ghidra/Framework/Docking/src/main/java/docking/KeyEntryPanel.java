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
package docking;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import resources.Icons;

/**
 * A panel that holds a {@link KeyEntryTextField} and a button for clearing the current key binding.
 * <p>
 * This class is a drop-in replacement for clients that are currently using 
 * {@link KeyEntryTextField}.
 */
public class KeyEntryPanel extends JPanel {

	private KeyEntryTextField keyEntryField;
	private JButton clearButton;

	/**
	 * Constructs this class with a text field based on the number of given columns.
	 * @param columns the number of columns for the text field
	 * @param listener the listener to be called as the user enters key strokes
	 */
	public KeyEntryPanel(int columns, KeyEntryListener listener) {

		setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));

		keyEntryField = new KeyEntryTextField(columns, listener);
		clearButton = new EmptyBorderButton(Icons.DELETE_ICON);
		clearButton.setName("Clear Key Binding");
		clearButton.addActionListener(e -> keyEntryField.clearKeyStroke());

		add(keyEntryField);
		add(Box.createHorizontalStrut(2));
		add(clearButton);
	}

	/**
	 * Returns the text field used by this class
	 * @return the text field
	 */
	public JTextField getTextField() {
		return keyEntryField;
	}

	/**
	 * Sets the key stroke on this panel
	 * @param ks the key stroke
	 */
	public void setKeyStroke(KeyStroke ks) {
		keyEntryField.setKeyStroke(ks);
	}

	/**
	 * Gets the key stroke being used by this panel
	 * @return the key stroke
	 */
	public KeyStroke getKeyStroke() {
		return keyEntryField.getKeyStroke();
	}

	/**
	 * Sets the text field hint for this panel.  
	 * 
	 * @param disabledHint the hint
	 * @see KeyEntryTextField#setDisabledHint(String)
	 */
	public void setDisabledHint(String disabledHint) {
		keyEntryField.setDisabledHint(disabledHint);
	}

	/**
	 * Clears the key stroke being used by this panel
	 */
	public void clearField() {
		keyEntryField.clearField();
	}
}
