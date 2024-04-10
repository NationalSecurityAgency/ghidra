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

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Objects;

import javax.swing.KeyStroke;

import docking.actions.KeyBindingUtils;
import docking.widgets.textfield.HintTextField;

/**
 * Text field captures key strokes and notifies a listener to process the key entry.
 */
public class KeyEntryTextField extends HintTextField {

	private static final String HINT = "Type a key";
	private String disabledHint = HINT;

	private KeyEntryListener listener;
	private String ksName;
	private KeyStroke currentKeyStroke;

	/**
	 * Construct a new entry text field.
	 * @param columns number of columns in the text field
	 * @param listener listener that is notified when the a key is pressed
	 */
	public KeyEntryTextField(int columns, KeyEntryListener listener) {
		super(HINT);
		setName("Key Entry Text Field");
		getAccessibleContext().setAccessibleName(getName());
		setColumns(columns);
		this.listener = listener;
		addKeyListener(new MyKeyListener());
	}

	@Override
	public void setEnabled(boolean enabled) {
		setHint(enabled ? HINT : disabledHint);
		super.setEnabled(enabled);
	}

	/**
	 * Sets the hint text that will be displayed when this field is disabled
	 * @param disabledHint the hint text
	 */
	public void setDisabledHint(String disabledHint) {
		this.disabledHint = Objects.requireNonNull(disabledHint);
	}

	/**
	 * Get the current key stroke
	 * @return the key stroke
	 */
	public KeyStroke getKeyStroke() {
		return currentKeyStroke;
	}

	/**
	 * Sets the current key stroke
	 * @param ks the new key stroke
	 */
	public void setKeyStroke(KeyStroke ks) {
		processKeyStroke(ks, false);
		setText(KeyBindingUtils.parseKeyStroke(ks));
	}

	public void clearField() {
		ksName = null;
		setText("");
		currentKeyStroke = null;
	}

	private void processKeyStroke(KeyStroke ks, boolean notify) {
		ksName = null;

		currentKeyStroke = ks;

		// Clear entry if enter or backspace
		if (ks != null) {
			char keyChar = ks.getKeyChar();
			if (!Character.isWhitespace(keyChar) &&
				Character.getType(keyChar) != Character.DIRECTIONALITY_LEFT_TO_RIGHT_OVERRIDE) {
				ksName = KeyBindingUtils.parseKeyStroke(ks);
			}
		}

		if (notify) {
			listener.processEntry(ks);
		}
	}

	private class MyKeyListener implements KeyListener {

		@Override
		public void keyTyped(KeyEvent e) {
			e.consume();
		}

		@Override
		public void keyReleased(KeyEvent e) {
			if (ksName != null) {
				setText(ksName);
			}
			else {
				setText("");
			}
			e.consume();
		}

		@Override
		public void keyPressed(KeyEvent e) {
			int keyCode = e.getKeyCode();
			KeyStroke keyStroke = null;
			if (!isClearKey(keyCode) && !isModifiersOnly(e)) {
				keyStroke = KeyStroke.getKeyStroke(keyCode, e.getModifiersEx());
			}
			processKeyStroke(keyStroke, true);
			e.consume();
		}

		private boolean isClearKey(int keyCode) {
			return keyCode == KeyEvent.VK_BACK_SPACE || keyCode == KeyEvent.VK_ENTER;
		}

		private boolean isModifiersOnly(KeyEvent event) {
			String keyText = KeyEvent.getKeyText(event.getKeyCode());
			return keyText.equals(KeyEvent.getKeyText(KeyEvent.VK_CONTROL)) ||
				keyText.equals(KeyEvent.getKeyText(KeyEvent.VK_ALT)) ||
				keyText.equals(KeyEvent.getKeyText(KeyEvent.VK_SHIFT)) ||
				keyText.equals(KeyEvent.getKeyText(KeyEvent.VK_META));
		}
	}
}
