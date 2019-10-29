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

import javax.swing.JTextField;
import javax.swing.KeyStroke;

import docking.actions.KeyBindingUtils;

/**
 * Text field captures key strokes and notifies a listener to process the key entry.
 */
public class KeyEntryTextField extends JTextField {

	private KeyEntryListener listener;
	private String ksName;
	private KeyStroke currentKeyStroke;

	/**
	 * Construct a new entry text field.
	 * @param columns number of columns in the text field
	 * @param listener listener that is notified when the a key is pressed
	 */
	public KeyEntryTextField(int columns, KeyEntryListener listener) {
		super(columns);
		this.listener = listener;
		addKeyListener(new MyKeyListener());
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
		processEntry(ks);
		setText(parseKeyStroke(ks));
	}

	/**
	 * Converts the toString() form of the keyStroke, e.g., Ctrl-M is returned as 
	 * "keyCode CtrlM-P" and we want it to look like: "Ctrl-M"
	 * 
	 * @param ks the keystroke to parse
	 * @return the parse string for the keystroke
	 */
	public static String parseKeyStroke(KeyStroke ks) {
		return KeyBindingUtils.parseKeyStroke(ks);
	}

	public void clearField() {
		ksName = null;
		setText("");
		currentKeyStroke = null;
	}

	private void processEntry(KeyStroke ks) {
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
		listener.processEntry(ks);
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
			if (isHelpKey(keyCode)) {
				return;
			}

			KeyStroke keyStroke = null;
			if (!isClearKey(keyCode) && !isModifiersOnly(e)) {
				keyStroke = KeyStroke.getKeyStroke(keyCode, e.getModifiersEx());
			}

			processEntry(keyStroke);
			e.consume();
		}

		private boolean isHelpKey(int keyCode) {
			return keyCode == KeyEvent.VK_F1 || keyCode == KeyEvent.VK_HELP;
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
