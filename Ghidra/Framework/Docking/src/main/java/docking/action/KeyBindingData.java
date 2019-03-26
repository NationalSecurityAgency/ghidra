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
package docking.action;

import java.awt.event.*;

import javax.swing.KeyStroke;

import docking.DockingUtils;
import docking.KeyBindingPrecedence;

public class KeyBindingData {
	private KeyStroke keyStroke;
	private KeyBindingPrecedence keyBindingPrecedence;

	public KeyBindingData(KeyStroke keyStroke) {
		this(keyStroke, KeyBindingPrecedence.DefaultLevel);
	}

	public KeyBindingData(char c, int modifiers) {
		this((int) Character.toUpperCase(c), modifiers);
	}

	public KeyBindingData(int keyCode, int modifiers) {
		this(KeyStroke.getKeyStroke(keyCode, modifiers));
	}

	public KeyBindingData(KeyStroke keyStroke, KeyBindingPrecedence precedence) {
		if (precedence == KeyBindingPrecedence.ReservedActionsLevel) {
			throw new IllegalArgumentException(
				"Can't set precedence to Reserved KeyBindingPrecedence");
		}
		this.keyStroke = keyStroke;
		this.keyBindingPrecedence = precedence;
	}

	/**
	 * Returns an accelerator keystroke to be associated with this action.
	 */
	public KeyStroke getKeyBinding() {
		return keyStroke;
	}

	/**
	 * Returns the keyBindingPrecedence for this action
	 */
	public KeyBindingPrecedence getKeyBindingPrecedence() {
		return keyBindingPrecedence;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[KeyStroke=" + keyStroke + ", precedence=" +
			keyBindingPrecedence + "]";
	}

	static KeyBindingData createReservedKeyBindingData(KeyStroke keyStroke) {
		KeyBindingData keyBindingData = new KeyBindingData(keyStroke);
		keyBindingData.keyBindingPrecedence = KeyBindingPrecedence.ReservedActionsLevel;
		return keyBindingData;
	}

	/**
	 * Updates the given data with system-independent versions of key modifiers.  For example, 
	 * the <tt>control</tt> key will be converted to the <tt>command</tt> key on the Mac.
	 * @param newKeyBindingData the data to validate
	 * @return the potentially changed data
	 */
	public static KeyBindingData validateKeyBindingData(KeyBindingData newKeyBindingData) {
		KeyStroke keyBinding = newKeyBindingData.getKeyBinding();
		if (keyBinding == null) {
			// not sure when this can happen
			return newKeyBindingData;
		}

		KeyBindingPrecedence precedence = newKeyBindingData.getKeyBindingPrecedence();
		if (precedence == KeyBindingPrecedence.ReservedActionsLevel) {
			return createReservedKeyBindingData(validateKeyStroke(keyBinding));
		}
		return new KeyBindingData(validateKeyStroke(keyBinding), precedence);
	}

	/**
	 * Updates the given data with system-independent versions of key modifiers.  For example, 
	 * the <tt>control</tt> key will be converted to the <tt>command</tt> key on the Mac.
	 * 
	 * @param keyStroke the keystroke to validate
	 * @return the potentially changed keystroke
	 */
	public static KeyStroke validateKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return null;
		}

		// remove system-dependent control key mask and transform deprecated modifiers
		int modifiers = keyStroke.getModifiers();
		if ((modifiers & InputEvent.CTRL_DOWN_MASK) == InputEvent.CTRL_DOWN_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_DOWN_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & InputEvent.CTRL_MASK) == InputEvent.CTRL_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK) {
			modifiers = modifiers ^ ActionEvent.CTRL_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & InputEvent.SHIFT_MASK) == InputEvent.SHIFT_MASK) {
			modifiers = modifiers ^ InputEvent.SHIFT_MASK;
			modifiers = modifiers | InputEvent.SHIFT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.ALT_MASK) == InputEvent.ALT_MASK) {
			modifiers = modifiers ^ InputEvent.ALT_MASK;
			modifiers = modifiers | InputEvent.ALT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.META_MASK) == InputEvent.META_MASK) {
			modifiers = modifiers ^ InputEvent.META_MASK;
			modifiers = modifiers | InputEvent.META_DOWN_MASK;
		}

		int eventType = keyStroke.getKeyEventType();
		if (eventType == KeyEvent.KEY_TYPED) {
			// we know that typed events have a key code of VK_UNDEFINED
			return KeyStroke.getKeyStroke(keyStroke.getKeyChar(), modifiers);
		}

		// key pressed or released
		boolean isOnKeyRelease = keyStroke.isOnKeyRelease();
		return KeyStroke.getKeyStroke(keyStroke.getKeyCode(), modifiers, isOnKeyRelease);
	}
}
