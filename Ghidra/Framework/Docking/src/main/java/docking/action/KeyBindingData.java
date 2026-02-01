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

import java.util.Objects;

import javax.swing.KeyStroke;

import docking.KeyBindingPrecedence;
import docking.actions.KeyBindingUtils;
import ghidra.framework.options.ActionTrigger;
import gui.event.MouseBinding;

/**
 * A class for storing an action's key stroke, mouse binding or both.
 * <p>
 * Note: this class creates key strokes that work on key {@code pressed}.  This effectively
 * normalizes all client key bindings to work on the same type of key stroke (pressed, typed or
 * released).
 */
public class KeyBindingData {
	private KeyStroke keyStroke;
	private KeyBindingPrecedence keyBindingPrecedence = KeyBindingPrecedence.DefaultLevel;

	private MouseBinding mouseBinding;

	public KeyBindingData(KeyStroke keyStroke) {
		this(keyStroke, KeyBindingPrecedence.DefaultLevel);
	}

	public KeyBindingData(char c, int modifiers) {
		this((int) Character.toUpperCase(c), modifiers);
	}

	public KeyBindingData(int keyCode, int modifiers) {
		this(KeyStroke.getKeyStroke(keyCode, modifiers));
	}

	/**
	 * Constructs an instance of this class that uses a mouse binding instead of a key stroke.
	 * @param mouseBinding the mouse binding.
	 */
	public KeyBindingData(MouseBinding mouseBinding) {
		this.mouseBinding = Objects.requireNonNull(mouseBinding);
	}

	/**
	 * Creates a key stroke from the given text.  See
	 * {@link KeyBindingUtils#parseKeyStroke(KeyStroke)}.   The key stroke created for this class
	 * will always be a key {@code pressed} key stroke.
	 *
	 * @param keyStrokeString the key stroke string to parse
	 */
	public KeyBindingData(String keyStrokeString) {
		this(parseKeyStrokeString(keyStrokeString));
	}

	/**
	 * Creates a key binding data with the given action trigger.
	 * @param actionTrigger the trigger; may not be null
	 */
	public KeyBindingData(ActionTrigger actionTrigger) {
		Objects.requireNonNull(actionTrigger);
		this.keyStroke = actionTrigger.getKeyStroke();
		this.mouseBinding = actionTrigger.getMouseBinding();
	}

	public KeyBindingData(KeyStroke keyStroke, KeyBindingPrecedence precedence) {
		if (precedence == KeyBindingPrecedence.SystemActionsLevel) {
			throw new IllegalArgumentException(
				"Can't set precedence to System KeyBindingPrecedence");
		}
		this.keyStroke = Objects.requireNonNull(keyStroke);
		this.keyBindingPrecedence = Objects.requireNonNull(precedence);
	}

	private static KeyStroke parseKeyStrokeString(String keyStrokeString) {
		KeyStroke keyStroke = KeyBindingUtils.parseKeyStroke(keyStrokeString);
		if (keyStroke == null) {
			throw new IllegalArgumentException("Invalid keystroke string: " + keyStrokeString);
		}
		return keyStroke;
	}

	/**
	 * Returns a key binding data object that matches the given trigger.  If the existing key 
	 * binding object already matches the new trigger, then the existing key binding data is 
	 * returned.  If the new trigger is null, the null will be returned.
	 * 
	 * @param kbData the existing key binding data; my be null
	 * @param newTrigger the new action trigger; may be null
	 * @return a key binding data based on the new action trigger; may be null
	 */
	public static KeyBindingData update(KeyBindingData kbData, ActionTrigger newTrigger) {
		if (kbData == null) {
			if (newTrigger == null) {
				return null; // no change
			}
			return new KeyBindingData(newTrigger); // trigger added
		}

		if (newTrigger == null) {
			return null; // trigger has been cleared
		}

		ActionTrigger existingTrigger = kbData.getActionTrigger();
		if (existingTrigger.equals(newTrigger)) {
			return kbData;
		}

		return new KeyBindingData(newTrigger);
	}

	/**
	 * Returns an accelerator keystroke to be associated with this action.
	 * @return the binding
	 */
	public KeyStroke getKeyBinding() {
		return keyStroke;
	}

	/**
	 * Returns the keyBindingPrecedence for this action
	 * @return the precedence
	 */
	public KeyBindingPrecedence getKeyBindingPrecedence() {
		return keyBindingPrecedence;
	}

	/**
	 * Returns the mouse binding assigned to this key binding data.
	 * @return the mouse binding; may be null
	 */
	public MouseBinding getMouseBinding() {
		return mouseBinding;
	}

	/**
	 * Creates a new action trigger with the values of this class
	 * @return the action trigger
	 */
	public ActionTrigger getActionTrigger() {
		return new ActionTrigger(keyStroke, mouseBinding);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[KeyStroke=" + keyStroke + ", precedence=" +
			keyBindingPrecedence + ", MouseBinding=" + mouseBinding + "]";
	}

	@Override
	public int hashCode() {
		return Objects.hash(keyBindingPrecedence, keyStroke, mouseBinding);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		KeyBindingData other = (KeyBindingData) obj;
		if (keyBindingPrecedence != other.keyBindingPrecedence) {
			return false;
		}
		if (!Objects.equals(keyStroke, other.keyStroke)) {
			return false;
		}
		if (!Objects.equals(mouseBinding, other.mouseBinding)) {
			return false;
		}
		return true;
	}

	static KeyBindingData createSystemKeyBindingData(KeyStroke keyStroke) {
		KeyBindingData keyBindingData = new KeyBindingData(keyStroke);
		keyBindingData.keyBindingPrecedence = KeyBindingPrecedence.SystemActionsLevel;
		return keyBindingData;
	}

	/**
	 * Updates the given data with system-independent versions of key modifiers.  For example,
	 * the <code>control</code> key will be converted to the <code>command</code> key on the Mac.
	 * @param newKeyBindingData the data to validate
	 * @return the potentially changed data
	 */
	static KeyBindingData validateKeyBindingData(KeyBindingData newKeyBindingData) {
		if (newKeyBindingData == null) {
			return null;
		}

		KeyStroke keyBinding = newKeyBindingData.getKeyBinding();
		if (keyBinding == null) {
			// not sure when this can happen
			return newKeyBindingData;
		}

		KeyBindingPrecedence precedence = newKeyBindingData.getKeyBindingPrecedence();
		if (precedence == KeyBindingPrecedence.SystemActionsLevel) {
			KeyBindingData kbd =
				createSystemKeyBindingData(KeyBindingUtils.validateKeyStroke(keyBinding));
			kbd.mouseBinding = newKeyBindingData.mouseBinding;
			return kbd;
		}

		KeyBindingData kbd =
			new KeyBindingData(KeyBindingUtils.validateKeyStroke(keyBinding), precedence);
		kbd.mouseBinding = newKeyBindingData.mouseBinding;
		return kbd;
	}
}
