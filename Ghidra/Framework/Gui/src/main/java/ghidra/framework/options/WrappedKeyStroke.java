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

import java.util.Objects;

import javax.swing.KeyStroke;

/**
 * Wrapper for a KeyStroke that will get saved as a property in an Options
 * object.
 */
class WrappedKeyStroke implements WrappedOption {

	private final static String KEY_CODE = "KeyCode";
	private final static String MODIFIERS = "Modifiers";
	private KeyStroke keyStroke;

	/**
	 * Default constructor
	 */
	WrappedKeyStroke() {
		// for reflection
	}

	/**
	 * Construct a wrapper object using the given KeyStroke.
	 * @param ks the keystroke
	 */
	WrappedKeyStroke(KeyStroke ks) {
		this.keyStroke = ks;
	}

	@Override
	public Object getObject() {
		return keyStroke;
	}

	@Override
	public void readState(SaveState saveState) {
		if (saveState.hasValue(KEY_CODE)) {
			int keyCode = saveState.getInt(KEY_CODE, 0);
			int modifiers = saveState.getInt(MODIFIERS, 0);
			keyStroke = KeyStroke.getKeyStroke(keyCode, modifiers);
		}
	}

	@Override
	public void writeState(SaveState saveState) {
		if (keyStroke == null) {
			return;
		}
		saveState.putInt(KEY_CODE, keyStroke.getKeyCode());
		saveState.putInt(MODIFIERS, keyStroke.getModifiers());
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.KEYSTROKE_TYPE;
	}

	@Override
	public String toString() {
		return Objects.toString(keyStroke);
	}

	/**
	 * A method to allow for converting the deprecated options key stroke usage to the new action
	 * trigger usage
	 * @return a WrappedActionTrigger 
	 */
	public WrappedActionTrigger toWrappedActionTrigger() {
		ActionTrigger trigger = null;
		if (keyStroke != null) {
			trigger = new ActionTrigger(keyStroke);
		}
		return new WrappedActionTrigger(trigger);
	}
}
