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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.KeyStroke;

import org.apache.commons.lang3.StringUtils;

import gui.event.MouseBinding;
import util.CollectionUtils;

/**
 * Represents a way to trigger an action in the system.  A trigger is based on a key stroke, a mouse 
 * binding or both.
 */
public class ActionTrigger {

	private final static Pattern TO_STRING_PATTERN =
		Pattern.compile(".*Key Stroke\\[(.*)\\].*Mouse Binding\\[(.*)\\]");

	private final static String KEY_STROKE = "KeyStroke";
	private final static String MOUSE_BINDING = "MouseBinding";

	private KeyStroke keyStroke;
	private MouseBinding mouseBinding;

	/**
	 * Creates an action trigger with the given key stroke.
	 * @param keyStroke the key stroke
	 */
	public ActionTrigger(KeyStroke keyStroke) {
		this(keyStroke, null);
	}

	/**
	 * Creates an action trigger with the given mouse binding.
	 * @param mouseBinding the mouse binding
	 */
	public ActionTrigger(MouseBinding mouseBinding) {
		this(null, mouseBinding);
	}

	/**
	 * A convenience constructor for creating an action trigger with either or both values set.  At
	 * least one of the values must be non-null. 
	 * 
	 * @param keyStroke the key stroke; may be null
	 * @param mouseBinding the mouse binding; may be null
	 */
	public ActionTrigger(KeyStroke keyStroke, MouseBinding mouseBinding) {
		if (CollectionUtils.isAllNull(keyStroke, mouseBinding)) {
			throw new NullPointerException("Both the key stroke and mouse bindng cannot be null");
		}
		this.keyStroke = keyStroke;
		this.mouseBinding = mouseBinding;
	}

	public KeyStroke getKeyStroke() {
		return keyStroke;
	}

	public MouseBinding getMouseBinding() {
		return mouseBinding;
	}

	@Override
	public String toString() {
		StringBuilder buffy = new StringBuilder("ActionTrigger: ");

		buffy.append("Key Stroke[");
		if (keyStroke != null) {
			buffy.append(keyStroke.toString());
		}
		buffy.append("], Mouse Binding[");

		if (mouseBinding != null) {
			buffy.append(mouseBinding.toString());
		}
		buffy.append(']');

		return buffy.toString();
	}

	/**
	 * Creates a new action trigger from the given string.  The string is expected to be the result
	 * of calling {@link #toString()} on an instance of this class.
	 * 
	 * @param string the string to parse.
	 * @return the new instance or null of the string is invalid.
	 */
	public static ActionTrigger getActionTrigger(String string) {

		Matcher matcher = TO_STRING_PATTERN.matcher(string);
		if (!matcher.matches()) {
			return null;
		}

		String ksString = matcher.group(1);
		String mbString = matcher.group(2);

		KeyStroke ks = null;
		if (!StringUtils.isBlank(ksString)) {
			ks = KeyStroke.getKeyStroke(ksString);
		}

		MouseBinding mb = null;
		if (!StringUtils.isBlank(mbString)) {
			mb = MouseBinding.getMouseBinding(mbString);
		}

		return create(ks, mb);
	}

	/**
	 * Writes this action trigger's data into the given save state.
	 * @param saveState the save state
	 */
	public void writeState(SaveState saveState) {

		String ksString = "";
		if (keyStroke != null) {
			ksString = keyStroke.toString();
		}
		saveState.putString(KEY_STROKE, ksString);

		String mbString = "";
		if (mouseBinding != null) {
			mbString = mouseBinding.toString();
		}
		saveState.putString(MOUSE_BINDING, mbString);
	}

	/**
	 * Creates a new action trigger by reading data from the given save state.
	 * @param saveState the save state 
	 * @return the new action trigger
	 */
	public static ActionTrigger create(SaveState saveState) {

		KeyStroke ks = null;
		String value = saveState.getString(KEY_STROKE, null);
		if (!StringUtils.isBlank(value)) {
			ks = KeyStroke.getKeyStroke(value);
		}

		MouseBinding mb = null;
		value = saveState.getString(MOUSE_BINDING, null);
		if (value != null) {
			mb = MouseBinding.getMouseBinding(value);
		}

		return create(ks, mb);
	}

	private static ActionTrigger create(KeyStroke ks, MouseBinding mb) {
		if (ks == null && mb == null) {
			return null;
		}
		return new ActionTrigger(ks, mb);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((keyStroke == null) ? 0 : keyStroke.hashCode());
		result = prime * result + ((mouseBinding == null) ? 0 : mouseBinding.hashCode());
		return result;
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

		ActionTrigger other = (ActionTrigger) obj;
		if (!Objects.equals(keyStroke, other.keyStroke)) {
			return false;
		}

		return Objects.equals(mouseBinding, other.mouseBinding);
	}

}
