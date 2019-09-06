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
package ghidra.app.plugin.core.script;

import javax.swing.KeyStroke;

import docking.actions.KeyBindingUtils;

class KeyBindingsInfo implements Comparable<KeyBindingsInfo> {
	boolean hasAction;
	String keystroke;
	String errorMessage;

	KeyBindingsInfo(boolean isActionBinding, KeyStroke keyBinding, String errorMessage) {
		this(isActionBinding, keyBinding);
		this.errorMessage = errorMessage;
	}

	KeyBindingsInfo(boolean hasAction, KeyStroke stroke) {
		this.hasAction = hasAction;
		this.keystroke = stroke == null ? "" : KeyBindingUtils.parseKeyStroke(stroke);
	}

	@Override
	public String toString() {
		if (errorMessage != null) {
			return "error";
		}
		return keystroke;
	}

	@Override
	public int compareTo(KeyBindingsInfo o) {
		return keystroke.compareToIgnoreCase(o.keystroke);
	}
}
