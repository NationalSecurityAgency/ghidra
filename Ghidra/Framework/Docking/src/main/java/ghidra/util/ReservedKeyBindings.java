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
package ghidra.util;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.DockingUtils;

public class ReservedKeyBindings {

	private ReservedKeyBindings() {
		// utils class
	}

	public static final KeyStroke HELP_KEY1 = KeyStroke.getKeyStroke(KeyEvent.VK_HELP, 0);
	public static final KeyStroke HELP_KEY2 = KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0);
	public static final KeyStroke HELP_INFO_KEY =
		KeyStroke.getKeyStroke(KeyEvent.VK_F1, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	public static final KeyStroke CONTEXT_MENU_KEY1 =
		KeyStroke.getKeyStroke(KeyEvent.VK_F10, InputEvent.SHIFT_DOWN_MASK);
	public static final KeyStroke CONTEXT_MENU_KEY2 =
		KeyStroke.getKeyStroke(KeyEvent.VK_CONTEXT_MENU, 0);

	public static final KeyStroke FOCUS_INFO_KEY =
		KeyStroke.getKeyStroke(KeyEvent.VK_F2, DockingUtils.CONTROL_KEY_MODIFIER_MASK |
			InputEvent.ALT_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
	public static final KeyStroke FOCUS_CYCLE_INFO_KEY =
		KeyStroke.getKeyStroke(KeyEvent.VK_F3, DockingUtils.CONTROL_KEY_MODIFIER_MASK |
			InputEvent.ALT_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);

	public static final KeyStroke UPDATE_KEY_BINDINGS_KEY =
		KeyStroke.getKeyStroke(KeyEvent.VK_F4, 0);

	public static boolean isReservedKeystroke(KeyStroke keyStroke) {
		int code = keyStroke.getKeyCode();
		if (code == KeyEvent.VK_SHIFT || code == KeyEvent.VK_ALT || code == KeyEvent.VK_CONTROL ||
			code == KeyEvent.VK_CAPS_LOCK || code == KeyEvent.VK_TAB ||
			HELP_KEY1.equals(keyStroke) || HELP_KEY2.equals(keyStroke) ||
			HELP_INFO_KEY.equals(keyStroke) || UPDATE_KEY_BINDINGS_KEY.equals(keyStroke) ||
			FOCUS_INFO_KEY.equals(keyStroke) || FOCUS_CYCLE_INFO_KEY.equals(keyStroke) ||
			CONTEXT_MENU_KEY1.equals(keyStroke) || CONTEXT_MENU_KEY2.equals(keyStroke)) {
			return true;
		}

		return false;
	}
}
