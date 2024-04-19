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
package generic.util.action;

import static java.awt.event.InputEvent.*;
import static java.awt.event.KeyEvent.*;
import static javax.swing.KeyStroke.*;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

/**
 * Default key strokes for System actions.
 */
public class SystemKeyBindings {

	private static final int CTRL = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
	private static final int CTRL_SHIFT = CTRL | SHIFT_DOWN_MASK;
	private static final int CTRL_ALT_SHIFT = CTRL_SHIFT | ALT_DOWN_MASK;

	public static final KeyStroke HELP_KEY1 = KeyStroke.getKeyStroke(VK_HELP, 0);
	public static final KeyStroke HELP_KEY2 = KeyStroke.getKeyStroke(VK_F1, 0);
	public static final KeyStroke HELP_INFO_KEY = getKeyStroke(VK_F1, CTRL_SHIFT);

	public static final KeyStroke CONTEXT_MENU_KEY1 = getKeyStroke(VK_F10, SHIFT_DOWN_MASK);
	public static final KeyStroke CONTEXT_MENU_KEY2 = getKeyStroke(VK_CONTEXT_MENU, 0);

	public static final KeyStroke FOCUS_NEXT_WINDOW_KEY = getKeyStroke(VK_F3, CTRL);
	public static final KeyStroke FOCUS_PREVIOUS_WINDOW_KEY = getKeyStroke(VK_F3, CTRL_SHIFT);

	public static final KeyStroke FOCUS_NEXT_COMPONENT_KEY = getKeyStroke(VK_TAB, CTRL);
	public static final KeyStroke FOCUS_PREVIOUS_COMPONENT_KEY = getKeyStroke(VK_TAB, CTRL_SHIFT);

	public static final KeyStroke FOCUS_INFO_KEY = getKeyStroke(VK_F2, CTRL_ALT_SHIFT);
	public static final KeyStroke FOCUS_CYCLE_INFO_KEY = getKeyStroke(VK_F3, CTRL_ALT_SHIFT);

	public static final KeyStroke UPDATE_KEY_BINDINGS_KEY = getKeyStroke(VK_F4, 0);

	public static final KeyStroke COMPONENT_THEME_INFO_KEY = getKeyStroke(VK_F9, CTRL_ALT_SHIFT);

	public static final KeyStroke ACTION_CHOOSER_KEY =
		KeyStroke.getKeyStroke(KeyEvent.VK_3, InputEvent.CTRL_DOWN_MASK);

	private SystemKeyBindings() {
		// utils class
	}
}
