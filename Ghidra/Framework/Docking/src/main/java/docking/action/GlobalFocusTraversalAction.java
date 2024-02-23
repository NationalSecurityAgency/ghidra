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

import java.awt.KeyboardFocusManager;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;

/**
 * Action for global focus traversal. 
 * <P>
 * The Java focus system suggests that both TAB and &LT;CTRL&GT; TAB move the focus to the next
 * component in the focus traversal cycle. It also suggests that both &LT;SHIFT&GT; TAB and
 * &LT;CTRL&GT;&LT;SHIFT&GT; TAB move the focus to the previous component in the focus traversal
 * cycle. 
 * <P>
 * However, the implementation across Look And Feels and some components within those Look and 
 * Feels are inconsistent with regards the &LT;CTRL&GT; version of these keys. Rather than try 
 * and find and fix all the inconsistencies across all components
 * and Look And Feels, we process the &LT;CTRL&GT; version of focus traversal using global
 * reserved actions. We can't take the same approach for the base TAB and &LT;SHIFT&GT; TAB because 
 * these really do need to be component specific as some components use these keys for some other
 * purpose other than focus traversal.
 * <P>
 * This global processing of &LT;CTRL&GT; TAB and &LT;CTRL&GT;&LT;SHIFT&GT; TAB can be disabled by
 * setting the system property {@link #GLOBAL_FOCUS_TRAVERSAL_PROPERTY} to "false"
 */

public class GlobalFocusTraversalAction extends DockingAction {
	private static final String GLOBAL_FOCUS_TRAVERSAL_PROPERTY =
		"docking.global.focus.traversal.key.enabled";

	private boolean forward;

	public GlobalFocusTraversalAction(KeyStroke keybinding, boolean forward) {
		super(forward ? "Next Component" : "Previous Component",
			DockingWindowManager.DOCKING_WINDOWS_OWNER);

		this.forward = forward;
		createSystemKeyBinding(keybinding);
		setEnabled(isGlobalFocusTraversalEnabled());
	}

	@Override
	public void actionPerformed(ActionContext context) {
		KeyboardFocusManager focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		if (forward) {
			focusManager.focusNextComponent();
		}
		else {
			focusManager.focusPreviousComponent();
		}
	}

	private static boolean isGlobalFocusTraversalEnabled() {
		String property =
			System.getProperty(GLOBAL_FOCUS_TRAVERSAL_PROPERTY, Boolean.TRUE.toString());
		return Boolean.parseBoolean(property);
	}
}
