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
package docking.menu;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.JButton;
import javax.swing.KeyStroke;

import org.apache.commons.lang3.StringUtils;

import docking.action.DockingActionIf;
import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import ghidra.util.StringUtilities;

class DockingToolBarUtils {

	private static final String START_KEYBINDING_TEXT = "<BR><HR><CENTER>(";
	private static final String END_KEYBINDNIG_TEXT = ")</CENTER>";

	/**
	 * Sets the given button's tooltip text to match that of the given action
	 * @param button the button
	 * @param action the action
	 */
	static void setToolTipText(JButton button, DockingActionIf action) {

		String toolTipText = getToolTipText(action);
		String keyBindingText = getKeyBindingAcceleratorText(button, action.getKeyBinding());
		if (keyBindingText != null) {
			button.setToolTipText(combingToolTipTextWithKeyBinding(toolTipText, keyBindingText));
		}
		else {
			button.setToolTipText(toolTipText);
		}
	}

	private static String combingToolTipTextWithKeyBinding(String toolTipText,
			String keyBindingText) {
		StringBuilder buffy = new StringBuilder(toolTipText);
		if (StringUtilities.startsWithIgnoreCase(toolTipText, "<HTML>")) {
			String endHTMLTag = "</HTML>";
			int closeTagIndex = StringUtils.indexOfIgnoreCase(toolTipText, endHTMLTag);
			if (closeTagIndex < 0) {
				// no closing tag, which is acceptable
				buffy.append(START_KEYBINDING_TEXT)
						.append(keyBindingText)
						.append(END_KEYBINDNIG_TEXT);
			}
			else {
				// remove the closing tag, put on our text, and then put the tag back on
				buffy.delete(closeTagIndex, closeTagIndex + endHTMLTag.length() + 1);
				buffy.append(START_KEYBINDING_TEXT)
						.append(keyBindingText)
						.append(END_KEYBINDNIG_TEXT)
						.append(endHTMLTag);
			}
			return buffy.toString();
		}

		// plain text (not HTML)
		return toolTipText + " (" + keyBindingText + ")";
	}

	private static String getToolTipText(DockingActionIf action) {
		String description = action.getDescription();
		if (!StringUtils.isEmpty(description)) {
			return description;
		}
		return action.getName();
	}

	private static String getKeyBindingAcceleratorText(JButton button, KeyStroke keyStroke) {
		if (keyStroke == null) {
			return null;
		}

		// This code is based on that of BasicMenuItemUI
		StringBuilder builder = new StringBuilder();
		int modifiers = keyStroke.getModifiers();
		if (modifiers > 0) {
			builder.append(InputEvent.getModifiersExText(modifiers));

			// The Aqua LaF does not use the '+' symbol between modifiers
			if (!DockingWindowsLookAndFeelUtils.isUsingAquaUI(button.getUI())) {
				builder.append('+');
			}
		}
		int keyCode = keyStroke.getKeyCode();
		if (keyCode != 0) {
			builder.append(KeyEvent.getKeyText(keyCode));
		}
		else {
			builder.append(keyStroke.getKeyChar());
		}
		return builder.toString();
	}
}
