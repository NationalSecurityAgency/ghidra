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
package docking.widgets;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GLabel;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

public interface GComponent {
	// taken from BasicHTML.htmlDisable, which is private
	public static final String HTML_DISABLE_STRING = "html.disable";

	/**
	 * Helper function that logs a warning about a string text that looks like it has HTML text.
	 * <p>
	 * Use this when working with a string in a label that has already disabled HTML rendering.
	 * <p>
	 * @param text string to test for HTML and warn about
	 */
	public static void warnAboutHtmlText(String text) {
		// #ifdef still_finding_html_labels_in_our_huge_codebase
		if (StringUtils.startsWithIgnoreCase(text, "<html>")) {
			Msg.warn(GLabel.class, "HTML text detected in non-HTML component: " + text,
				ReflectionUtilities.createJavaFilteredThrowable());
		}
		// #endif
	}

	/**
	 * Turns off the HTML rendering in the specified component.
	 * 
	 * @param comp the thing
	 */
	public static void turnOffHTMLRendering(JComponent comp) {
		comp.putClientProperty(HTML_DISABLE_STRING, true);
	}

	/**
	 * Turns off the HTML rendering in the specified component and its current cell renderer.
	 * 
	 * @param list the list
	 */
	public static void turnOffHTMLRendering(JList<?> list) {
		turnOffHTMLRendering((JComponent) list);
		if (list.getCellRenderer() instanceof JComponent) {
			turnOffHTMLRendering((JComponent) list.getCellRenderer());
		}
	}

	/**
	 * Turns off the HTML rendering in the specified component and its current renderer.
	 * 
	 * @param cb the combobox
	 */
	public static void turnOffHTMLRendering(JComboBox<?> cb) {
		turnOffHTMLRendering((JComponent) cb);
		if (cb.getRenderer() instanceof JComponent) {
			turnOffHTMLRendering((JComponent) cb.getRenderer());
		}
	}

}
