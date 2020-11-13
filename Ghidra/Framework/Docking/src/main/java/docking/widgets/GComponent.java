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

import javax.swing.JComponent;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GLabel;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

public interface GComponent {
	// taken from BasicHTML.htmlDisable, which is private
	public static final String HTML_DISABLE_STRING = "html.disable";

	/**
	 * Enables and disables the rendering of HTML content in this component.  If enabled, this
	 * component will interpret HTML content when the text this component is showing begins with
	 * {@code <html>}
	 *
	 * @param enabled true to enable HTML rendering; false to disable it
	 */
	public default void setHTMLRenderingEnabled(boolean enabled) {
		setHTMLRenderingFlag((JComponent) this, enabled);
	}

	/**
	 * Returns the current HTML rendering 'enable-ment' of this component.
	 * 
	 * @return boolean, true if HTML rendering is allowed
	 */
	public default boolean getHTMLRenderingEnabled() {
		Object prop = ((JComponent) this).getClientProperty(HTML_DISABLE_STRING);
		return prop == null || prop != Boolean.TRUE;
	}

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
	 * Sets the HTML rendering flag for the specified component.
	 * 
	 * @param comp the thing
	 * @param enabled boolean, if true html rendering will be allowed
	 */
	public static void setHTMLRenderingFlag(JComponent comp, boolean enabled) {
		comp.putClientProperty(HTML_DISABLE_STRING, enabled ? null : true);
	}

}
