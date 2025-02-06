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
package docking.widgets.label;

import javax.swing.JLabel;
import javax.swing.SwingConstants;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.checkbox.GHtmlCheckBox;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * An immutable label (the text can NOT be changed), with HTML rendering allowed.
 * <p>
 * Clients do not need to prefix label text with "&lt;html&gt;", as is required for a standard
 * JLabel.
 *
 * <p>
 * See also:
 * <table border=1>
 * 	<tr><th>Class</th><th>Mutable text</th><th>HTML rendering</th><th>Description</th></tr>
 *  <tr><td>{@link GLabel}</td><td>Immutable</td><td>NO</td><td>Non-html unchangeable label</td></tr>
 *  <tr><td>{@link GDLabel}</td><td>Mutable</td><td>NO</td><td>Non-html changeable label</td></tr>
 *  <tr><td>{@link GHtmlLabel}</td><td>Immutable</td><td>YES</td><td>Html unchangeable label</td></tr>
 *  <tr><td>{@link GDHtmlLabel}</td><td>Mutable</td><td>YES</td><td>Html changeable label</td></tr>
 *  <tr><td>{@link GIconLabel}</td><td>N/A</td><td>NO</td><td>Label that only has an icon image, no text</td></tr>
 *  <tr><th colspan=4>Other components of note:</th></tr>
 *  <tr><td>{@link GCheckBox}</td><td></td><td>NO</td><td>Non-html checkbox</td></tr>
 *  <tr><td>{@link GHtmlCheckBox}</td><td></td><td>YES</td><td>Html checkbox</td></tr>
 * </table>
 */
public class GHtmlLabel extends AbstractHtmlLabel {

	/**
	 * Creates a immutable label with no image and no text, with {@link SwingConstants#LEADING}
	 * horizontal alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel()}.
	 */
	public GHtmlLabel() {
	}

	/**
	 * Creates a immutable label with the specified text, with {@link SwingConstants#LEADING}
	 * horizontal alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel(String)}.
	 * 
	 * @param text string to be displayed by the label
	 */
	public GHtmlLabel(String text) {
		super(text);
	}

	/**
	 * This is a half-way method of turning this label into an immutable instance.
	 * <p>
	 * If the user has a type of "GHtmlLabel", they will see the deprecated warning on calls to
	 * setText().
	 * <p>
	 * If there are calls to setText() after the initial value has been set by the  constructor, a
	 * warning will be printed in the log.
	 * 
	 * @param text string this label will display
	 */
	@Deprecated
	@Override
	public void setText(String text) {
		if (!StringUtils.isEmpty(getText())) {
			Msg.warn(this,
				"Trying to set text on an immutable label!  Current text: [" + getText() +
					"], new text: [" + text + "]",
				ReflectionUtilities.createJavaFilteredThrowable());
			return;
		}
		super.setText(text);
	}

}
