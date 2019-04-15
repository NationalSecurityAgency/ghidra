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

import javax.swing.*;

import ghidra.util.Msg;

/**
 * An immutable label with HTML rendering allowed.
 * <p>
 * See also:
 * <table border=1>
 * 	<tr><th>Class</th><th>Mutable text</th><th>HTML rendering</th><th>Description</th></tr>
 *  <tr><td>{@link GLabel}</td><td>Immutable</td><td>NO</td><td>Non-html unchangeable label</td></tr>
 *  <tr><td>{@link GDLabel}</td><td>Mutable</td><td>NO</td><td>Non-html changeable label</td></tr>
 *  <tr><td>{@link GHtmlLabel}</td><td>Immutable</td><td>YES</td><td>Html unchangeable label</td></tr>
 *  <tr><td>{@link GDHtmlLabel}</td><td>Mutable</td><td>YES</td><td>Html changeable label</td></tr>
 *  <tr><td>{@link GIconLabel}</td><td>N/A</td><td>NO</td><td>Label that only has an icon image, no text</td></tr>
 * </table>
 */
public class GHtmlLabel extends JLabel {

	/**
	 * Creates a immutable label with no image and no text, with {@link SwingConstants#LEADING} horizontal
	 * alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel()}.
	 * <p>
	 */
	public GHtmlLabel() {
		super();
	}

	/**
	 * Creates a immutable label with the specified text, with {@link SwingConstants#LEADING} horizontal
	 * alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel(String)}.
	 * <p>
	 * @param text string to be displayed by the label
	 */
	public GHtmlLabel(String text) {
		super(text);
	}

	/**
	 * Creates a immutable label with the specified text and horizontal alignment, 
	 * with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel(String, int)}.
	 * <p>
	 * @param text string to be displayed by the label
	 * @param horizontalAlignment One of
	 *           {@link SwingConstants#LEFT},
	 *           {@link SwingConstants#CENTER},
	 *           {@link SwingConstants#RIGHT},
	 *           {@link SwingConstants#LEADING},
	 *           {@link SwingConstants#TRAILING}
	 */
	public GHtmlLabel(String text, int horizontalAlignment) {
		super(text, horizontalAlignment);
	}

	/**
	 * Creates a immutable label with the specified text, image and horizontal alignment, 
	 * with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel(String, Icon, int)}.
	 * <p>
	 *
	 * @param text string to be displayed by the label
	 * @param icon image to be displayed by the label
	 * @param horizontalAlignment  One of
	 *           {@link SwingConstants#LEFT},
	 *           {@link SwingConstants#CENTER},
	 *           {@link SwingConstants#RIGHT},
	 *           {@link SwingConstants#LEADING},
	 *           {@link SwingConstants#TRAILING} 
	 */
	public GHtmlLabel(String text, Icon icon, int horizontalAlignment) {
		super(text, icon, horizontalAlignment);
	}

	/**
	 * This is a half-way method of turning this label into an immutable instance.
	 * <p>
	 * If the user has a type of "GHtmlLabel", they will see the deprecated warning on calls to setText().
	 * <p>
	 * If there are calls to setText() after the initial value has been set by the ctor, a
	 * warning will be printed in the log.
	 * <p>
	 * @param text string this label will display 
	 */
	@Deprecated
	@Override
	public void setText(String text) {
		if (getText() != null && !getText().isEmpty()) {
			Msg.warn(this, "Trying to set text on an immutable label!  Current text: [" +
				getText() + "], new text: [" + text + "]", new Throwable());
			return;
		}
		super.setText(text);
	}
}
