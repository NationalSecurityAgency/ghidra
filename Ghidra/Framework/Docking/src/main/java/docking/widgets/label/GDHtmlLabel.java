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

import docking.widgets.GComponent;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.checkbox.GHtmlCheckBox;

/**
 * A 'dynamic' label (the text can be changed), with HTML rendering allowed.
 * <p>
 * See also:
 * <table border=1><caption></caption>
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
public class GDHtmlLabel extends JLabel implements GComponent {

	/**
	 * Creates a label with no image and no text, with {@link SwingConstants#LEADING} horizontal
	 * alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel()}.
	 * <p>
	 */
	public GDHtmlLabel() {
		super();
	}

	/**
	 * Creates a label with the specified text, with {@link SwingConstants#LEADING} horizontal
	 * alignment, with HTML rendering allowed.
	 * <p>
	 * See {@link JLabel#JLabel(String)}.
	 * <p>
	 * @param text string to be displayed by the label
	 */
	public GDHtmlLabel(String text) {
		super(text);
	}

	/**
	 * Creates a label with the specified text and horizontal alignment, 
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
	public GDHtmlLabel(String text, int horizontalAlignment) {
		super(text, horizontalAlignment);
	}

	/**
	 * Creates a label with the specified text, image and horizontal alignment, 
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
	public GDHtmlLabel(String text, Icon icon, int horizontalAlignment) {
		super(text, icon, horizontalAlignment);
	}

}
