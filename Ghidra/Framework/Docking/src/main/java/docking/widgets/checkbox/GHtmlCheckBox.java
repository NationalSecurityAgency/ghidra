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
package docking.widgets.checkbox;

import javax.swing.*;

import docking.widgets.GComponent;

/**
 * A {@link JCheckBox} that allows HTML rendering.
 * <p>
 * See also:
 * <table border=1><caption></caption>
 * 	<tr><th>Class</th><th>HTML rendering</th><th>Description</th></tr>
 *  <tr><td>{@link GCheckBox}</td><td>NO</td><td>HTML disabled JCheckBox</td></tr>
 *  <tr><td>{@link GHtmlCheckBox}</td><td>YES</td><td>HTML allowed JCheckBox</td></tr>
 * </table>
*/
public class GHtmlCheckBox extends JCheckBox implements GComponent {

	/**
	 * Creates a check box with no text or icon, with HTML rendering allowed.
	 * <p>
	 * See {@link JCheckBox#JCheckBox()}
	 * <p>
	 */
	public GHtmlCheckBox() {
		super();
	}

	/**
	 * Creates a check box with an icon, with HTML rendering allowed.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Icon)}
	 * <p>
	 *
	 * @param icon image to display
	 */
	public GHtmlCheckBox(Icon icon) {
		super(icon);
	}

	/**
	 * Creates a check box with an icon and initial selected state, with HTML rendering allowed.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Icon, boolean)}
	 * <p>
	 *
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GHtmlCheckBox(Icon icon, boolean selected) {
		super(icon, selected);
	}

	/**
	 * Creates a check box with the specified text, with HTML rendering allowed.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(String)}
	 * <p>
	 *
	 * @param text text of the check box
	 */
	public GHtmlCheckBox(String text) {
		super(text);
	}

	/**
	 * Creates a check box where properties are taken from the
	 * Action supplied, with HTML rendering allowed.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Action)}
	 * <p>
	 *
	 * @param a {@code Action} used to specify the new check box
	 */
	public GHtmlCheckBox(Action a) {
		super(a);
	}

	/**
	 * Creates a check box with the specified text and initial selected state, with HTML
	 * rendering allowed.
	 *
	 * @param text text of the check box.
	 * @param selected initial selection state, true means selected
	 */
	public GHtmlCheckBox(String text, boolean selected) {
		super(text, selected);
	}

	/**
	 * Creates a check box with the specified text and icon, with HTML rendering allowed.
	 *
	 * @param text text of the check box
	 * @param icon image to display
	 */
	public GHtmlCheckBox(String text, Icon icon) {
		super(text, icon);
	}

	/**
	 * Creates a check box with the specified text and icon and initial selected state,
	 * with HTML rendering allowed.
	 *
	 * @param text text of the check box
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GHtmlCheckBox(String text, Icon icon, boolean selected) {
		super(text, icon, selected);
	}

}
