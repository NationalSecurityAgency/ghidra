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
 * A {@link JCheckBox} that has HTML rendering disabled.
 * <p>
 * See also:
 * <table border=1><caption></caption>
 * 	<tr><th>Class</th><th>HTML rendering</th><th>Description</th></tr>
 *  <tr><td>{@link GCheckBox}</td><td>NO</td><td>HTML disabled JCheckBox</td></tr>
 *  <tr><td>{@link GHtmlCheckBox}</td><td>YES</td><td>HTML allowed JCheckBox</td></tr>
 * </table>
 */
public class GCheckBox extends JCheckBox implements GComponent {

	/**
	 * Creates a check box with no text or icon, with HTML rendering disabled.
	 * <p>
	 * See {@link JCheckBox#JCheckBox()}
	 * <p>
	 */
	public GCheckBox() {
		super();
		init();
	}

	/**
	 * Creates a check box with an icon, with HTML rendering disabled.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Icon)}
	 * <p>
	 *
	 * @param icon image to display
	 */
	public GCheckBox(Icon icon) {
		super(icon);
		init();
	}

	/**
	 * Creates a check box with an icon and initial selected state, with HTML rendering disabled.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Icon, boolean)}
	 * <p>
	 *
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GCheckBox(Icon icon, boolean selected) {
		super(icon, selected);
		init();
	}

	/**
	 * Creates a check box with the specified text, with HTML rendering disabled.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(String)}
	 * <p>
	 *
	 * @param text text of the check box
	 */
	public GCheckBox(String text) {
		super(text);
		init();
	}

	/**
	 * Creates a check box where properties are taken from the
	 * Action supplied, with HTML rendering disabled.
	 * <p>
	 * See {@link JCheckBox#JCheckBox(Action)}
	 * <p>
	 *
	 * @param a {@code Action} used to specify the new check box
	 */
	public GCheckBox(Action a) {
		super(a);
		init();
	}

	/**
	 * Creates a check box with the specified text and initial selected state, with HTML
	 * rendering disabled.
	 *
	 * @param text text of the check box.
	 * @param selected initial selection state, true means selected
	 */
	public GCheckBox(String text, boolean selected) {
		super(text, selected);
		init();
	}

	/**
	 * Creates a check box with the specified text and icon, with HTML rendering disabled.
	 *
	 * @param text text of the check box
	 * @param icon image to display
	 */
	public GCheckBox(String text, Icon icon) {
		super(text, icon);
		init();
	}

	/**
	 * Creates a check box with the specified text and icon and initial selected state,
	 * with HTML rendering disabled.
	 *
	 * @param text text of the check box
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GCheckBox(String text, Icon icon, boolean selected) {
		super(text, icon, selected);
		init();
	}

	private void init() {
		setHTMLRenderingEnabled(false);
	}

	/**
	 * See {@link JCheckBox#setText(String)}.
	 * <p>
	 * Overridden to warn about HTML text in non-HTML enabled checkbox.
	 * 
	 * @param text string this label will display 
	 */
	@Override
	public void setText(String text) {
		GComponent.warnAboutHtmlText(text);
		super.setText(text);
	}
}
