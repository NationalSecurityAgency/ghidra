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
package docking.widgets.button;

import javax.swing.*;

import docking.widgets.GComponent;

/**
 * A {@link JRadioButton} that disables HTML rendering.
 * 
 */
public class GRadioButton extends JRadioButton implements GComponent {

	/**
	 * Creates a blank radio button with HTML rendering disabled.
	 */
	public GRadioButton() {
		super();
		init();
	}

	/**
	 * Creates a radio button with the specified icon, with HTML rendering disabled.
	 *
	 * @param icon image to display
	 */
	public GRadioButton(Icon icon) {
		super(icon);
		init();
	}

	/**
	 * Creates a radio button with properties taken from the specified Action, with HTML rendering
	 * disabled.
	 *
	 * @param a {@link Action}
	 */
	public GRadioButton(Action a) {
		super(a);
		init();
	}

	/**
	 * Creates a radio button with the specified icon and selected state, with HTML rendering 
	 * disabled.
	 *
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GRadioButton(Icon icon, boolean selected) {
		super(icon, selected);
		init();
	}

	/**
	 * Creates a radio button with the specified text, with HTML rendering disabled.
	 *
	 * @param text string to be displayed by the label
	 */
	public GRadioButton(String text) {
		super(text);
		init();
	}

	/**
	 * Creates a radio button with the specified text and selected state, with HTML rendering
	 * disabled.
	 *
	 * @param text string to be displayed by the label
	 * @param selected initial selection state, true means selected
	 */
	public GRadioButton(String text, boolean selected) {
		super(text, selected);
		init();
	}

	/**
	 * Creates a radio button that has the specified text and icon, with HTML rendering disabled.
	 *
	 * @param text string to be displayed by the label
	 * @param icon image to display
	 */
	public GRadioButton(String text, Icon icon) {
		super(text, icon);
		init();
	}

	/**
	 * Creates a radio button that has the specified text, icon, and selected state, with
	 * HTML rendering disabled.
	 *
	 * @param text string to be displayed by the label
	 * @param icon image to display
	 * @param selected initial selection state, true means selected
	 */
	public GRadioButton(String text, Icon icon, boolean selected) {
		super(text, icon, selected);
		init();
	}

	private void init() {
		setHTMLRenderingEnabled(false);
	}
}
