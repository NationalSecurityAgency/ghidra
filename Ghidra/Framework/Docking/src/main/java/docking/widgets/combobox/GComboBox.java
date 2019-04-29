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
package docking.widgets.combobox;

import java.util.Vector;

import javax.swing.*;

import docking.widgets.GComponent;

/**
 * A {@link JComboBox} that disables HTML rendering.
 * 
 * @param <E> the type of the elements of this combo box
 */
public class GComboBox<E> extends JComboBox<E> implements GComponent {

	/**
	 * Creates an empty combobox with a default data model.
	 * <p>
	 * See {@link JComboBox#JComboBox()}
	 * <p>
	 */
	public GComboBox() {
		super();
		init();
	}

	/**
	 * Creates a combobox using the specified model.
	 * <p>
	 * See {@link JComboBox#JComboBox(ComboBoxModel)}
	 * <p>
	 * @param aModel the {@link ComboBoxModel} of generic type {@code E} 
	 */
	public GComboBox(ComboBoxModel<E> aModel) {
		super(aModel);
		init();
	}

	/**
	 * Creates a combobox using the specified items.
	 * <p>
	 * See {@link JComboBox#JComboBox(Object[])}
	 * <p>
	 * @param items array of objects of generic type {@code E} to insert into the combo box
	 */
	public GComboBox(E[] items) {
		super(items);
		init();
	}

	/**
	 * Creates a combobox using the specified items.
	 * <p>
	 * See {@link JComboBox#JComboBox(Vector)}
	 * <p>
	 * @param items a vector containing objects of generic type {@code E} to insert into the combo box
	 */
	public GComboBox(Vector<E> items) {
		super(items);
		init();
	}

	private void init() {
		setHTMLRenderingEnabled(false);
		if (getRenderer() instanceof JComponent) {
			GComponent.setHTMLRenderingFlag((JComponent) getRenderer(), false);
		}
	}

}
