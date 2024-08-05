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
package docking.widgets.list;

import java.awt.Color;
import java.awt.Font;
import java.util.function.Function;

import generic.theme.*;

/**
 * Provides a common implementation of a combo box drop-down list renderer, for use with 
 * JComboBoxes.
 * <p>
 * HTML rendering defaults to disabled.  See {@link #setHTMLRenderingEnabled(boolean)}.
 *
 * @param <E> the element-type this list models.
 */
public class GComboBoxCellRenderer<E> extends GListCellRenderer<E> {

	private static final Color COMBO_BOX_BACKGROUND_COLOR = new GColor("color.bg.combobox.row");

	/**
	 * Returns a new GComboBoxCellRenderer that maps the list's data instance to a string used in 
	 * the cell.
	 * <p>
	 * Use this if you only need to provide a way to get the string value from the type being shown
	 * in the list.
	 *
	 * @param cellToTextMappingFunction a function that maps your custom type to a string value
	 * @return new GComboBoxCellRenderer instance
	 */
	public static <E> GComboBoxCellRenderer<E> createDefaultTextRenderer(
			Function<E, String> cellToTextMappingFunction) {
		return new GComboBoxCellRenderer<>() {
			@Override
			protected String getItemText(E value) {
				return cellToTextMappingFunction.apply(value);
			}
		};
	}

	// overridden to return the combo box-specific background color
	@Override
	protected Color getDefaultBackgroundColor() {
		return COMBO_BOX_BACKGROUND_COLOR;
	}

	@Override
	protected void checkForInvalidSetFont(Font f) {

		//
		// The Metal LaF will use the combo's renderer to paint the contents when it is not 
		// editable. (It uses the cell editor when it is editable.)  The UI in this case will call
		// renderer.setFont(comboBox.getFont()) before painting.  We don't want to generate font
		// warnings when this is the case, since we have no control over that behavior.
		//
		if (ThemeManager.getInstance().getLookAndFeelType() == LafType.METAL) {
			return;
		}

		super.checkForInvalidSetFont(f);
	}
}
