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
package docking.widgets.trable;

import java.awt.Color;
import java.awt.Component;

import javax.swing.table.DefaultTableCellRenderer;

/**
 * Base class for GTrable cell renderers.
 *
 * @param <T> the data model row object type
 */
public class DefaultGTrableCellRenderer<T> extends DefaultTableCellRenderer
		implements GTrableCellRenderer<T> {

	@Override
	public Component getCellRenderer(GTrable<?> trable, T value, boolean isSelected,
			boolean hasFocus, int row, int column) {

		if (trable == null) {
			return this;
		}

		Color fg = isSelected ? trable.getSelectionForeground() : trable.getForeground();
		Color bg = isSelected ? trable.getSelectionBackground() : trable.getBackground();
		super.setForeground(fg);
		super.setBackground(bg);

		setFont(trable.getFont());
		setValue(value);

		return this;

	}

}
