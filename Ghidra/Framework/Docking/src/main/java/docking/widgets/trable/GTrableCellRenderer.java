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

import java.awt.Component;

/**
 * Interface for {@link GTrable} cell renderers
 *
 * @param <C> the type of the column value for this cell
 */
public interface GTrableCellRenderer<C> {

	/**
	 * Gets and prepares the renderer component for the given column value
	 * @param trable the GTrable
	 * @param value the column value
	 * @param isSelected true if the row is selected
	 * @param hasFocus true if the cell has focus
	 * @param row the row of the cell being painted
	 * @param column the column of the cell being painted
	 * @return the component to use to paint the cell value
	 */
	public Component getCellRenderer(GTrable<?> trable, C value,
			boolean isSelected, boolean hasFocus, int row, int column);

}
