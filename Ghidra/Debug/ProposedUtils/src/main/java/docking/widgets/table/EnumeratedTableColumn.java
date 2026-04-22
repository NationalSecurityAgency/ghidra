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
package docking.widgets.table;

import javax.swing.table.TableCellEditor;

import docking.widgets.table.ColumnSortState.SortDirection;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.util.table.column.GColumnRenderer;

// NOTE: If I need to track indices, addSortListener
/**
 * An interface on enums used to describe table columns
 *
 * @param <C> the type of the enum
 * @param <R> the type of rows
 */
public interface EnumeratedTableColumn<C extends Enum<C>, R> {
	/**
	 * Get the value class of cells in this column
	 * 
	 * @return the class
	 */
	public Class<?> getValueClass();

	/**
	 * Get the value of this column for the given row
	 * 
	 * @param row the row
	 * @return the value
	 */
	public Object getValueOf(R row);

	/**
	 * Get the name of this column
	 * 
	 * @return the name
	 */
	public String getHeader();

	/**
	 * Get the value of this column for the given row
	 * 
	 * @param row the row
	 * @param value the new value
	 */
	default public void setValueOf(R row, Object value) {
		throw new UnsupportedOperationException("Cell is not editable");
	}

	/**
	 * Check if this column can be modified for the given row
	 * 
	 * @param row the row
	 * @return true if editable
	 */
	default public boolean isEditable(R row) {
		return false;
	}

	/**
	 * Check if this column can be sorted
	 * 
	 * <p>
	 * TODO: Either this should be implemented as ported to {@link GDynamicColumnTableModel}, or
	 * removed.
	 * 
	 * @return true if sortable
	 */
	default public boolean isSortable() {
		return true;
	}

	/**
	 * Check if this column should be visible by default
	 * 
	 * @return true if visible
	 */
	default public boolean isVisible() {
		return true;
	}

	/**
	 * Get the default sort direction for this column
	 * 
	 * @return the sort direction
	 */
	default public SortDirection defaultSortDirection() {
		return SortDirection.ASCENDING;
	}

	default public int getPreferredWidth() {
		return AbstractGTableModel.WIDTH_UNDEFINED;
	}

	default public int getMinWidth() {
		return AbstractGTableModel.WIDTH_UNDEFINED;
	}

	default public int getMaxWidth() {
		return AbstractGTableModel.WIDTH_UNDEFINED;
	}

	/**
	 * Because of limitations with Java generics and Enumerations, type checking cannot be
	 * guaranteed here. The user must ensure that any returned by {@link #getValueOf(Object)} can be
	 * accepted by the renderer returned here. The framework will perform an unchecked cast of the
	 * renderer.
	 * 
	 * @return the renderer
	 */
	default public GColumnRenderer<?> getRenderer() {
		return null;
	}

	default public TableCellEditor getEditor() {
		return null;
	}

	default public SettingsDefinition[] getSettingsDefinitions() {
		return null;
	}
}
