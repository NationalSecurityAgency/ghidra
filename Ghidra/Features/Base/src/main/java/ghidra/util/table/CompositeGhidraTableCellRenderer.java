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
package ghidra.util.table;

import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderingData;

/**
 * What: A cell renderer that will attempt to use any registered cell renderer and will otherwise
 *       default to the parent rendering implementation.
 * Why:  Sometimes the need arises to be able to use the default table rendering while adding 
 *       additional rendering (e.g., to be able to add row coloring).
 * How:  Create a cell renderer that extends this class and install that into your table.  Then,
 *       override {@link #getTableCellRendererComponent(JTable, Object, boolean, boolean, int, int)}
 *       to call this class' implementation.  Finally, add desired decoration.
 *  
 */
public class CompositeGhidraTableCellRenderer extends GhidraTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();
		JTable table = data.getTable();
		int row = data.getRowViewIndex();
		int column = data.getColumnViewIndex();
		boolean isSelected = data.isSelected();
		boolean hasFocus = data.hasFocus();

		Component rendererComponent = null;
		TableCellRenderer cellRenderer = getCellRenderer(table, row, column);
		if (cellRenderer != null) {
			rendererComponent =
				cellRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
					column);
		}
		else {
			// no defined renderer; use me
			rendererComponent =
				super.getTableCellRendererComponent(data);
		}

		return rendererComponent;
	}

	private TableCellRenderer getCellRenderer(JTable table, int row, int column) {

		// 
		// Step 1: See if we can use our custom rendering lookup        
		// 
		if (table instanceof GTable) {
			GTable gTable = (GTable) table;
			return gTable.getCellRendererOverride(row, column);
		}

		// 
		// Step 2: Locate normal JTable-style rendering   
		//
		TableColumn tableColumn = table.getColumnModel().getColumn(column);
		TableCellRenderer renderer = tableColumn.getCellRenderer();
		if (renderer == null) {
			renderer = table.getDefaultRenderer(table.getColumnClass(column));
		}
		return renderer;
	}
}
