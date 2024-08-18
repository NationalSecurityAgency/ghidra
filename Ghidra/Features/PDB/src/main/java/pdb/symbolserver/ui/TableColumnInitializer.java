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
package pdb.symbolserver.ui;

import java.awt.FontMetrics;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.table.*;

/**
 * For Pdb symbolserver gui stuff only.
 * 
 * Add on interface for DynamicTableColumn classes that let them control aspects of the
 * matching TableColumn. 
 */
public interface TableColumnInitializer {
	/**
	 * Best called during {@link DialogComponentProvider#dialogShown} or 
	 * {@link ComponentProvider#componentShown} 
	 * 
	 * @param table table component 
	 * @param model table model
	 */
	static void initializeTableColumns(GTable table, GDynamicColumnTableModel<?, ?> model) {
		TableColumnModel colModel = table.getColumnModel();

		FontMetrics fm = table.getTableHeader().getFontMetrics(table.getTableHeader().getFont());
		int padding = fm.stringWidth("WW"); // w.a.g. for the left+right padding on the header column component

		for (int colIndex = 0; colIndex < model.getColumnCount(); colIndex++) {
			DynamicTableColumn<?, ?, ?> dtableCol = model.getColumn(colIndex);
			if (dtableCol instanceof TableColumnInitializer colInitializer) {
				TableColumn tableCol = colModel.getColumn(colIndex);
				colInitializer.initializeTableColumn(tableCol, fm, padding);
			}
		}
	}

	/**
	 * Called to allow the initializer to modify the specified TableColumn
	 * 
	 * @param col {@link TableColumn}
	 * @param fm {@link FontMetrics} used by the table header gui component
	 * @param padding padding to use in the column
	 */
	void initializeTableColumn(TableColumn col, FontMetrics fm, int padding);
}
