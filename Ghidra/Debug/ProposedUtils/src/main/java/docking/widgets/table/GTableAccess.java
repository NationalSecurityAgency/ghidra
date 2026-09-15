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

import javax.swing.JTable;
import javax.swing.table.TableModel;

/**
 * Provides public access to the unwrapped table model of a {@link GTable}
 */
public interface GTableAccess {
	/**
	 * {@return the unwrapped table model of the given table}
	 * <p>
	 * If the given table is a plain {@link JTable}, then this merely delegates to
	 * {@link JTable#getModel()}. However, if the table happens to be a {@link GTable}, then this
	 * will invoke the otherwise-protected {@link GTable#getUnwrappedTableModel()}. This is both a
	 * utility and a means to access a protected method of {@link GTable}.
	 * 
	 * @param table the table whose model to get
	 */
	default TableModel getUnwrappedModel(JTable table) {
		return (table instanceof GTable gtable) ? gtable.getUnwrappedTableModel()
				: table.getModel();
	}
}
