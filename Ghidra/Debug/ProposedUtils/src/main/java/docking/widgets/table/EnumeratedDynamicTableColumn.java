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

import docking.widgets.table.EnumeratedColumnTableModel.EditableDynamicTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.table.column.GColumnRenderer;

class EnumeratedDynamicTableColumn<R>
		extends AbstractDynamicTableColumn<R, Object, Void>
		implements EditableDynamicTableColumn<R, Object, Void> {
	private final EnumeratedTableColumn<?, R> col;

	public EnumeratedDynamicTableColumn(EnumeratedTableColumn<?, R> col) {
		this.col = col;
	}

	@Override
	public String getColumnName() {
		return col.getHeader();
	}

	@Override
	public Object getValue(R rowObject, Settings settings, Void data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return col.getValueOf(rowObject);
	}

	@Override
	@SuppressWarnings("unchecked")
	public Class<Object> getColumnClass() {
		return (Class<Object>) col.getValueClass();
	}

	@Override
	public boolean isEditable(R row, Settings settings, Void dataSource,
			ServiceProvider serviceProvider) {
		return col.isEditable(row);
	}

	@Override
	public void setValueOf(R row, Object value, Settings settings, Void dataSource,
			ServiceProvider serviceProvider) {
		col.setValueOf(row, value);
	}

	@Override
	@SuppressWarnings("unchecked")
	public GColumnRenderer<Object> getColumnRenderer() {
		return (GColumnRenderer<Object>) col.getRenderer();
	}

	@Override
	public TableCellEditor getColumnEditor() {
		return col.getEditor();
	}

	@Override
	public int getColumnPreferredWidth() {
		return col.getPreferredWidth();
	}

	@Override
	public int getColumnMaxWidth() {
		return col.getMaxWidth();
	}

	@Override
	public int getColumnMinWidth() {
		return col.getMinWidth();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		SettingsDefinition[] defs = col.getSettingsDefinitions();
		if (defs != null) {
			return defs;
		}
		return super.getSettingsDefinitions();
	}
}
