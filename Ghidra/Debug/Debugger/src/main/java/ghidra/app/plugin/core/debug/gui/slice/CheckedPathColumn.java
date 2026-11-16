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
package ghidra.app.plugin.core.debug.gui.slice;

import javax.swing.DefaultCellEditor;
import javax.swing.JCheckBox;
import javax.swing.table.TableCellEditor;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.GBooleanCellRenderer;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.table.column.GColumnRenderer;

class CheckedPathColumn extends AbstractDynamicTableColumnStub<PathRow, Boolean> {
	private static final GColumnRenderer<Boolean> RENDERER = new BooleanRenderer();
	private static final TableCellEditor EDITOR = new DefaultCellEditor(new JCheckBox());

	private static class BooleanRenderer extends GBooleanCellRenderer
			implements GColumnRenderer<Boolean> {
		@Override
		public String getFilterString(Boolean value, Settings settings) {
			return value == null ? "" : value.toString();
		}
	}

	@Override
	public String getColumnName() {
		return "Favorite";
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		return "";
	}

	@Override
	public int getColumnMinWidth() {
		return 30;
	}

	@Override
	public int getColumnMaxWidth() {
		return 30;
	}

	@Override
	public Boolean getValue(PathRow row, Settings settings, ServiceProvider serviceProvider) {
		return row.isChecked();
	}

	@Override
	public GColumnRenderer<Boolean> getColumnRenderer() {
		return RENDERER;
	}

	@Override
	public TableCellEditor getColumnEditor() {
		return EDITOR;
	}
}
