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
package ghidra.app.plugin.core.debug.gui.model.columns;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ColorsModified;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class TracePathValueColumn extends AbstractDynamicTableColumn<PathRow, PathRow, Trace> {
	private final class ValueRenderer extends AbstractGColumnRenderer<PathRow>
			implements ColorsModified.InTable {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public String getFilterString(PathRow t, Settings settings) {
			return t.getDisplay();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			PathRow row = (PathRow) data.getValue();
			setText(row.getHtmlDisplay());
			setToolTipText(row.getToolTip());
			setForeground(getForegroundFor(data.getTable(), row.isModified(), data.isSelected()));
			return this;
		}

		@Override
		public Color getDiffForeground(JTable table) {
			return diffColor;
		}

		@Override
		public Color getDiffSelForeground(JTable table) {
			return diffColorSel;
		}
	}

	private Color diffColor = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED;
	private Color diffColorSel = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED_SEL;

	@Override
	public String getColumnName() {
		return "Value";
	}

	@Override
	public PathRow getValue(PathRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject;
	}

	@Override
	public GColumnRenderer<PathRow> getColumnRenderer() {
		return new ValueRenderer();
	}

	public void setDiffColor(Color diffColor) {
		this.diffColor = diffColor;
	}

	public void setDiffColorSel(Color diffColorSel) {
		this.diffColorSel = diffColorSel;
	}
}
