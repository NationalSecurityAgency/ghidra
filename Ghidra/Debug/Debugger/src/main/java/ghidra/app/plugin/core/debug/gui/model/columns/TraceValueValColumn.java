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
import java.util.Comparator;

import javax.swing.JTable;

import docking.widgets.table.*;
import docking.widgets.table.sort.ColumnRenderedValueBackupComparator;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ColorsModified;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class TraceValueValColumn extends AbstractDynamicTableColumn<ValueRow, ValueRow, Trace> {
	private final class ValRenderer extends AbstractGColumnRenderer<ValueRow>
			implements ColorsModified.InTable {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public String getFilterString(ValueRow t, Settings settings) {
			return t.getDisplay();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			ValueRow row = (ValueRow) data.getValue();
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
	private final ValRenderer renderer = new ValRenderer();

	@Override
	public String getColumnName() {
		return "Value";
	}

	@Override
	public ValueRow getValue(ValueRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject;
	}

	@Override
	public GColumnRenderer<ValueRow> getColumnRenderer() {
		return renderer;
	}

	@Override
	public Comparator<ValueRow> getComparator(DynamicColumnTableModel<?> model, int columnIndex) {
		return getComparator()
				.thenComparing(new ColumnRenderedValueBackupComparator<>(model, columnIndex));
	}

	@Override
	@SuppressWarnings("unchecked")
	public Comparator<ValueRow> getComparator() {
		return (r1, r2) -> {
			Object v1 = r1.getValue().getValue();
			Object v2 = r2.getValue().getValue();
			if (v1 instanceof Comparable) {
				if (v1.getClass() == v2.getClass()) {
					return ((Comparable<Object>) v1).compareTo(v2);
				}
			}
			return 0; // Defer to backup comparator
		};
	}

	public void setDiffColor(Color diffColor) {
		this.diffColor = diffColor;
	}

	public void setDiffColorSel(Color diffColorSel) {
		this.diffColorSel = diffColorSel;
	}
}
