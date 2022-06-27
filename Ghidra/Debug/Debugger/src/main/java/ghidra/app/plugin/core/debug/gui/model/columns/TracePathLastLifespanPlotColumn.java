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

import com.google.common.collect.Range;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.RangeTableCellRenderer;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.table.column.GColumnRenderer;

public class TracePathLastLifespanPlotColumn
		extends AbstractDynamicTableColumn<PathRow, Range<Long>, Trace> {

	private final RangeTableCellRenderer<Long> cellRenderer = new RangeTableCellRenderer<>();

	@Override
	public String getColumnName() {
		return "Plot";
	}

	@Override
	public Range<Long> getValue(PathRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		TraceObjectValue lastEntry = rowObject.getPath().getLastEntry();
		if (lastEntry == null) {
			return Range.all();
		}
		return lastEntry.getLifespan();
	}

	@Override
	public GColumnRenderer<Range<Long>> getColumnRenderer() {
		return cellRenderer;
	}

	// TODO: header renderer

	public void setFullRange(Range<Long> fullRange) {
		cellRenderer.setFullRange(fullRange);
		// TODO: header, too
	}
}
