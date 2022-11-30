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

import docking.widgets.table.*;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import generic.Span;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.table.column.GColumnRenderer;

public class TracePathLastLifespanPlotColumn
		extends AbstractDynamicTableColumn<PathRow, Span<Long, ?>, Trace> {

	private final SpanTableCellRenderer<Long> cellRenderer = new SpanTableCellRenderer<>();
	private final RangeCursorTableHeaderRenderer<Long> headerRenderer =
		new RangeCursorTableHeaderRenderer<>(0L);

	@Override
	public String getColumnName() {
		return "Plot";
	}

	@Override
	public Lifespan getValue(PathRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		TraceObjectValue lastEntry = rowObject.getPath().getLastEntry();
		if (lastEntry == null) {
			return Lifespan.ALL;
		}
		return lastEntry.getLifespan();
	}

	@Override
	public GColumnRenderer<Span<Long, ?>> getColumnRenderer() {
		return cellRenderer;
	}

	@Override
	public GTableHeaderRenderer getHeaderRenderer() {
		return headerRenderer;
	}

	public void setFullRange(Lifespan fullRange) {
		cellRenderer.setFullRange(fullRange);
		headerRenderer.setFullRange(fullRange);
	}

	public void setSnap(long snap) {
		headerRenderer.setCursorPosition(snap);
	}

	public void addSeekListener(SeekListener listener) {
		headerRenderer.addSeekListener(listener);
	}
}
