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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.Color;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;

public class PathTableModel extends AbstractQueryTableModel<PathRow> {
	record Seen(KeyPath path, long minSnap) {
		static Seen forPath(TraceObjectValPath valPath) {
			TraceObjectValue last = valPath.getLastEntry();
			return new Seen(valPath.getPath(), last == null ? 0 : last.getMinSnap());
		}
	}

	/** Initialized in {@link #createTableColumnDescriptor()}, which precedes this. */
	private TracePathValueColumn valueColumn;
	private TracePathLastLifespanPlotColumn lifespanPlotColumn;

	protected static Stream<? extends TraceObjectValPath> distinctKeyPath(
			Stream<? extends TraceObjectValPath> stream) {
		Set<Seen> seen = new HashSet<>();
		return stream.filter(path -> seen.add(Seen.forPath(path)));
	}

	public class PathRow {
		private final TraceObjectValPath path;
		private final Object value;

		public PathRow(TraceObjectValPath path) {
			this.path = path;
			this.value = computeValue();
		}

		public TraceObjectValPath getPath() {
			return path;
		}

		public Object computeValue() {
			// Spare fetching the root unless it's really needed
			if (path.getLastEntry() == null) {
				return getTrace().getObjectManager().getRootObject();
			}
			return path.getDestinationValue(null);
		}

		public Object getValue() {
			return value;
		}

		/**
		 * Get a non-HTML string representing how this row's value should be sorted, filtered, etc.
		 * 
		 * @return the display string
		 */
		public String getDisplay() {
			return display.getEdgeDisplay(path.getLastEntry());
		}

		/**
		 * Get an HTML string representing how this row's value should be displayed
		 * 
		 * @return the display string
		 */
		public String getHtmlDisplay() {
			return display.getEdgeHtmlDisplay(path.getLastEntry());
		}

		public String getToolTip() {
			return display.getEdgeToolTip(path.getLastEntry());
		}

		public boolean isModified() {
			return isValueModified(path.getLastEntry());
		}

		public boolean isLastCanonical() {
			TraceObjectValue last = path.getLastEntry();
			// Root is canonical
			return last == null || last.isCanonical();
		}

		public boolean isCurrent() {
			TraceObject current = getCurrentObject();
			if (current == null) {
				return false;
			}
			if (!(getValue() instanceof TraceObject child)) {
				return false;
			}
			return child.getCanonicalPath().isAncestor(current.getCanonicalPath());
		}
	}

	public PathTableModel(Plugin plugin) {
		super("Attribute Model", plugin);
	}

	protected void updateTimelineMax() {
		Long max = getTrace() == null ? null : getTrace().getTimeManager().getMaxSnap();
		Lifespan fullRange = Lifespan.span(0L, max == null ? 1 : max + 1);
		lifespanPlotColumn.setFullRange(fullRange);
	}

	@Override
	protected void traceChanged() {
		updateTimelineMax();
		super.traceChanged();
	}

	@Override
	protected void showHiddenChanged() {
		reload();
		super.showHiddenChanged();
	}

	@Override
	protected void maxSnapChanged() {
		updateTimelineMax();
		refresh();
	}

	protected static boolean isAnyHidden(TraceObjectValPath path) {
		return path.getEntryList().stream().anyMatch(v -> v.isHidden());
	}

	@Override
	protected Stream<PathRow> streamRows(Trace trace, ModelQuery query, Lifespan span) {
		// TODO: For queries with early wildcards, this is not efficient
		// May need to incorporate filtering hidden into the query execution itself.
		return distinctKeyPath(query.streamPaths(trace, span)
				.filter(p -> isShowHidden() || !isAnyHidden(p)))
						.map(PathRow::new);
	}

	@Override
	protected TableColumnDescriptor<PathRow> createTableColumnDescriptor() {
		TableColumnDescriptor<PathRow> descriptor = new TableColumnDescriptor<>();
		descriptor.addHiddenColumn(new TracePathStringColumn());
		descriptor.addVisibleColumn(new TracePathLastKeyColumn(), 1, true);
		descriptor.addVisibleColumn(valueColumn = new TracePathValueColumn());
		descriptor.addVisibleColumn(new TracePathLastLifespanColumn(), 2, true);
		descriptor.addHiddenColumn(lifespanPlotColumn = new TracePathLastLifespanPlotColumn());
		return descriptor;
	}

	@Override
	public PathRow findTraceObject(TraceObject object) {
		for (PathRow row : getModelData()) {
			if (row.getValue() == object && row.isLastCanonical()) {
				return row;
			}
		}
		return null;
	}

	@Override
	public void setDiffColor(Color diffColor) {
		valueColumn.setDiffColor(diffColor);
	}

	@Override
	public void setDiffColorSel(Color diffColorSel) {
		valueColumn.setDiffColorSel(diffColorSel);
	}

	@Override
	public void snapChanged() {
		super.snapChanged();
		lifespanPlotColumn.setSnap(getSnap());
	}

	@Override
	public void addSeekListener(SeekListener listener) {
		lifespanPlotColumn.addSeekListener(listener);
	}
}
