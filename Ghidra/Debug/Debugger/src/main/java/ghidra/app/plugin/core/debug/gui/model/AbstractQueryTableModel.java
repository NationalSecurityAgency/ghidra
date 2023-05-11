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
import java.util.Objects;
import java.util.stream.Stream;

import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractQueryTableModel<T> extends ThreadedTableModel<T, Trace>
		implements DisplaysModified {

	protected class ListenerForChanges extends TraceDomainObjectListener {
		public ListenerForChanges() {
			listenForUntyped(Trace.DO_OBJECT_RESTORED, this::objectRestored);
			listenFor(TraceObjectChangeType.VALUE_CREATED, this::valueCreated);
			listenFor(TraceObjectChangeType.VALUE_DELETED, this::valueDeleted);
			listenFor(TraceObjectChangeType.VALUE_LIFESPAN_CHANGED, this::valueLifespanChanged);

			listenFor(TraceSnapshotChangeType.ADDED, this::maxSnapChanged);
			listenFor(TraceSnapshotChangeType.DELETED, this::maxSnapChanged);
		}

		protected void objectRestored(DomainObjectChangeRecord record) {
			reload();
		}

		protected void valueCreated(TraceObjectValue value) {
			if (query != null && query.involves(span, value)) {
				reload(); // Can I be more surgical?
			}
		}

		protected void valueDeleted(TraceObjectValue value) {
			if (query != null && query.involves(span, value)) {
				reload(); // Can I be more surgical?
			}
		}

		protected void valueLifespanChanged(TraceObjectValue value, Lifespan oldSpan,
				Lifespan newSpan) {
			if (query == null) {
				return;
			}
			boolean inOld = span.intersects(oldSpan);
			boolean inNew = span.intersects(newSpan);
			boolean queryIncludes = query.involves(Lifespan.ALL, value);
			if (queryIncludes) {
				if (inOld != inNew) {
					reload();
				}
				else if (inOld || inNew) {
					refresh();
				}
			}
		}

		protected void maxSnapChanged() {
			AbstractQueryTableModel.this.maxSnapChanged();
		}
	}

	protected class TableDisplaysObjectValues implements DisplaysObjectValues {
		@Override
		public long getSnap() {
			return snap;
		}
	}

	protected class DiffTableDisplaysObjectValues implements DisplaysObjectValues {
		@Override
		public long getSnap() {
			return diffSnap;
		}
	}

	private Trace trace;
	private long snap;
	private TraceObject curObject;
	private Trace diffTrace;
	private long diffSnap;
	private ModelQuery query;
	private Lifespan span = Lifespan.ALL;
	private boolean showHidden;

	private final ListenerForChanges listenerForChanges = newListenerForChanges();
	protected final DisplaysObjectValues display = new TableDisplaysObjectValues();
	protected final DisplaysObjectValues diffDisplay = new DiffTableDisplaysObjectValues();

	protected AbstractQueryTableModel(String name, Plugin plugin) {
		super(name, plugin.getTool(), null, true);
	}

	protected ListenerForChanges newListenerForChanges() {
		return new ListenerForChanges();
	}

	protected void maxSnapChanged() {
		// Extension point
	}

	private void removeOldTraceListener() {
		if (trace != null) {
			trace.removeListener(listenerForChanges);
		}
	}

	private void addNewTraceListener() {
		if (trace != null) {
			trace.addListener(listenerForChanges);
		}
	}

	protected void traceChanged() {
		reload();
	}

	public void setTrace(Trace trace) {
		if (Objects.equals(this.trace, trace)) {
			return;
		}
		removeOldTraceListener();
		this.trace = trace;
		addNewTraceListener();

		traceChanged();
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	protected void snapChanged() {
		refresh();
	}

	public void setSnap(long snap) {
		if (this.snap == snap) {
			return;
		}
		this.snap = snap;

		snapChanged();
	}

	@Override
	public long getSnap() {
		return snap;
	}

	protected void currentObjectChanged() {
		refresh();
	}

	public void setCurrentObject(TraceObject curObject) {
		if (this.curObject == curObject) {
			return;
		}
		this.curObject = curObject;

		currentObjectChanged();
	}

	public TraceObject getCurrentObject() {
		return curObject;
	}

	protected void diffTraceChanged() {
		refresh();
	}

	/**
	 * Set alternative trace to colorize values that differ
	 * 
	 * <p>
	 * The same trace can be used, but with an alternative snap, if desired. See
	 * {@link #setDiffSnap(long)}. One common use is to compare with the previous snap of the same
	 * trace. Another common use is to compare with the previous navigation.
	 * 
	 * @param diffTrace the alternative trace
	 */
	public void setDiffTrace(Trace diffTrace) {
		if (this.diffTrace == diffTrace) {
			return;
		}
		this.diffTrace = diffTrace;
		diffTraceChanged();
	}

	@Override
	public Trace getDiffTrace() {
		return diffTrace;
	}

	protected void diffSnapChanged() {
		refresh();
	}

	/**
	 * Set alternative snap to colorize values that differ
	 * 
	 * <p>
	 * The diff trace must be set, even if it's the same as the trace being displayed. See
	 * {@link #setDiffTrace(Trace)}.
	 * 
	 * @param diffSnap the alternative snap
	 */
	public void setDiffSnap(long diffSnap) {
		if (this.diffSnap == diffSnap) {
			return;
		}
		this.diffSnap = diffSnap;
		diffSnapChanged();
	}

	@Override
	public long getDiffSnap() {
		return diffSnap;
	}

	protected void queryChanged() {
		reload();
	}

	public void setQuery(ModelQuery query) {
		if (Objects.equals(this.query, query)) {
			return;
		}
		this.query = query;

		queryChanged();
	}

	public ModelQuery getQuery() {
		return query;
	}

	protected void spanChanged() {
		reload();
	}

	public void setSpan(Lifespan span) {
		if (Objects.equals(this.span, span)) {
			return;
		}
		this.span = span;

		spanChanged();
	}

	public Lifespan getSpan() {
		return span;
	}

	protected void showHiddenChanged() {
		reload();
	}

	public void setShowHidden(boolean showHidden) {
		if (this.showHidden == showHidden) {
			return;
		}
		this.showHidden = showHidden;

		showHiddenChanged();
	}

	public boolean isShowHidden() {
		return showHidden;
	}

	protected abstract Stream<T> streamRows(Trace trace, ModelQuery query, Lifespan span);

	@Override
	protected void doLoad(Accumulator<T> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (trace == null || query == null || trace.getObjectManager().getRootSchema() == null) {
			return;
		}
		for (T t : (Iterable<T>) streamRows(trace, query, span)::iterator) {
			accumulator.add(t);
			monitor.checkCancelled();
		}
	}

	@Override
	public Trace getDataSource() {
		return trace;
	}

	@Override
	public boolean isEdgesDiffer(TraceObjectValue newEdge, TraceObjectValue oldEdge) {
		if (DisplaysModified.super.isEdgesDiffer(newEdge, oldEdge)) {
			return true;
		}
		// Hack to incorporate _display logic to differencing.
		// This ensures "boxed" primitives show as differing at the object level
		return !Objects.equals(diffDisplay.getEdgeDisplay(oldEdge),
			display.getEdgeDisplay(newEdge));
	}

	public abstract void setDiffColor(Color diffColor);

	public abstract void setDiffColorSel(Color diffColorSel);

	public abstract T findTraceObject(TraceObject object);

	public abstract void addSeekListener(SeekListener listener);
}
