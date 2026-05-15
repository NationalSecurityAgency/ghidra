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
package ghidra.app.plugin.core.debug.gui.time;

import java.util.*;

import docking.widgets.table.ThreadedEnumeratedColumnTableModel;
import ghidra.app.plugin.core.debug.gui.time.DebuggerSnapshotTablePanel.SnapshotTableColumns;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.util.TraceEvents;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class SnapshotTableModel
		extends ThreadedEnumeratedColumnTableModel<SnapshotTableColumns, SnapshotRow> {

	private class SnapshotListener extends TraceDomainObjectListener {
		public SnapshotListener() {
			listenForUntyped(DomainObjectEvent.RESTORED, e -> objectRestored());

			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapAdded);
			listenFor(TraceEvents.SNAPSHOT_CHANGED, this::snapChanged);
			listenFor(TraceEvents.SNAPSHOT_DELETED, this::snapDeleted);

			listenFor(TraceEvents.VALUE_CREATED, this::valueCreated);
			listenFor(TraceEvents.VALUE_DELETED, this::valueDeleted);
		}

		private void objectRestored() {
			reload();
		}

		private void snapAdded(TraceSnapshot snapshot) {
			addSnapshot(snapshot);
		}

		private void snapChanged(TraceSnapshot snapshot) {
			updateSnapshot(snapshot);
		}

		private void snapDeleted(TraceSnapshot snapshot) {
			removeSnapshot(snapshot);
		}

		private void valueCreated(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				fireTableDataChanged();
			}
		}

		private void valueDeleted(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				fireTableDataChanged();
			}
		}
	}

	protected final SnapshotListener listener = new SnapshotListener();
	protected final Map<TraceSnapshot, SnapshotRow> rowMap = new HashMap<>();

	private volatile Trace currentTrace; // Because it gets set before current
	private volatile DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private boolean hideScratch;

	public SnapshotTableModel(PluginTool tool) {
		super(tool, "Snapshots", SnapshotTableColumns.class, null, true);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(listener);
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(listener);
	}

	public void setTrace(Trace trace) {
		if (this.currentTrace == trace) {
			return;
		}
		removeOldListeners();
		this.currentTrace = trace;
		addNewListeners();

		reload();
	}

	public Trace getTrace() {
		return currentTrace;
	}

	public void setCurrent(DebuggerCoordinates coords) {
		assert coords.getTrace() == currentTrace;
		this.current = coords;
	}

	public DebuggerCoordinates getCurrent() {
		return current;
	}

	public void setHideScratch(boolean hideScratch) {
		if (this.hideScratch == hideScratch) {
			return;
		}
		this.hideScratch = hideScratch;
		reload();
	}

	@Override
	public List<SnapshotTableColumns> defaultSortOrder() {
		return List.of(SnapshotTableColumns.TIME);
	}

	@Override
	protected void doLoad(Accumulator<SnapshotRow> accumulator, TaskMonitor monitor)
			throws CancelledException {
		rowMap.clear();
		if (currentTrace == null) {
			return;
		}
		TraceTimeManager manager = currentTrace.getTimeManager();
		Long maxSnap = manager.getMaxSnap();
		monitor.initialize(maxSnap == null ? 0 : maxSnap.longValue(), "Reading Snapshots");
		for (TraceSnapshot snapshot : hideScratch
				? manager.getSnapshots(0, true, Long.MAX_VALUE, true)
				: manager.getAllSnapshots()) {
			SnapshotRow row = new SnapshotRow(snapshot, serviceProvider);
			rowMap.put(snapshot, row);
			accumulator.add(row);
			monitor.setProgress(Math.max(0, snapshot.getKey()));
			monitor.checkCancelled();
		}
	}

	public void addSnapshot(TraceSnapshot snapshot) {
		if (snapshot.getKey() < 0 && hideScratch) {
			return;
		}
		SnapshotRow row =
			rowMap.computeIfAbsent(snapshot, s -> new SnapshotRow(s, serviceProvider));
		addObject(row);
	}

	public void updateSnapshot(TraceSnapshot snapshot) {
		if (snapshot.getKey() < 0 && hideScratch) {
			return;
		}
		SnapshotRow row = rowMap.get(snapshot);
		if (row == null) {
			return;
		}
		updateObject(row);
	}

	public void removeSnapshot(TraceSnapshot snapshot) {
		if (snapshot.getKey() < 0 && hideScratch) {
			return;
		}
		SnapshotRow row = rowMap.remove(snapshot);
		if (row == null) {
			return;
		}
		removeObject(row);
	}

	public SnapshotRow getRow(long snap) {
		if (currentTrace == null) {
			return null;
		}
		TraceSnapshot snapshot = currentTrace.getTimeManager().getSnapshot(snap, false);
		if (snapshot == null) {
			return null;
		}
		return rowMap.get(snapshot);
	}
}
