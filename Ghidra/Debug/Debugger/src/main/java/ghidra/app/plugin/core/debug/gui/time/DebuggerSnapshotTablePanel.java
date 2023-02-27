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

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.Collection;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.*;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerSnapshotTablePanel extends JPanel {

	protected enum SnapshotTableColumns
		implements EnumeratedTableColumn<SnapshotTableColumns, SnapshotRow> {
		SNAP("Snap", Long.class, SnapshotRow::getSnap),
		TIMESTAMP("Timestamp", String.class, SnapshotRow::getTimeStamp), // TODO: Use Date type here
		EVENT_THREAD("Event Thread", String.class, SnapshotRow::getEventThreadName),
		SCHEDULE("Schedule", String.class, SnapshotRow::getSchedule),
		DESCRIPTION("Description", String.class, SnapshotRow::getDescription, SnapshotRow::setDescription);

		private final String header;
		private final Function<SnapshotRow, ?> getter;
		private final BiConsumer<SnapshotRow, Object> setter;
		private final Class<?> cls;

		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter) {
			this(header, cls, getter, null);
		}

		@SuppressWarnings("unchecked")
		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter,
				BiConsumer<SnapshotRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<SnapshotRow, Object>) setter;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(SnapshotRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(SnapshotRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(SnapshotRow row, Object value) {
			setter.accept(row, value);
		}
	}

	private class SnapshotListener extends TraceDomainObjectListener {
		public SnapshotListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceSnapshotChangeType.ADDED, this::snapAdded);
			listenFor(TraceSnapshotChangeType.CHANGED, this::snapChanged);
			listenFor(TraceSnapshotChangeType.DELETED, this::snapDeleted);
		}

		private void objectRestored() {
			loadSnapshots();
		}

		private void snapAdded(TraceSnapshot snapshot) {
			if (snapshot.getKey() < 0 && hideScratch) {
				return;
			}
			SnapshotRow row = new SnapshotRow(currentTrace, snapshot);
			snapshotTableModel.add(row);
			if (currentSnap == snapshot.getKey()) {
				snapshotFilterPanel.setSelectedItem(row);
			}
		}

		private void snapChanged(TraceSnapshot snapshot) {
			if (snapshot.getKey() < 0 && hideScratch) {
				return;
			}
			snapshotTableModel.notifyUpdatedWith(row -> row.getSnapshot() == snapshot);
		}

		private void snapDeleted(TraceSnapshot snapshot) {
			if (snapshot.getKey() < 0 && hideScratch) {
				return;
			}
			snapshotTableModel.deleteWith(row -> row.getSnapshot() == snapshot);
		}
	}

	final TableCellRenderer boldCurrentRenderer = new AbstractGColumnRenderer<Object>() {
		@Override
		public String getFilterString(Object t, Settings settings) {
			return t == null ? "<null>" : t.toString();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			SnapshotRow row = (SnapshotRow) data.getRowObject();
			if (row != null && row.getSnap() == currentSnap) {
				setBold();
			}
			return this;
		}
	};

	protected final EnumeratedColumnTableModel<SnapshotRow> snapshotTableModel;
	protected final GTable snapshotTable;
	protected final GhidraTableFilterPanel<SnapshotRow> snapshotFilterPanel;
	protected boolean hideScratch = true;

	private Trace currentTrace;
	private Long currentSnap;

	protected final SnapshotListener listener = new SnapshotListener();

	public DebuggerSnapshotTablePanel(PluginTool tool) {
		super(new BorderLayout());
		snapshotTableModel =
			new DefaultEnumeratedColumnTableModel<>(tool, "Snapshots", SnapshotTableColumns.class);
		snapshotTable = new GTable(snapshotTableModel);
		snapshotTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(new JScrollPane(snapshotTable));

		snapshotFilterPanel = new GhidraTableFilterPanel<>(snapshotTable, snapshotTableModel);
		add(snapshotFilterPanel, BorderLayout.SOUTH);

		TableColumnModel columnModel = snapshotTable.getColumnModel();
		TableColumn snapCol = columnModel.getColumn(SnapshotTableColumns.SNAP.ordinal());
		snapCol.setPreferredWidth(40);
		snapCol.setCellRenderer(boldCurrentRenderer);
		TableColumn timeCol = columnModel.getColumn(SnapshotTableColumns.TIMESTAMP.ordinal());
		timeCol.setPreferredWidth(200);
		timeCol.setCellRenderer(boldCurrentRenderer);
		TableColumn etCol = columnModel.getColumn(SnapshotTableColumns.EVENT_THREAD.ordinal());
		etCol.setPreferredWidth(40);
		etCol.setCellRenderer(boldCurrentRenderer);
		TableColumn schdCol = columnModel.getColumn(SnapshotTableColumns.SCHEDULE.ordinal());
		schdCol.setPreferredWidth(60);
		schdCol.setCellRenderer(boldCurrentRenderer);
		TableColumn descCol = columnModel.getColumn(SnapshotTableColumns.DESCRIPTION.ordinal());
		descCol.setPreferredWidth(200);
		descCol.setCellRenderer(boldCurrentRenderer);
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
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadSnapshots();
	}

	public Trace getTrace() {
		return currentTrace;
	}

	public void setHideScratchSnapshots(boolean hideScratch) {
		if (this.hideScratch == hideScratch) {
			return;
		}
		this.hideScratch = hideScratch;
		if (hideScratch) {
			deleteScratchSnapshots();
		}
		else {
			loadScratchSnapshots();
		}
	}

	protected void loadSnapshots() {
		snapshotTableModel.clear();
		if (currentTrace == null) {
			return;
		}
		TraceTimeManager manager = currentTrace.getTimeManager();
		Collection<? extends TraceSnapshot> snapshots = hideScratch
				? manager.getSnapshots(0, true, Long.MAX_VALUE, true)
				: manager.getAllSnapshots();
		snapshotTableModel
				.addAll(snapshots.stream().map(s -> new SnapshotRow(currentTrace, s)).toList());
	}

	protected void deleteScratchSnapshots() {
		snapshotTableModel.deleteWith(s -> s.getSnap() < 0);
	}

	protected void loadScratchSnapshots() {
		if (currentTrace == null) {
			return;
		}
		TraceTimeManager manager = currentTrace.getTimeManager();
		snapshotTableModel.addAll(manager.getSnapshots(Long.MIN_VALUE, true, 0, false)
				.stream()
				.map(s -> new SnapshotRow(currentTrace, s))
				.toList());
	}

	public ListSelectionModel getSelectionModel() {
		return snapshotTable.getSelectionModel();
	}

	public Long getSelectedSnapshot() {
		SnapshotRow row = snapshotFilterPanel.getSelectedItem();
		return row == null ? null : row.getSnap();
	}

	public void setSelectedSnapshot(Long snap) {
		currentSnap = snap;
		if (snap == null) {
			snapshotTable.clearSelection();
			return;
		}

		SnapshotRow sel = snapshotFilterPanel.getSelectedItem();
		Long curSnap = sel == null ? null : sel.getSnap();
		if (Objects.equals(curSnap, snap)) {
			return;
		}
		SnapshotRow row = snapshotTableModel.findFirst(r -> r.getSnap() == snap);
		if (row == null) {
			snapshotTable.clearSelection();
			return;
		}
		snapshotFilterPanel.setSelectedItem(row);
		snapshotTableModel.fireTableDataChanged();
	}
}
