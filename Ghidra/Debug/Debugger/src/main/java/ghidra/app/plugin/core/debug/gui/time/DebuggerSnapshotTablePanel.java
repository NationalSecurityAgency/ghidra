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
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.*;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix;
import ghidra.trace.util.TraceEvents;
import ghidra.util.DateUtils;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerSnapshotTablePanel extends JPanel {

	protected enum SnapshotTableColumns
		implements EnumeratedTableColumn<SnapshotTableColumns, SnapshotRow> {
		SNAP("Snap", Long.class, SnapshotRow::getSnap, false),
		TIME("Time", TraceSchedule.class, SnapshotRow::getTime, true),
		EVENT_THREAD("Event Thread", String.class, SnapshotRow::getEventThreadName, true),
		PC("PC", Address.class, SnapshotRow::getProgramCounter, true),
		MODULE("Module", String.class, SnapshotRow::getModuleName, true),
		FUNCTION("Function", ghidra.program.model.listing.Function.class, SnapshotRow::getFunction, true),
		TIMESTAMP("Timestamp", Date.class, SnapshotRow::getTimeStamp, false),
		SCHEDULE("Schedule", TraceSchedule.class, SnapshotRow::getSchedule, false),
		DESCRIPTION("Description", String.class, SnapshotRow::getDescription, //
				SnapshotRow::setDescription, true);

		private final String header;
		private final Function<SnapshotRow, ?> getter;
		private final BiConsumer<SnapshotRow, Object> setter;
		private final Class<?> cls;
		private final boolean visible;

		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter,
				boolean visible) {
			this(header, cls, getter, null, visible);
		}

		@SuppressWarnings("unchecked")
		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter,
				BiConsumer<SnapshotRow, T> setter, boolean visible) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<SnapshotRow, Object>) setter;
			this.visible = visible;
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
		public boolean isVisible() {
			return visible;
		}

		@Override
		public void setValueOf(SnapshotRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class SnapshotTableModel
			extends DefaultEnumeratedColumnTableModel<SnapshotTableColumns, SnapshotRow> {
		public SnapshotTableModel(PluginTool tool) {
			super(tool, "Snapshots", SnapshotTableColumns.class);
		}

		@Override
		public List<SnapshotTableColumns> defaultSortOrder() {
			return List.of(SnapshotTableColumns.TIME);
		}
	}

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
			loadSnapshots();
		}

		private void snapAdded(TraceSnapshot snapshot) {
			if (snapshot.getKey() < 0 && hideScratch) {
				return;
			}
			SnapshotRow row = new SnapshotRow(snapshot, tool);
			snapshotTableModel.add(row);
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

		private void valueCreated(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				snapshotTableModel.fireTableDataChanged();
			}
		}

		private void valueDeleted(TraceObjectValue value) {
			if (value.getCanonicalPath().equals(KeyPath.of(TraceTimeManager.KEY_TIME_RADIX))) {
				snapshotTableModel.fireTableDataChanged();
			}
		}
	}

	final TableCellRenderer styleCurrentRenderer = new AbstractGColumnRenderer<Object>() {
		@Override
		protected String formatNumber(Number value, Settings settings) {
			return switch (value) {
				case null -> "";
				// SNAP is the only column with Long type
				case Long snap -> getTimeRadix().format(snap);
				default -> super.formatNumber(value, settings);
			};
		}

		@Override
		protected String getText(Object value) {
			return switch (value) {
				case null -> "";
				case Date date -> DateUtils.formatDateTimestamp(date);
				case TraceSchedule schedule -> schedule.toString(getTimeRadix());
				default -> value.toString();
			};
		}

		@Override
		public String getFilterString(Object t, Settings settings) {
			return switch (t) {
				case null -> "";
				// SNAP is the only column with Long type
				case Long snap -> getTimeRadix().format(snap);
				case Number n -> formatNumber(n, settings);
				default -> getText(t);
			};
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			SnapshotRow row = (SnapshotRow) data.getRowObject();
			if (row == null || current == DebuggerCoordinates.NOWHERE) {
				// When used in a dialog, only currentTrace is set
				return this;
			}
			if (current.getViewSnap() == row.getSnap()) {
				setBold();
			}
			else if (current.getSnap() == row.getSnap()) {
				setItalic();
			}
			return this;
		}
	};

	protected final PluginTool tool;
	protected final SnapshotTableModel snapshotTableModel;
	protected final GTable snapshotTable;
	protected final GhidraTableFilterPanel<SnapshotRow> snapshotFilterPanel;
	protected boolean hideScratch = false;

	private Trace currentTrace;
	private volatile DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected final SnapshotListener listener = new SnapshotListener();

	public DebuggerSnapshotTablePanel(PluginTool tool) {
		super(new BorderLayout());
		this.tool = tool;
		snapshotTableModel = new SnapshotTableModel(tool);
		snapshotTable = new GTable(snapshotTableModel);
		snapshotTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(new JScrollPane(snapshotTable));

		snapshotFilterPanel = new GhidraTableFilterPanel<>(snapshotTable, snapshotTableModel);
		add(snapshotFilterPanel, BorderLayout.SOUTH);

		TableColumnModel columnModel = snapshotTable.getColumnModel();
		TableColumn snapCol = columnModel.getColumn(SnapshotTableColumns.SNAP.ordinal());
		snapCol.setPreferredWidth(20);
		snapCol.setCellRenderer(styleCurrentRenderer);
		TableColumn timeCol = columnModel.getColumn(SnapshotTableColumns.TIME.ordinal());
		timeCol.setPreferredWidth(20);
		timeCol.setCellRenderer(styleCurrentRenderer);
		TableColumn etCol = columnModel.getColumn(SnapshotTableColumns.EVENT_THREAD.ordinal());
		etCol.setPreferredWidth(20);
		etCol.setCellRenderer(styleCurrentRenderer);
		TableColumn pcCol = columnModel.getColumn(SnapshotTableColumns.PC.ordinal());
		pcCol.setPreferredWidth(40);
		pcCol.setCellRenderer(styleCurrentRenderer);
		TableColumn moduleCol = columnModel.getColumn(SnapshotTableColumns.MODULE.ordinal());
		moduleCol.setPreferredWidth(40);
		moduleCol.setCellRenderer(styleCurrentRenderer);
		TableColumn functionCol = columnModel.getColumn(SnapshotTableColumns.FUNCTION.ordinal());
		functionCol.setPreferredWidth(40);
		functionCol.setCellRenderer(styleCurrentRenderer);
		TableColumn timeStampCol = columnModel.getColumn(SnapshotTableColumns.TIMESTAMP.ordinal());
		timeStampCol.setPreferredWidth(200);
		timeStampCol.setCellRenderer(styleCurrentRenderer);
		TableColumn schdCol = columnModel.getColumn(SnapshotTableColumns.SCHEDULE.ordinal());
		schdCol.setPreferredWidth(60);
		schdCol.setCellRenderer(styleCurrentRenderer);
		TableColumn descCol = columnModel.getColumn(SnapshotTableColumns.DESCRIPTION.ordinal());
		descCol.setPreferredWidth(20);
		descCol.setCellRenderer(styleCurrentRenderer);
	}

	protected TimeRadix getTimeRadix() {
		return currentTrace == null ? TimeRadix.DEFAULT
				: currentTrace.getTimeManager().getTimeRadix();
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

		List<SnapshotRow> toAdd = new ArrayList<>();
		for (TraceSnapshot snapshot : hideScratch
				? manager.getSnapshots(0, true, Long.MAX_VALUE, true)
				: manager.getAllSnapshots()) {
			SnapshotRow row = new SnapshotRow(snapshot, tool);
			toAdd.add(row);
			if (current != DebuggerCoordinates.NOWHERE &&
				snapshot.getKey() == current.getViewSnap()) {
			}
		}
		snapshotTableModel.addAll(toAdd);
	}

	protected void deleteScratchSnapshots() {
		snapshotTableModel.deleteWith(s -> s.getSnap() < 0);
	}

	protected void loadScratchSnapshots() {
		if (currentTrace == null) {
			return;
		}
		TraceTimeManager manager = currentTrace.getTimeManager();
		Collection<? extends TraceSnapshot> sratch =
			manager.getSnapshots(Long.MIN_VALUE, true, 0, false);
		snapshotTableModel.addAll(sratch.stream()
				.map(s -> new SnapshotRow(s, tool))
				.collect(Collectors.toList()));
	}

	public ListSelectionModel getSelectionModel() {
		return snapshotTable.getSelectionModel();
	}

	public Long getSelectedSnapshot() {
		SnapshotRow row = snapshotFilterPanel.getSelectedItem();
		return row == null ? null : row.getSnap();
	}

	public void setCurrent(DebuggerCoordinates coords) {
		boolean fire = coords.getViewSnap() != current.getViewSnap();
		current = coords;
		if (fire) {
			snapshotTableModel.fireTableDataChanged();
		}
	}

	public void setSelectedSnapshot(Long snap) {
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
	}
}
