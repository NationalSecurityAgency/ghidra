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

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.*;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import com.google.common.collect.Collections2;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerTimeProvider extends ComponentProviderAdapter {
	private static final AutoConfigState.ClassHandler<DebuggerTimeProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerTimeProvider.class, MethodHandles.lookup());

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
			SnapshotRow row = new SnapshotRow(current.getTrace(), snapshot);
			snapshotTableModel.add(row);
			if (current.getSnap() == snapshot.getKey()) {
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

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		return true;
	}

	protected final DebuggerTimePlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // copy for transition

	protected final SnapshotListener listener = new SnapshotListener();

	@AutoServiceConsumed
	protected DebuggerTraceManagerService viewManager;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	/* testing */ final EnumeratedColumnTableModel<SnapshotRow> snapshotTableModel =
		new DefaultEnumeratedColumnTableModel<>("Snapshots", SnapshotTableColumns.class);
	/* testing */ GTable snapshotTable;
	/* testing */ GhidraTableFilterPanel<SnapshotRow> snapshotFilterPanel;

	private DebuggerSnapActionContext myActionContext;

	ToggleDockingAction actionHideScratch;

	@AutoConfigStateField
	/* testing */ boolean hideScratch = true;

	public DebuggerTimeProvider(DebuggerTimePlugin plugin) {
		super(plugin.getTool(), TITLE_PROVIDER_TIME, plugin.getName());
		this.plugin = plugin;

		autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle(TITLE_PROVIDER_TIME);
		setIcon(ICON_PROVIDER_TIME);
		setHelpLocation(HELP_PROVIDER_TIME);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		myActionContext = new DebuggerSnapActionContext(0);
		createActions();
		contextChanged();

		setVisible(true);
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void buildMainPanel() {
		snapshotTable = new GTable(snapshotTableModel);
		snapshotTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		mainPanel.add(new JScrollPane(snapshotTable));

		snapshotFilterPanel = new GhidraTableFilterPanel<>(snapshotTable, snapshotTableModel);
		mainPanel.add(snapshotFilterPanel, BorderLayout.SOUTH);

		snapshotTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			SnapshotRow row = snapshotFilterPanel.getSelectedItem();
			if (row == null) {
				myActionContext = null;
				return;
			}
			long snap = row.getSnap();
			if (snap == current.getSnap().longValue()) {
				return;
			}
			myActionContext = new DebuggerSnapActionContext(snap);
			viewManager.activateSnap(snap);
			contextChanged();
		});

		TableColumnModel columnModel = snapshotTable.getColumnModel();
		TableColumn snapCol = columnModel.getColumn(SnapshotTableColumns.SNAP.ordinal());
		snapCol.setPreferredWidth(40);
		TableColumn timeCol = columnModel.getColumn(SnapshotTableColumns.TIMESTAMP.ordinal());
		timeCol.setPreferredWidth(200);
		TableColumn etCol = columnModel.getColumn(SnapshotTableColumns.EVENT_THREAD.ordinal());
		etCol.setPreferredWidth(40);
		TableColumn schdCol = columnModel.getColumn(SnapshotTableColumns.SCHEDULE.ordinal());
		schdCol.setPreferredWidth(60);
		TableColumn descCol = columnModel.getColumn(SnapshotTableColumns.DESCRIPTION.ordinal());
		descCol.setPreferredWidth(200);
	}

	protected void createActions() {
		actionHideScratch = DebuggerResources.HideScratchSnapshotsAction.builder(plugin)
				.selected(hideScratch)
				.onAction(this::activatedHideScratch)
				.buildAndInstallLocal(this);
	}

	private void activatedHideScratch(ActionContext ctx) {
		hideScratch = !hideScratch;
		if (hideScratch) {
			deleteScratchSnapshots();
		}
		else {
			loadScratchSnapshots();
		}
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

	protected void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadSnapshots();
	}

	protected void doSetSnap(long snap) {
		SnapshotRow sel = snapshotFilterPanel.getSelectedItem();
		Long curSnap = sel == null ? null : sel.getSnap();
		if (curSnap != null && curSnap.longValue() == snap) {
			return;
		}
		SnapshotRow row = snapshotTableModel.findFirst(r -> r.getSnap() == snap);
		if (row == null) {
			snapshotTable.clearSelection();
		}
		else {
			snapshotFilterPanel.setSelectedItem(row);
		}
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;

		doSetTrace(current.getTrace());
		doSetSnap(current.getSnap());
	}

	protected void loadSnapshots() {
		snapshotTableModel.clear();
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return;
		}
		TraceTimeManager manager = curTrace.getTimeManager();
		Collection<? extends TraceSnapshot> snapshots = hideScratch
				? manager.getSnapshots(0, true, Long.MAX_VALUE, true)
				: manager.getAllSnapshots();
		snapshotTableModel.addAll(Collections2.transform(snapshots,
			s -> new SnapshotRow(curTrace, s)));
	}

	protected void deleteScratchSnapshots() {
		snapshotTableModel.deleteWith(s -> s.getSnap() < 0);
	}

	protected void loadScratchSnapshots() {
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return;
		}
		TraceTimeManager manager = curTrace.getTimeManager();
		snapshotTableModel.addAll(Collections2.transform(
			manager.getSnapshots(Long.MIN_VALUE, true, 0, false),
			s -> new SnapshotRow(curTrace, s)));
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);

		actionHideScratch.setSelected(hideScratch);
	}
}
