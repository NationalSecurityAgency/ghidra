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
package ghidra.app.plugin.core.debug.gui.watch;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;

import docking.WindowPosition;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerListingService;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.Trace.TraceMemoryStateChangeType;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerWatchesProvider extends ComponentProviderAdapter implements Unfinished {
	protected enum WatchTableColumns implements EnumeratedTableColumn<WatchTableColumns, WatchRow> {
		EXPRESSION("Expression", String.class, WatchRow::getExpression, WatchRow::setExpression),
		ADDRESS("Address", Address.class, WatchRow::getAddress),
		DATA_TYPE("Data Type", DataType.class, WatchRow::getDataType, WatchRow::setDataType),
		RAW("Raw", String.class, WatchRow::getRawValueString),
		VALUE("Value", String.class, WatchRow::getValueString),
		ERROR("Error", String.class, WatchRow::getError);

		private final String header;
		private final Function<WatchRow, ?> getter;
		private final BiConsumer<WatchRow, ?> setter;
		private final Class<?> cls;

		<T> WatchTableColumns(String header, Class<T> cls, Function<WatchRow, T> getter,
				BiConsumer<WatchRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = setter;
		}

		<T> WatchTableColumns(String header, Class<T> cls, Function<WatchRow, T> getter) {
			this(header, cls, getter, null);
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(WatchRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(WatchRow row) {
			return setter != null;
		}
	}

	protected static class WatchTableModel
			extends DefaultEnumeratedColumnTableModel<WatchTableColumns, WatchRow> {
		public WatchTableModel() {
			super("Watches", WatchTableColumns.class);
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getRecorder(), b.getRecorder())) {
			return false; // May need to read target
		}
		if (!Objects.equals(a.getSnap(), b.getSnap())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		// TODO: Ticks
		return true;
	}

	class ForDepsListener extends TraceDomainObjectListener {
		public ForDepsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, this::objectRestored);
			listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
			listenFor(TraceMemoryStateChangeType.CHANGED, this::stateChanged);
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			changed.add(current.getView().getMemory());
			changeDebouncer.contact(null);
		}

		private void bytesChanged(TraceAddressSpace space, TraceAddressSnapRange range) {
			if (space.getThread() == current.getThread()) {
				changed.add(range.getRange());
				changeDebouncer.contact(null);
			}
		}

		private void stateChanged(TraceAddressSpace space, TraceAddressSnapRange range) {
			if (space.getThread() == current.getThread()) {
				changed.add(range.getRange());
				changeDebouncer.contact(null);
			}
		}
	}

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition

	@AutoServiceConsumed
	private DebuggerListingService listingService; // TODO: For goto
	// TODO: Allow address marking
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final AddressSet changed = new AddressSet();
	private final AsyncDebouncer<Void> changeDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);
	private ForDepsListener forDepsListener = new ForDepsListener();

	protected final WatchTableModel watchTableModel = new WatchTableModel();
	protected GhidraTable watchTable;
	protected GhidraTableFilterPanel<WatchRow> watchFilterPanel;

	private JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerWatchActionContext myActionContext;

	public DebuggerWatchesProvider(DebuggerWatchesPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_WATCHES, plugin.getName());

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_WATCHES);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.RIGHT);
		createActions();

		setVisible(true);
		contextChanged();

		changeDebouncer.addListener(__ -> doCheckDepsAndReevaluate());
	}

	protected void buildMainPanel() {
		watchTable = new GhidraTable(watchTableModel);
		mainPanel.add(new JScrollPane(watchTable));
		watchFilterPanel = new GhidraTableFilterPanel<>(watchTable, watchTableModel);
		mainPanel.add(watchFilterPanel, BorderLayout.SOUTH);

		watchTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			contextChanged();
		});
		watchTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2 || e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				if (listingService == null) {
					return;
				}
				if (myActionContext == null) {
					return;
				}
				Address address = myActionContext.getWatchRow().getAddress();
				if (address == null || !address.isMemoryAddress()) {
					return;
				}
				listingService.goTo(address, true);
			}
		});
	}

	@Override
	public void contextChanged() {
		myActionContext =
			new DebuggerWatchActionContext(this, watchFilterPanel.getSelectedItems(), watchTable);
		super.contextChanged();
	}

	protected void createActions() {
		// TODO: Apply data type to listing
		// TODO: Select read addresses
		// TODO: Add
		// TODO: Remove
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(forDepsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(forDepsListener);
	}

	private void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		this.currentTrace = trace;
		addNewListeners();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;

		doSetTrace(current.getTrace());

		if (current.getRecorder() != null) {
			readTarget();
		}
		reevaluate();
	}

	public synchronized void readTarget() {
		for (WatchRow row : watchTableModel.getModelData()) {
			if (row.getReads().intersects(changed)) {
				row.doTargetReads();
			}
		}
	}

	public synchronized void doCheckDepsAndReevaluate() {
		for (WatchRow row : watchTableModel.getModelData()) {
			if (row.getReads().intersects(changed)) {
				row.reevaluate();
			}
		}
		changed.clear();
		Swing.runIfSwingOrRunLater(() -> watchTableModel.fireTableDataChanged());
	}

	public void reevaluate() {
		for (WatchRow row : watchTableModel.getModelData()) {
			row.reevaluate();
		}
		changed.clear();
	}
}
