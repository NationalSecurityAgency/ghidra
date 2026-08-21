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
package ghidra.app.plugin.core.debug.gui.thread;

import java.util.Objects;

import javax.swing.event.ListSelectionEvent;

import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.plugin.core.debug.gui.action.PCLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.action.SPLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceExecutionStateful;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.trace.model.thread.TraceThread;

public class DebuggerThreadsPanel extends AbstractObjectsTableBasedPanel<TraceThread> {

	protected static ModelQuery successorThreads(TraceObjectSchema rootSchema, KeyPath path) {
		TraceObjectSchema schema = rootSchema.getSuccessorSchema(path);
		return new ModelQuery(schema.searchFor(TraceThread.class, path, true));
	}

	private static class ThreadPathColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getValue().getCanonicalPath().toString();
		}
	}

	private static class ThreadNameColumn extends TraceValueValColumn {
		@Override
		public String getColumnName() {
			return "Name";
		}
	}

	DebuggerCoordinates coordsForObject(TraceObject object) {
		if (provider.current.getTrace() != object.getTrace()) {
			// This can happen transiently, so just find something graceful
			return DebuggerCoordinates.NOWHERE.object(object).frame(0);
		}
		return provider.current.object(object).frame(0);
	}

	DebuggerCoordinates diffCoordsForObject(TraceObject object) {
		if (tableModel.getDiffTrace() == null) {
			return DebuggerCoordinates.NOWHERE;
		}
		return DebuggerCoordinates.NOWHERE
				.trace(tableModel.getDiffTrace())
				.path(object.getCanonicalPath()) // May not exist in diff trace
				.frame(0)
				.snap(tableModel.getDiffSnap());
	}

	private Address computeProgramCounter(DebuggerCoordinates coords) {
		// TODO: Cheating a bit. Also, can user configure whether by stack or regs?
		return PCLocationTrackingSpec.INSTANCE.computeTraceAddress(provider.getTool(),
			coords);
	}

	private class ThreadPcColumn extends TraceValueObjectPropertyColumn<Address> {
		public ThreadPcColumn() {
			super(Address.class);
		}

		@Override
		public ValueProperty<Address> getProperty(ValueRow row) {
			TraceObject obj = row.getValue().getChild();
			DebuggerCoordinates coords = coordsForObject(obj);
			DebuggerCoordinates diffCoords = diffCoordsForObject(obj);
			return new ValueAddressProperty(row) {
				@Override
				public Address getValue() {
					return computeProgramCounter(coords);
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeProgramCounter(coords),
						computeProgramCounter(diffCoords));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "PC";
		}
	}

	private Function computeFunction(DebuggerCoordinates coords, ServiceProvider serviceProvider) {
		Address pc = computeProgramCounter(coords);
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getFunction(pc, coords, serviceProvider);
	}

	private class ThreadFunctionColumn extends TraceValueObjectPropertyColumn<Function> {
		public ThreadFunctionColumn() {
			super(Function.class);
		}

		@Override
		public ValueProperty<Function> getProperty(ValueRow row) {
			throw new AssertionError(); // overrode caller to this
		}

		@Override
		public ValueProperty<Function> getValue(ValueRow row, Settings settings, Trace data,
				ServiceProvider serviceProvider) {
			TraceObject obj = row.getValue().getChild();
			DebuggerCoordinates coords = coordsForObject(obj);
			DebuggerCoordinates diffCoords = diffCoordsForObject(obj);
			return new ValueDerivedProperty<>(row, Function.class) {
				@Override
				public Function getValue() {
					return computeFunction(coords, serviceProvider);
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeFunction(coords, serviceProvider),
						computeFunction(diffCoords, serviceProvider));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "Function";
		}
	}

	private String computeModuleName(DebuggerCoordinates coords) {
		Address pc = computeProgramCounter(coords);
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getModuleName(pc, coords);
	}

	private class ThreadModuleColumn extends TraceValueObjectPropertyColumn<String> {
		public ThreadModuleColumn() {
			super(String.class);
		}

		@Override
		public ValueProperty<String> getProperty(ValueRow row) {
			TraceObject obj = row.getValue().getChild();
			DebuggerCoordinates coords = coordsForObject(obj);
			DebuggerCoordinates diffCoords = diffCoordsForObject(obj);
			return new ValueDerivedProperty<>(row, String.class) {
				@Override
				public String getValue() {
					return computeModuleName(coords);
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeModuleName(coords),
						computeModuleName(diffCoords));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "Module";
		}
	}

	private Address computeStackPointer(DebuggerCoordinates coords) {
		return SPLocationTrackingSpec.INSTANCE.computeTraceAddress(provider.getTool(),
			coords);
	}

	private class ThreadSpColumn extends TraceValueObjectPropertyColumn<Address> {
		public ThreadSpColumn() {
			super(Address.class);
		}

		@Override
		public ValueProperty<Address> getProperty(ValueRow row) {
			TraceObject obj = row.getValue().getChild();
			DebuggerCoordinates coords = coordsForObject(obj);
			DebuggerCoordinates diffCoords = diffCoordsForObject(obj);
			return new ValueAddressProperty(row) {
				@Override
				public Address getValue() {
					return computeStackPointer(coords);
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeStackPointer(coords),
						computeStackPointer(diffCoords));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "SP";
		}
	}

	private static class ThreadStateColumn extends TraceValueObjectAttributeColumn<String> {
		public ThreadStateColumn() {
			// NB. The recorder converts enums to strings
			super(TraceExecutionStateful.KEY_STATE, String.class);
		}

		@Override
		public String getColumnName() {
			return "State";
		}
	}

	private static class ThreadCommentColumn
			extends TraceValueObjectEditableAttributeColumn<String> {
		public ThreadCommentColumn() {
			super(TraceThread.KEY_COMMENT, String.class);
		}

		@Override
		public String getColumnName() {
			return "Comment";
		}
	}

	private static class ThreadPlotColumn extends TraceValueLifePlotColumn {
	}

	private class ThreadTableModel extends ObjectTableModel {
		protected ThreadTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TraceValueLifePlotColumn newPlotColumn() {
			return new ThreadPlotColumn();
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addHiddenColumn(new ThreadPathColumn());
			descriptor.addVisibleColumn(new ThreadNameColumn(), 1, true);
			descriptor.addVisibleColumn(new ThreadPcColumn());
			descriptor.addVisibleColumn(new ThreadFunctionColumn());
			descriptor.addHiddenColumn(new ThreadModuleColumn());
			descriptor.addHiddenColumn(new ThreadSpColumn());
			descriptor.addVisibleColumn(new ThreadStateColumn());
			descriptor.addHiddenColumn(new ThreadCommentColumn());
			descriptor.addVisibleColumn(getPlotColumn());
			return descriptor;
		}
	}

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;

	private final DebuggerThreadsProvider provider;

	private final SeekListener seekListener = pos -> {
		long snap = Math.round(pos);
		if (snap < 0) {
			snap = 0;
		}
		long max =
			current.getTrace() == null ? 0 : current.getTrace().getTimeManager().getMaxSnap();
		if (snap > max) {
			snap = max;
		}
		traceManager.activateSnap(snap);
	};

	public DebuggerThreadsPanel(DebuggerThreadsProvider provider) {
		super(provider.plugin, provider, TraceThread.class);
		this.provider = provider;
		setLimitToSnap(false); // TODO: Toggle for this?

		addSeekListener(seekListener);

		tableModel.addThreadedTableModelListener(new ThreadedTableModelListener() {
			@Override
			public void loadingStarted() {
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				trySelectCurrentThread();
			}

			@Override
			public void loadPending() {
			}
		});
	}

	@Override
	protected ObjectTableModel createModel() {
		return new ThreadTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TraceObjectSchema rootSchema = object.getRoot().getSchema();
		KeyPath seedPath = object.getCanonicalPath();
		KeyPath processPath = rootSchema.searchForAncestor(TraceProcess.class, seedPath);
		if (processPath != null) {
			ModelQuery result = successorThreads(rootSchema, processPath);
			if (!result.isEmpty()) {
				return result;
			}
		}
		KeyPath containerPath =
			rootSchema.searchForSuitableContainer(TraceThread.class, seedPath);

		if (containerPath != null) {
			ModelQuery result = successorThreads(rootSchema, containerPath);
			if (!result.isEmpty()) {
				return result;
			}
		}
		return successorThreads(rootSchema, KeyPath.ROOT);
	}

	private void trySelectCurrentThread() {
		TraceObject object = current.getObject();
		if (object == null) {
			return;
		}
		trySelectAncestor(object);
	}

	@Override
	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		super.coordinatesActivated(coordinates);
		trySelectCurrentThread();
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		super.valueChanged(e);
		if (e.getValueIsAdjusting()) {
			return;
		}
		provider.threadsPanelContextChanged();
	}
}
