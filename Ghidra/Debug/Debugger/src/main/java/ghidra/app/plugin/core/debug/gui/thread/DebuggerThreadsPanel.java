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

import java.util.List;

import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;

import docking.widgets.table.AbstractDynamicTableColumn;
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
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceObjectThread;

public class DebuggerThreadsPanel extends AbstractObjectsTableBasedPanel<TraceObjectThread> {

	protected static ModelQuery successorThreads(TargetObjectSchema rootSchema, List<String> path) {
		TargetObjectSchema schema = rootSchema.getSuccessorSchema(path);
		return new ModelQuery(schema.searchFor(TargetThread.class, path, true));
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
			DebuggerCoordinates coords = provider.current.object(obj);
			return new ValueAddressProperty(row) {
				@Override
				public Address getValue() {
					return computeProgramCounter(coords);
				}
			};
		}

		@Override
		public String getColumnName() {
			return "PC";
		}
	}

	private class ThreadFunctionColumn
			extends AbstractDynamicTableColumn<ValueRow, Function, Trace> {
		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public Function getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			DebuggerCoordinates coords = provider.current.object(rowObject.currentObject());
			Address pc = computeProgramCounter(coords);
			if (pc == null) {
				return null;
			}
			return DebuggerStaticMappingUtils.getFunction(pc, coords, serviceProvider);
		}
	}

	private class ThreadModuleColumn extends AbstractDynamicTableColumn<ValueRow, String, Trace> {
		@Override
		public String getColumnName() {
			return "Module";
		}

		@Override
		public String getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			DebuggerCoordinates coords = provider.current.object(rowObject.currentObject());
			Address pc = computeProgramCounter(coords);
			if (pc == null) {
				return null;
			}
			return DebuggerStaticMappingUtils.getModuleName(pc, coords);
		}
	}

	private class ThreadSpColumn extends TraceValueObjectPropertyColumn<Address> {
		public ThreadSpColumn() {
			super(Address.class);
		}

		@Override
		public ValueProperty<Address> getProperty(ValueRow row) {
			DebuggerCoordinates coords = provider.current.object(row.currentObject());
			return new ValueAddressProperty(row) {
				@Override
				public Address getValue() {
					return SPLocationTrackingSpec.INSTANCE.computeTraceAddress(provider.getTool(),
						coords);
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
			super(TargetExecutionStateful.STATE_ATTRIBUTE_NAME, String.class);
		}

		@Override
		public String getColumnName() {
			return "State";
		}
	}

	private static class ThreadCommentColumn
			extends TraceValueObjectEditableAttributeColumn<String> {
		public ThreadCommentColumn() {
			super(TraceObjectThread.KEY_COMMENT, String.class);
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
			descriptor.addVisibleColumn(new ThreadPlotColumn());
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
		super(provider.plugin, provider, TraceObjectThread.class);
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
	protected ObjectTableModel createModel(Plugin plugin) {
		return new ThreadTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TargetObjectSchema rootSchema = object.getRoot().getTargetSchema();
		List<String> seedPath = object.getCanonicalPath().getKeyList();
		List<String> processPath = rootSchema.searchForAncestor(TargetProcess.class, seedPath);
		if (processPath != null) {
			return successorThreads(rootSchema, processPath);
		}
		List<String> containerPath =
			rootSchema.searchForSuitableContainer(TargetThread.class, seedPath);

		if (containerPath != null) {
			return successorThreads(rootSchema, containerPath);
		}
		return successorThreads(rootSchema, List.of());
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
	public void cellActivated(JTable table) {
		// No super
		ValueRow item = getSelectedItem();
		if (item != null) {
			traceManager.activateObject(item.getValue().getChild());
		}
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
