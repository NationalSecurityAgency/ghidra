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

import javax.swing.event.ListSelectionEvent;

import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceObjectThread;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

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

	private abstract static class AbstractThreadLifeBoundColumn
			extends TraceValueObjectPropertyColumn<Long> {
		public AbstractThreadLifeBoundColumn() {
			super(Long.class);
		}

		abstract Long fromLifespan(Lifespan lifespan);

		@Override
		public ValueProperty<Long> getProperty(ValueRow row) {
			return new ValueDerivedProperty<>(row, Long.class) {
				@Override
				public Long getValue() {
					// De-duplication may not select parent value at current snap 
					TraceObjectValue curVal =
						row.getValue().getChild().getCanonicalParent(row.currentSnap());
					if (curVal == null) {
						// Thread is not actually alive a current snap
						return null;
					}
					return fromLifespan(curVal.getLifespan());
				}
			};
		}
	}

	private static class ThreadCreatedColumn extends AbstractThreadLifeBoundColumn {
		@Override
		public String getColumnName() {
			return "Created";
		}

		@Override
		Long fromLifespan(Lifespan lifespan) {
			return lifespan.minIsFinite() ? lifespan.lmin() : null;
		}
	}

	private static class ThreadDestroyedColumn extends AbstractThreadLifeBoundColumn {
		@Override
		public String getColumnName() {
			return "Destroyed";
		}

		@Override
		Long fromLifespan(Lifespan lifespan) {
			return lifespan.maxIsFinite() ? lifespan.lmax() : null;
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

	private static class ThreadTableModel extends ObjectTableModel {
		protected ThreadTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addHiddenColumn(new ThreadPathColumn());
			descriptor.addVisibleColumn(new ThreadNameColumn(), 1, true);
			descriptor.addVisibleColumn(new ThreadCreatedColumn());
			descriptor.addVisibleColumn(new ThreadDestroyedColumn());
			descriptor.addVisibleColumn(new ThreadStateColumn());
			descriptor.addVisibleColumn(new ThreadCommentColumn());
			descriptor.addVisibleColumn(new ThreadPlotColumn());
			return descriptor;
		}
	}

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;

	private final SuppressableCallback<Void> cbThreadSelected = new SuppressableCallback<>();

	private final SeekListener seekListener = pos -> {
		long snap = Math.round(pos);
		if (current.getTrace() == null || snap < 0) {
			snap = 0;
		}
		traceManager.activateSnap(snap);
	};

	public DebuggerThreadsPanel(DebuggerThreadsProvider provider) {
		super(provider.plugin, provider, TraceObjectThread.class);
		setLimitToSnap(false); // TODO: Toggle for this?

		tableModel.addTableModelListener(e -> {
			// This seems a bit heavy handed
			trySelectCurrentThread();
		});
		addSeekListener(seekListener);
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
		if (object != null) {
			try (Suppression supp = cbThreadSelected.suppress(null)) {
				trySelectAncestor(object);
			}
		}
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
		ValueRow item = getSelectedItem();
		if (item != null) {
			cbThreadSelected.invoke(() -> {
				if (current.getTrace() != item.getValue().getTrace()) {
					// Prevent timing issues during navigation from causing trace changes
					// Thread table should never cause trace change anyway
					return;
				}
				traceManager.activateObject(item.getValue().getChild());
			});
		}
	}
}
