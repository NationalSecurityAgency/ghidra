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
package ghidra.app.plugin.core.debug.gui.stack;

import java.util.List;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.AbstractQueryTablePanel.CellActivationListener;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerStackPanel extends AbstractObjectsTableBasedPanel<TraceObjectStackFrame>
		implements ListSelectionListener, CellActivationListener {

	private static class FrameLevelColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Level";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 48;
		}
	}

	private static class FramePcColumn extends TraceValueObjectAttributeColumn<Address> {
		public FramePcColumn() {
			super(TargetStackFrame.PC_ATTRIBUTE_NAME, Address.class);
		}

		@Override
		public String getColumnName() {
			return "PC";
		}
	}

	private class FrameFunctionColumn
			extends AbstractDynamicTableColumn<ValueRow, Function, Trace> {

		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public Function getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			TraceObjectValue value =
				rowObject.getAttributeEntry(TargetStackFrame.PC_ATTRIBUTE_NAME);
			return value == null ? null : provider.getFunction((Address) value.getValue());
		}
	}

	private class StackTableModel extends ObjectTableModel {
		protected StackTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new FrameLevelColumn(), 1, true);
			descriptor.addVisibleColumn(new FramePcColumn());
			descriptor.addVisibleColumn(new FrameFunctionColumn());
			return descriptor;
		}
	}

	private final DebuggerStackProvider provider;

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;

	private final SuppressableCallback<Void> cbFrameSelected = new SuppressableCallback<>();

	public DebuggerStackPanel(DebuggerStackProvider provider) {
		super(provider.plugin, provider, TraceObjectStackFrame.class);
		this.provider = provider;
	}

	@Override
	protected ObjectTableModel createModel(Plugin plugin) {
		return new StackTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TargetObjectSchema rootSchema = object.getRoot().getTargetSchema();
		List<String> stackPath = rootSchema
				.searchForSuitable(TargetStack.class, object.getCanonicalPath().getKeyList());
		if (stackPath == null) {
			return ModelQuery.EMPTY;
		}
		TargetObjectSchema stackSchema = rootSchema.getSuccessorSchema(stackPath);
		PathMatcher matcher = stackSchema.searchFor(TargetStackFrame.class, stackPath, true);
		return new ModelQuery(matcher);
	}

	@Override
	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		super.coordinatesActivated(coordinates);
		TraceObject object = coordinates.getObject();
		if (object != null) {
			try (Suppression supp = cbFrameSelected.suppress(null)) {
				trySelectAncestor(object);
			}
		}
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		super.valueChanged(e);
		if (e.getValueIsAdjusting()) {
			return;
		}
		ValueRow item = getSelectedItem();
		if (item != null) {
			cbFrameSelected.invoke(() -> traceManager.activateObject(item.getValue().getChild()));
		}
	}
}
