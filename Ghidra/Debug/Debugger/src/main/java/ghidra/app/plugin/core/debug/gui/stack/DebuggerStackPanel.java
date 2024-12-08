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
import java.util.Objects;

import javax.swing.JTable;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
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

public class DebuggerStackPanel extends AbstractObjectsTableBasedPanel<TraceObjectStackFrame>
		implements ListSelectionListener {

	private static class FrameLevelColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Level";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 60;
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

	static Address computeProgramCounter(ValueRow row, long snap) {
		if (!(row.getValue().getValue() instanceof TraceObject object)) {
			return null;
		}
		TraceObjectValue attrPc = object.getAttribute(snap, TargetStackFrame.PC_ATTRIBUTE_NAME);
		if (attrPc == null || !(attrPc.getValue() instanceof Address pc)) {
			return null;
		}
		return pc;
	}

	private Function computeFunction(ValueRow row, long snap, ServiceProvider serviceProvider) {
		Address pc = computeProgramCounter(row, snap);
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getFunction(pc, provider.current, serviceProvider);
	}

	private class FrameFunctionColumn extends TraceValueObjectPropertyColumn<Function> {
		public FrameFunctionColumn() {
			super(Function.class);
		}

		@Override
		public ValueProperty<Function> getProperty(ValueRow row) {
			throw new AssertionError(); // overrode caller to this
		}

		@Override
		public ValueProperty<Function> getValue(ValueRow row, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return new ValueDerivedProperty<>(row, Function.class) {
				@Override
				public Function getValue() {
					return computeFunction(row, row.currentSnap(), serviceProvider);
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeFunction(row, row.currentSnap(), serviceProvider),
						computeFunction(row, row.previousSnap(), serviceProvider));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "Function";
		}
	}

	private String computeModuleName(ValueRow row, long snap) {
		Address pc = computeProgramCounter(row, snap);
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getModuleName(pc, provider.current);
	}

	private class FrameModuleColumn extends TraceValueObjectPropertyColumn<String> {
		public FrameModuleColumn() {
			super(String.class);
		}

		@Override
		public ValueProperty<String> getProperty(ValueRow row) {
			return new ValueDerivedProperty<>(row, String.class) {
				@Override
				public String getValue() {
					return computeModuleName(row, row.currentSnap());
				}

				@Override
				public boolean isModified() {
					return !Objects.equals(computeModuleName(row, row.currentSnap()),
						computeModuleName(row, row.previousSnap()));
				}
			};
		}

		@Override
		public String getColumnName() {
			return "Module";
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
			descriptor.addVisibleColumn(new FrameModuleColumn());
			return descriptor;
		}
	}

	private final DebuggerStackProvider provider;

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;

	public DebuggerStackPanel(DebuggerStackProvider provider) {
		super(provider.plugin, provider, TraceObjectStackFrame.class);
		this.provider = provider;
	}

	@Override
	protected ObjectTableModel createModel() {
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
			trySelectAncestor(object);
		}
	}

	@Override
	public void cellActivated(JTable table) {
		/**
		 * Override, because PC columns is fairly wide and representative of the stack frame.
		 * Likely, when the user double-clicks, they mean to activate the frame, even if it happens
		 * to be in that column. Simply going to the address will confuse and/or disappoint.
		 */
		ValueRow item = getSelectedItem();
		if (item != null) {
			traceManager.activateObject(item.getValue().getChild());
		}
	}
}
