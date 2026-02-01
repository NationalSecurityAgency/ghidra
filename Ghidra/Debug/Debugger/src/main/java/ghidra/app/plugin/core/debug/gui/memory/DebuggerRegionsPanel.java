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
package ghidra.app.plugin.core.debug.gui.memory;

import java.util.Set;
import java.util.stream.Collectors;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemory;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceProcess;

public class DebuggerRegionsPanel extends AbstractObjectsTableBasedPanel<TraceMemoryRegion> {

	private static class RegionKeyColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Key";
		}
	}

	private static class RegionPathColumn extends TraceValueKeyColumn {
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

	private static class RegionNameColumn extends TraceValueValColumn {
		@Override
		public String getColumnName() {
			return "Name";
		}
	}

	private static class RegionStartColumn extends AbstractTraceValueObjectAddressColumn {
		public RegionStartColumn() {
			super(TraceMemoryRegion.KEY_RANGE);
		}

		@Override
		public String getColumnName() {
			return "Start";
		}

		@Override
		protected Address fromRange(AddressRange range) {
			return range.getMinAddress();
		}
	}

	private static class RegionEndColumn extends AbstractTraceValueObjectAddressColumn {
		public RegionEndColumn() {
			super(TraceMemoryRegion.KEY_RANGE);
		}

		@Override
		public String getColumnName() {
			return "End";
		}

		@Override
		protected Address fromRange(AddressRange range) {
			return range.getMaxAddress();
		}
	}

	private static class RegionLengthColumn extends AbstractTraceValueObjectLengthColumn {
		public RegionLengthColumn() {
			super(TraceMemoryRegion.KEY_RANGE);
		}

		@Override
		public String getColumnName() {
			return "Length";
		}
	}

	public abstract static class RegionFlagColumn extends TraceValueObjectAttributeColumn<Boolean> {
		public RegionFlagColumn(String attributeName) {
			super(attributeName, Boolean.class);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	public static class RegionReadColumn extends RegionFlagColumn {
		public RegionReadColumn() {
			super(TraceMemoryRegion.KEY_READABLE);
		}

		@Override
		public String getColumnName() {
			return "Read";
		}
	}

	public static class RegionWriteColumn extends RegionFlagColumn {
		public RegionWriteColumn() {
			super(TraceMemoryRegion.KEY_WRITABLE);
		}

		@Override
		public String getColumnName() {
			return "Write";
		}
	}

	public static class RegionExecuteColumn extends RegionFlagColumn {
		public RegionExecuteColumn() {
			super(TraceMemoryRegion.KEY_EXECUTABLE);
		}

		@Override
		public String getColumnName() {
			return "Execute";
		}
	}

	private static class RegionTableModel extends ObjectTableModel {
		protected RegionTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addHiddenColumn(new RegionKeyColumn());
			descriptor.addHiddenColumn(new RegionPathColumn());
			descriptor.addVisibleColumn(new RegionNameColumn());
			descriptor.addVisibleColumn(new RegionStartColumn(), 1, true);
			descriptor.addVisibleColumn(new RegionEndColumn());
			descriptor.addVisibleColumn(new RegionLengthColumn());
			descriptor.addVisibleColumn(new RegionReadColumn());
			descriptor.addVisibleColumn(new RegionWriteColumn());
			descriptor.addVisibleColumn(new RegionExecuteColumn());
			return descriptor;
		}
	}

	protected static ModelQuery successorRegions(TraceObjectSchema rootSchema, KeyPath path) {
		TraceObjectSchema schema = rootSchema.getSuccessorSchema(path);
		return new ModelQuery(schema.searchFor(TraceMemoryRegion.class, path, true));
	}

	protected Set<TraceMemoryRegion> getSelectedRegions(DebuggerObjectActionContext ctx) {
		return ctx == null ? null : getSelected(ctx).collect(Collectors.toSet());
	}

	public DebuggerRegionsPanel(DebuggerRegionsProvider provider) {
		super(provider.plugin, provider, TraceMemoryRegion.class);
	}

	@Override
	protected ObjectTableModel createModel() {
		return new RegionTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TraceObjectSchema rootSchema = object.getRoot().getSchema();
		KeyPath seedPath = object.getCanonicalPath();
		KeyPath processPath = rootSchema.searchForAncestor(TraceProcess.class, seedPath);
		if (processPath != null) {
			ModelQuery result = successorRegions(rootSchema, processPath);
			if (!result.isEmpty()) {
				return result;
			}
		}
		KeyPath memoryPath = rootSchema.searchForSuitable(TraceMemory.class, seedPath);
		if (memoryPath != null) {
			ModelQuery result = successorRegions(rootSchema, memoryPath);
			if (!result.isEmpty()) {
				return result;
			}
		}
		return successorRegions(rootSchema, KeyPath.ROOT);
	}

	public void setSelectedRegions(Set<TraceMemoryRegion> sel) {
		setSelected(sel);
	}
}
