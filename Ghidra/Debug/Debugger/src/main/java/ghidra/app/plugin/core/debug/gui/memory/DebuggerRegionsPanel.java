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

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.AbstractQueryTablePanel.CellActivationListener;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.HTMLUtilities;

public class DebuggerRegionsPanel extends ObjectsTablePanel
		implements ListSelectionListener, CellActivationListener {

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

	private abstract static class ValueAddress extends ValueDerivedProperty<Address> {
		public ValueAddress(ValueRow row) {
			super(row, Address.class);
		}

		@Override
		public String getDisplay() {
			Address value = getValue();
			return value == null ? "" : value.toString();
		}

		@Override
		public String getHtmlDisplay() {
			Address value = getValue();
			return value == null ? ""
					: ("<html><body style='font-family:monospaced'>" +
						HTMLUtilities.escapeHTML(value.toString()));
		}

		@Override
		public String getToolTip() {
			Address value = getValue();
			return value == null ? "" : value.toString(true);
		}

		@Override
		public boolean isModified() {
			return false;
		}
	}

	private abstract static class RegionAddressColumn
			extends TraceValueObjectPropertyColumn<Address> {
		public RegionAddressColumn() {
			super(Address.class);
		}

		abstract Address fromRange(AddressRange range);

		@Override
		public ValueProperty<Address> getProperty(ValueRow row) {
			return new ValueAddress(row) {
				@Override
				public Address getValue() {
					TraceObjectValue entry =
						row.getAttributeEntry(TargetMemoryRegion.RANGE_ATTRIBUTE_NAME);
					return entry == null || !(entry.getValue() instanceof AddressRange range)
							? null
							: fromRange(range);
				}
			};
		}
	}

	private static class RegionStartColumn extends RegionAddressColumn {
		@Override
		public String getColumnName() {
			return "Start";
		}

		@Override
		Address fromRange(AddressRange range) {
			return range.getMinAddress();
		}
	}

	private static class RegionEndColumn extends RegionAddressColumn {
		@Override
		public String getColumnName() {
			return "End";
		}

		@Override
		Address fromRange(AddressRange range) {
			return range.getMaxAddress();
		}
	}

	private static class RegionLengthColumn extends TraceValueObjectPropertyColumn<Long> {
		public RegionLengthColumn() {
			super(Long.class);
		}

		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public ValueProperty<Long> getProperty(ValueRow row) {
			return new ValueDerivedProperty<>(row, Long.class) {
				@Override
				public Long getValue() {
					TraceObjectValue entry =
						row.getAttributeEntry(TargetMemoryRegion.RANGE_ATTRIBUTE_NAME);
					return entry == null || !(entry.getValue() instanceof AddressRange range)
							? null
							: range.getLength();
				}

				@Override
				public String getDisplay() {
					Long value = getValue();
					return value == null ? "" : ("0x" + Long.toUnsignedString(value, 16));
				}

				@Override
				public String getHtmlDisplay() {
					Long value = getValue();
					return value == null ? ""
							: ("<html><body style='font-family:monospaced'>0x" +
								Long.toUnsignedString(value, 16));
				}

				@Override
				public String getToolTip() {
					return getDisplay();
				}

				@Override
				public boolean isModified() {
					return false;
				}
			};
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
			super(TargetMemoryRegion.READABLE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Read";
		}
	}

	public static class RegionWriteColumn extends RegionFlagColumn {
		public RegionWriteColumn() {
			super(TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Write";
		}
	}

	public static class RegionExecuteColumn extends RegionFlagColumn {
		public RegionExecuteColumn() {
			super(TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Execute";
		}
	}

	private class RegionTableModel extends ObjectTableModel {
		protected RegionTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addHiddenColumn(new RegionKeyColumn());
			descriptor.addHiddenColumn(new RegionPathColumn());
			descriptor.addVisibleColumn(new RegionNameColumn());
			descriptor.addVisibleColumn(new RegionStartColumn());
			descriptor.addVisibleColumn(new RegionEndColumn());
			descriptor.addVisibleColumn(new RegionLengthColumn());
			descriptor.addVisibleColumn(new RegionReadColumn());
			descriptor.addVisibleColumn(new RegionWriteColumn());
			descriptor.addVisibleColumn(new RegionExecuteColumn());
			return descriptor;
		}
	}

	private final DebuggerRegionsProvider provider;

	private DebuggerObjectActionContext myActionContext;

	public DebuggerRegionsPanel(DebuggerRegionsProvider provider) {
		super(provider.plugin);
		this.provider = provider;

		setLimitToSnap(true);
		setShowHidden(false);

		addSelectionListener(this);
		addCellActivationListener(this);
	}

	@Override
	protected ObjectTableModel createModel(Plugin plugin) {
		return new RegionTableModel(plugin);
	}

	public DebuggerObjectActionContext getActionContext() {
		return myActionContext;
	}

	protected static ModelQuery successorRegions(TargetObjectSchema rootSchema, List<String> path) {
		TargetObjectSchema schema = rootSchema.getSuccessorSchema(path);
		return new ModelQuery(schema.searchFor(TargetMemoryRegion.class, path, true));
	}

	protected ModelQuery computeQuery(TraceObject object) {
		if (object == null) {
			return ModelQuery.EMPTY;
		}
		TargetObjectSchema rootSchema = object.getRoot().getTargetSchema();
		List<String> seedPath = object.getCanonicalPath().getKeyList();
		List<String> processPath = rootSchema.searchForAncestor(TargetProcess.class, seedPath);
		if (processPath != null) {
			return successorRegions(rootSchema, processPath);
		}
		List<String> memoryPath = rootSchema.searchForSuitable(TargetMemory.class, seedPath);
		if (memoryPath != null) {
			return successorRegions(rootSchema, memoryPath);
		}
		return successorRegions(rootSchema, List.of());
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		TraceObject object = coordinates.getObject();
		setQuery(computeQuery(object));
		goToCoordinates(coordinates);
	}

	boolean isContextNonEmpty(DebuggerObjectActionContext ctx) {
		return ctx != null && !ctx.getObjectValues().isEmpty();
	}

	protected static Set<TraceMemoryRegion> getSelectedRegions(DebuggerObjectActionContext ctx) {
		return ctx == null ? null
				: ctx.getObjectValues()
						.stream()
						.filter(v -> v.isObject())
						.map(v -> v.getChild().queryInterface(TraceObjectMemoryRegion.class))
						.filter(r -> r != null)
						.collect(Collectors.toSet());
	}

	public void setSelectedRegions(Set<TraceMemoryRegion> sel) {
		trySelect(sel.stream()
				.filter(r -> r instanceof TraceObjectMemoryRegion)
				.map(r -> ((TraceObjectMemoryRegion) r).getObject())
				.collect(Collectors.toSet()));
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		List<ValueRow> sel = getSelectedItems();
		if (!sel.isEmpty()) {
			myActionContext = new DebuggerObjectActionContext(
				sel.stream().map(r -> r.getValue()).collect(Collectors.toList()), provider, this);
		}
	}

	@Override
	public void cellActivated(JTable table) {
		if (provider.listingService == null) {
			return;
		}
		int row = table.getSelectedRow();
		int col = table.getSelectedColumn();
		Object value = table.getValueAt(row, col);
		if (!(value instanceof ValueProperty<?> property)) {
			return;
		}
		Object propVal = property.getValue();
		if (propVal instanceof Address address) {
			provider.listingService.goTo(address, true);
		}
		else if (propVal instanceof AddressRange range) {
			provider.listingService.setCurrentSelection(
				new ProgramSelection(range.getMinAddress(), range.getMaxAddress()));
			provider.listingService.goTo(range.getMinAddress(), true);
		}
	}
}
