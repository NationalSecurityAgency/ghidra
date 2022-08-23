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
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.AbstractDebuggerMapProposalDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Swing;

public class DebuggerRegionMapProposalDialog
		extends AbstractDebuggerMapProposalDialog<RegionMapEntry> {

	static final int BUTTON_SIZE = 32;

	protected enum RegionMapTableColumns
		implements EnumeratedTableColumn<RegionMapTableColumns, RegionMapEntry> {
		REMOVE("Remove", String.class, e -> "Remove Proposed Entry", (e, v) -> nop()),
		REGION_NAME("Region", String.class, e -> e.getRegion().getName()),
		DYNAMIC_BASE("Dynamic Base", Address.class, e -> e.getRegion().getMinAddress()),
		CHOOSE("Choose", String.class, e -> "Choose Block", (e, s) -> nop()),
		PROGRAM_NAME("Program", String.class, e -> e.getToProgram().getName()),
		BLOCK_NAME("Block", String.class, e -> e.getBlock().getName()),
		STATIC_BASE("Static Base", Address.class, e -> e.getBlock().getStart()),
		SIZE("Size", Long.class, e -> e.getMappingLength());

		private final String header;
		private final Class<?> cls;
		private final Function<RegionMapEntry, ?> getter;
		private final BiConsumer<RegionMapEntry, Object> setter;

		private static void nop() {
		}

		@SuppressWarnings("unchecked")
		<T> RegionMapTableColumns(String header, Class<T> cls, Function<RegionMapEntry, T> getter,
				BiConsumer<RegionMapEntry, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<RegionMapEntry, Object>) setter;
		}

		<T> RegionMapTableColumns(String header, Class<T> cls,
				Function<RegionMapEntry, T> getter) {
			this(header, cls, getter, null);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(RegionMapEntry row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(RegionMapEntry row) {
			return setter != null;
		}

		@Override
		public void setValueOf(RegionMapEntry row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class RegionMapPropsalTableModel extends
			DefaultEnumeratedColumnTableModel<RegionMapTableColumns, RegionMapEntry> {

		public RegionMapPropsalTableModel(PluginTool tool) {
			super(tool, "Region Map", RegionMapTableColumns.class);
		}

		@Override
		public List<RegionMapTableColumns> defaultSortOrder() {
			return List.of(RegionMapTableColumns.REGION_NAME);
		}
	}

	private final DebuggerRegionsProvider provider;

	public DebuggerRegionMapProposalDialog(DebuggerRegionsProvider provider) {
		super(provider.getTool(), DebuggerResources.NAME_MAP_REGIONS);
		this.provider = provider;
	}

	@Override
	protected RegionMapPropsalTableModel createTableModel(PluginTool tool) {
		return new RegionMapPropsalTableModel(tool);
	}

	@Override
	protected void populateComponents() {
		super.populateComponents();
		setPreferredSize(600, 300);

		TableColumnModel columnModel = table.getColumnModel();

		TableColumn removeCol = columnModel.getColumn(RegionMapTableColumns.REMOVE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, removeCol,
			DebuggerResources.ICON_DELETE, BUTTON_SIZE, this::removeEntry);

		TableColumn dynBaseCol =
			columnModel.getColumn(RegionMapTableColumns.DYNAMIC_BASE.ordinal());
		dynBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn chooseCol = columnModel.getColumn(RegionMapTableColumns.CHOOSE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, chooseCol, DebuggerResources.ICON_PROGRAM,
			BUTTON_SIZE, this::chooseAndSetBlock);

		TableColumn stBaseCol = columnModel.getColumn(RegionMapTableColumns.STATIC_BASE.ordinal());
		stBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn sizeCol = columnModel.getColumn(RegionMapTableColumns.SIZE.ordinal());
		sizeCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	private void chooseAndSetBlock(RegionMapEntry entry) {
		Map.Entry<Program, MemoryBlock> choice =
			provider.askBlock(entry.getRegion(), entry.getToProgram(), entry.getBlock());
		if (choice == null) {
			return;
		}

		Swing.runIfSwingOrRunLater(() -> {
			entry.setBlock(choice.getKey(), choice.getValue());
			tableModel.notifyUpdated(entry);
		});
	}
}
