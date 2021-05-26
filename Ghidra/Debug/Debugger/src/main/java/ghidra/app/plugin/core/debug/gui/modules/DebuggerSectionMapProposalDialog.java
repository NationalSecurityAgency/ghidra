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
package ghidra.app.plugin.core.debug.gui.modules;

import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.MapSectionsAction;
import ghidra.app.services.DebuggerStaticMappingService.SectionMapEntry;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Swing;

public class DebuggerSectionMapProposalDialog
		extends AbstractDebuggerMapProposalDialog<SectionMapEntry> {

	static final int BUTTON_SIZE = 32;

	protected enum SectionMapTableColumns
		implements EnumeratedTableColumn<SectionMapTableColumns, SectionMapEntry> {
		REMOVE("Remove", String.class, e -> "Remove Proposed Entry", (e, v) -> nop()),
		MODULE_NAME("Module", String.class, e -> e.getModule().getName()),
		SECTION_NAME("Section", String.class, e -> e.getSection().getName()),
		DYNAMIC_BASE("Dynamic Base", Address.class, e -> e.getSection().getStart()),
		CHOOSE("Choose", String.class, e -> "Choose Block", (e, s) -> nop()),
		PROGRAM_NAME("Program", String.class, e -> e.getProgram().getName()),
		BLOCK_NAME("Block", String.class, e -> e.getBlock().getName()),
		STATIC_BASE("Static Base", Address.class, e -> e.getBlock().getStart()),
		SIZE("Size", Long.class, e -> e.getLength());

		private final String header;
		private final Class<?> cls;
		private final Function<SectionMapEntry, ?> getter;
		private final BiConsumer<SectionMapEntry, Object> setter;

		private static void nop() {
		}

		@SuppressWarnings("unchecked")
		<T> SectionMapTableColumns(String header, Class<T> cls, Function<SectionMapEntry, T> getter,
				BiConsumer<SectionMapEntry, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<SectionMapEntry, Object>) setter;
		}

		<T> SectionMapTableColumns(String header, Class<T> cls,
				Function<SectionMapEntry, T> getter) {
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
		public Object getValueOf(SectionMapEntry row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(SectionMapEntry row) {
			return setter != null;
		}

		@Override
		public void setValueOf(SectionMapEntry row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class SectionMapPropsalTableModel extends
			DefaultEnumeratedColumnTableModel<SectionMapTableColumns, SectionMapEntry> {

		public SectionMapPropsalTableModel() {
			super("Section Map", SectionMapTableColumns.class);
		}

		@Override
		public List<SectionMapTableColumns> defaultSortOrder() {
			return List.of(SectionMapTableColumns.MODULE_NAME, SectionMapTableColumns.SECTION_NAME);
		}
	}

	private final DebuggerModulesProvider provider;

	public DebuggerSectionMapProposalDialog(DebuggerModulesProvider provider) {
		super(MapSectionsAction.NAME);
		this.provider = provider;
	}

	@Override
	protected SectionMapPropsalTableModel createTableModel() {
		return new SectionMapPropsalTableModel();
	}

	@Override
	protected void populateComponents() {
		super.populateComponents();
		setPreferredSize(600, 300);

		TableColumnModel columnModel = table.getColumnModel();

		TableColumn removeCol = columnModel.getColumn(SectionMapTableColumns.REMOVE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, removeCol,
			DebuggerResources.ICON_DELETE, BUTTON_SIZE, this::removeEntry);

		TableColumn dynBaseCol =
			columnModel.getColumn(SectionMapTableColumns.DYNAMIC_BASE.ordinal());
		dynBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn chooseCol = columnModel.getColumn(SectionMapTableColumns.CHOOSE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, chooseCol, DebuggerResources.ICON_PROGRAM,
			BUTTON_SIZE, this::chooseAndSetBlock);

		TableColumn stBaseCol = columnModel.getColumn(SectionMapTableColumns.STATIC_BASE.ordinal());
		stBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn sizeCol = columnModel.getColumn(SectionMapTableColumns.SIZE.ordinal());
		sizeCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	private void chooseAndSetBlock(SectionMapEntry entry) {
		Map.Entry<Program, MemoryBlock> choice =
			provider.askBlock(entry.getSection(), entry.getProgram(), entry.getBlock());
		if (choice == null) {
			return;
		}

		Swing.runIfSwingOrRunLater(() -> {
			entry.setBlock(choice.getKey(), choice.getValue());
			tableModel.notifyUpdated(entry);
		});
	}
}
