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
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.MapModulesAction;
import ghidra.app.services.DebuggerStaticMappingService.ModuleMapEntry;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;

public class DebuggerModuleMapProposalDialog
		extends AbstractDebuggerMapProposalDialog<ModuleMapEntry> {

	static final int BUTTON_SIZE = 32;

	protected enum ModuleMapTableColumns
		implements EnumeratedTableColumn<ModuleMapTableColumns, ModuleMapEntry> {
		REMOVE("Remove", String.class, e -> "Remove Proposed Entry", (e, v) -> nop()),
		MODULE_NAME("Module", String.class, e -> e.getModule().getName()),
		DYNAMIC_BASE("Dynamic Base", Address.class, e -> e.getModule().getBase()),
		CHOOSE("Choose", String.class, e -> "Choose Program", (e, v) -> nop()),
		PROGRAM_NAME("Program", String.class, e -> e.getProgram().getName()),
		STATIC_BASE("Static Base", Address.class, e -> e.getProgram().getImageBase()),
		SIZE("Size", Long.class, e -> e.getModuleRange().getLength());

		private final String header;
		private final Class<?> cls;
		private final Function<ModuleMapEntry, ?> getter;
		private final BiConsumer<ModuleMapEntry, Object> setter;

		private static void nop() {
		}

		@SuppressWarnings("unchecked")
		<T> ModuleMapTableColumns(String header, Class<T> cls, Function<ModuleMapEntry, T> getter,
				BiConsumer<ModuleMapEntry, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<ModuleMapEntry, Object>) setter;
		}

		<T> ModuleMapTableColumns(String header, Class<T> cls, Function<ModuleMapEntry, T> getter) {
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
		public Object getValueOf(ModuleMapEntry row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(ModuleMapEntry row) {
			return setter != null;
		}

		@Override
		public void setValueOf(ModuleMapEntry row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class ModuleMapPropsalTableModel extends
			DefaultEnumeratedColumnTableModel<ModuleMapTableColumns, ModuleMapEntry> {

		public ModuleMapPropsalTableModel() {
			super("Module Map", ModuleMapTableColumns.class);
		}

		@Override
		public List<ModuleMapTableColumns> defaultSortOrder() {
			return List.of(ModuleMapTableColumns.MODULE_NAME);
		}
	}

	private final DebuggerModulesProvider provider;

	protected DebuggerModuleMapProposalDialog(DebuggerModulesProvider provider) {
		super(MapModulesAction.NAME);
		this.provider = provider;
	}

	@Override
	protected ModuleMapPropsalTableModel createTableModel() {
		return new ModuleMapPropsalTableModel();
	}

	@Override
	protected void populateComponents() {
		super.populateComponents();
		setPreferredSize(600, 300);

		TableColumnModel columnModel = table.getColumnModel();

		TableColumn removeCol = columnModel.getColumn(ModuleMapTableColumns.REMOVE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, removeCol,
			DebuggerResources.ICON_DELETE, BUTTON_SIZE, this::removeEntry);

		TableColumn dynBaseCol =
			columnModel.getColumn(ModuleMapTableColumns.DYNAMIC_BASE.ordinal());
		dynBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn chooseCol = columnModel.getColumn(ModuleMapTableColumns.CHOOSE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, chooseCol,
			DebuggerResources.ICON_PROGRAM, BUTTON_SIZE, this::chooseAndSetProgram);

		TableColumn stBaseCol = columnModel.getColumn(ModuleMapTableColumns.STATIC_BASE.ordinal());
		stBaseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn sizeCol = columnModel.getColumn(ModuleMapTableColumns.SIZE.ordinal());
		sizeCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	private void chooseAndSetProgram(ModuleMapEntry entry) {
		DomainFile file = provider.askProgram(entry.getProgram());
		if (file == null) {
			return;
		}
		/**
		 * TODO: I don't technically need the programManager here, but then I have to worry about
		 * releasing the program. If users are mapping stuff, it's probably because they would like
		 * to sync, and thus must have a program manager, anyway.
		 */
		if (provider.programManager == null) {
			return;
		}
		Program program = provider.programManager.openProgram(file);
		Swing.runIfSwingOrRunLater(() -> {
			entry.setProgram(program);
			tableModel.notifyUpdated(entry);
		});
	}
}
