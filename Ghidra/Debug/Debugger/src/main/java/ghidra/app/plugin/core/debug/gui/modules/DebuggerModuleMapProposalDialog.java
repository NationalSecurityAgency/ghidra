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

import javax.swing.table.TableCellEditor;

import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.gui.AbstractDebuggerMapProposalDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.table.column.GColumnRenderer;

public class DebuggerModuleMapProposalDialog
		extends AbstractDebuggerMapProposalDialog<ModuleMapEntry> {

	private static final IconButtonTableCellRenderer REMOVE_BUTTON_RENDERER =
		new IconButtonTableCellRenderer(DebuggerResources.ICON_DELETE, BUTTON_SIZE);
	private static final IconButtonTableCellEditor<ModuleMapEntry> REMOVE_BUTTON_EDITOR =
		new IconButtonTableCellEditor<>(ModuleMapEntry.class, DebuggerResources.ICON_DELETE) {
			@Override
			protected void clicked() {
				if (!(model instanceof ModuleMapPropsalTableModel mapModel)) {
					return;
				}
				mapModel.dialog.removeEntry(row);
			}
		};

	private static final IconButtonTableCellRenderer CHOOSE_BUTTON_RENDERER =
		new IconButtonTableCellRenderer(DebuggerResources.ICON_PROGRAM, BUTTON_SIZE);
	private static final IconButtonTableCellEditor<ModuleMapEntry> CHOOSE_BUTTON_EDITOR =
		new IconButtonTableCellEditor<>(ModuleMapEntry.class, DebuggerResources.ICON_PROGRAM) {
			@Override
			protected void clicked() {
				if (!(model instanceof ModuleMapPropsalTableModel mapModel)) {
					return;
				}
				mapModel.dialog.chooseAndSetProgram(row);
			}
		};

	protected enum ModuleMapTableColumns
		implements EnumeratedTableColumn<ModuleMapTableColumns, ModuleMapEntry> {
		REMOVE("Remove", String.class, e -> "Remove Proposed Entry", (e, v) -> nop()) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return REMOVE_BUTTON_RENDERER;
			}

			@Override
			public TableCellEditor getEditor() {
				return REMOVE_BUTTON_EDITOR;
			}

			@Override
			public int getMaxWidth() {
				return BUTTON_SIZE;
			}

			@Override
			public int getMinWidth() {
				return BUTTON_SIZE;
			}
		},
		MODULE_NAME("Module", String.class, e -> e.getModuleName()),
		DYNAMIC_BASE("Dynamic Base", Address.class, e -> e.getFromRange().getMinAddress()) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return CustomToStringCellRenderer.MONO_OBJECT;
			}
		},
		CHOOSE("Choose", String.class, e -> "Choose Program", (e, v) -> nop()) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return CHOOSE_BUTTON_RENDERER;
			}

			@Override
			public TableCellEditor getEditor() {
				return CHOOSE_BUTTON_EDITOR;
			}

			@Override
			public int getMaxWidth() {
				return BUTTON_SIZE;
			}

			@Override
			public int getMinWidth() {
				return BUTTON_SIZE;
			}
		},
		PROGRAM_NAME("Program", String.class, e -> (e.getToProgram().getDomainFile() == null
				? e.getToProgram().getName()
				: e.getToProgram().getDomainFile().getName())),
		STATIC_BASE("Static Base", Address.class, e -> e.getToRange().getMinAddress()) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return CustomToStringCellRenderer.MONO_OBJECT;
			}
		},
		SIZE("Size", Long.class, e -> e.getFromRange().getLength()) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return CustomToStringCellRenderer.MONO_ULONG_HEX;
			}
		},
		MEMORIZE("Memorize", Boolean.class, ModuleMapEntry::isMemorize,
				ModuleMapEntry::setMemorize);

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
		protected final DebuggerModuleMapProposalDialog dialog;

		public ModuleMapPropsalTableModel(PluginTool tool, DebuggerModuleMapProposalDialog dialog) {
			super(tool, "Module Map", ModuleMapTableColumns.class);
			this.dialog = dialog;
		}

		@Override
		public List<ModuleMapTableColumns> defaultSortOrder() {
			return List.of(ModuleMapTableColumns.MODULE_NAME);
		}
	}

	private final DebuggerModulesProvider provider;

	protected DebuggerModuleMapProposalDialog(DebuggerModulesProvider provider) {
		super(provider.getTool(), DebuggerResources.NAME_MAP_MODULES);
		this.provider = provider;
	}

	@Override
	protected ModuleMapPropsalTableModel createTableModel(PluginTool tool) {
		return new ModuleMapPropsalTableModel(tool, this);
	}

	@Override
	protected void populateComponents() {
		super.populateComponents();
		setPreferredSize(600, 300);
		table.setRowHeight(BUTTON_SIZE);
	}

	private void chooseAndSetProgram(ModuleMapEntry entry) {
		DomainFile file = provider.askProgram(entry.getToProgram());
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
