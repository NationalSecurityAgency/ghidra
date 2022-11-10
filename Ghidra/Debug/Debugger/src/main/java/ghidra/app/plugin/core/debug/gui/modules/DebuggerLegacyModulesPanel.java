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

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.modules.*;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerLegacyModulesPanel extends JPanel {

	protected static Set<TraceModule> getSelectedModulesFromContext(
			DebuggerModuleActionContext context) {
		return context.getSelectedModules()
				.stream()
				.map(r -> r.getModule())
				.collect(Collectors.toSet());
	}

	protected static Set<TraceSection> getSelectedSectionsFromContext(
			DebuggerModuleActionContext context) {
		return context.getSelectedModules()
				.stream()
				.flatMap(r -> r.getModule().getSections().stream())
				.collect(Collectors.toSet());
	}

	protected static AddressSetView getSelectedAddressesFromContext(
			DebuggerModuleActionContext context) {
		AddressSet sel = new AddressSet();
		for (TraceModule module : getSelectedModulesFromContext(context)) {
			sel.add(module.getRange());
		}
		return sel;
	}

	protected static ModuleRow getSelectedModuleRowFromContext(
			DebuggerModuleActionContext context) {
		Set<ModuleRow> modules = context.getSelectedModules();
		if (modules.size() != 1) {
			return null;
		}
		return modules.iterator().next();
	}

	protected static SectionRow getSelectedSectionRowFromContext(
			DebuggerSectionActionContext context) {
		Set<SectionRow> sections = context.getSelectedSections();
		if (sections.size() != 1) {
			return null;
		}
		return sections.iterator().next();
	}

	protected enum ModuleTableColumns
		implements EnumeratedTableColumn<ModuleTableColumns, ModuleRow> {
		BASE("Base Address", Address.class, ModuleRow::getBase),
		MAX("Max Address", Address.class, ModuleRow::getMaxAddress),
		SHORT_NAME("Name", String.class, ModuleRow::getShortName),
		NAME("Module Name", String.class, ModuleRow::getName, ModuleRow::setName),
		LIFESPAN("Lifespan", Lifespan.class, ModuleRow::getLifespan),
		LENGTH("Length", Long.class, ModuleRow::getLength);

		private final String header;
		private final Function<ModuleRow, ?> getter;
		private final BiConsumer<ModuleRow, Object> setter;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> ModuleTableColumns(String header, Class<T> cls, Function<ModuleRow, T> getter,
				BiConsumer<ModuleRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<ModuleRow, Object>) setter;
		}

		<T> ModuleTableColumns(String header, Class<T> cls, Function<ModuleRow, T> getter) {
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
		public boolean isEditable(ModuleRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(ModuleRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public Object getValueOf(ModuleRow row) {
			return getter.apply(row);
		}
	}

	protected static class ModuleTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					ModuleTableColumns, ObjectKey, ModuleRow, TraceModule> {

		public ModuleTableModel(PluginTool tool) {
			super(tool, "Modules", ModuleTableColumns.class, TraceModule::getObjectKey,
				ModuleRow::new);
		}

		@Override
		public List<ModuleTableColumns> defaultSortOrder() {
			return List.of(ModuleTableColumns.BASE);
		}
	}

	private class ModulesListener extends TraceDomainObjectListener {
		public ModulesListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceModuleChangeType.ADDED, this::moduleAdded);
			listenFor(TraceModuleChangeType.CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.LIFESPAN_CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.DELETED, this::moduleDeleted);
		}

		private void objectRestored() {
			loadModules();
		}

		private void moduleAdded(TraceModule module) {
			moduleTableModel.addItem(module);
		}

		private void moduleChanged(TraceModule module) {
			moduleTableModel.updateItem(module);
		}

		private void moduleDeleted(TraceModule module) {
			moduleTableModel.deleteItem(module);
		}
	}

	private final DebuggerModulesProvider provider;

	Trace currentTrace;

	private final ModulesListener modulesListener = new ModulesListener();
	protected final ModuleTableModel moduleTableModel;
	protected final GhidraTable moduleTable;
	final GhidraTableFilterPanel<ModuleRow> moduleFilterPanel;

	private DebuggerModuleActionContext myActionContext;

	public DebuggerLegacyModulesPanel(DebuggerModulesProvider provider) {
		super(new BorderLayout());
		this.provider = provider;

		moduleTableModel = new ModuleTableModel(provider.getTool());
		moduleTable = new GhidraTable(moduleTableModel);
		moduleTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		add(new JScrollPane(moduleTable));
		moduleFilterPanel = new GhidraTableFilterPanel<>(moduleTable, moduleTableModel);
		add(moduleFilterPanel, BorderLayout.SOUTH);

		moduleTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			myActionContext = new DebuggerModuleActionContext(provider,
				moduleFilterPanel.getSelectedItems(), moduleTable);
			provider.legacyModulesPanelContextChanged();
		});
		moduleTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedModule();
				}
			}
		});
		moduleTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					navigateToSelectedModule();
					e.consume();
				}
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel colModel = moduleTable.getColumnModel();

		TableColumn baseCol = colModel.getColumn(ModuleTableColumns.BASE.ordinal());
		baseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn maxCol = colModel.getColumn(ModuleTableColumns.MAX.ordinal());
		maxCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn lenCol = colModel.getColumn(ModuleTableColumns.LENGTH.ordinal());
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	protected void contextChanged() {
		provider.contextChanged();
	}

	protected void navigateToSelectedModule() {
		if (provider.listingService != null) {
			int selectedRow = moduleTable.getSelectedRow();
			int selectedColumn = moduleTable.getSelectedColumn();
			Object value = moduleTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				provider.listingService.goTo((Address) value, true);
			}
		}
	}

	public DebuggerModuleActionContext getActionContext() {
		return myActionContext;
	}

	private void loadModules() {
		moduleTable.getSelectionModel().clearSelection();
		moduleTableModel.clear();

		if (currentTrace == null) {
			return;
		}

		TraceModuleManager moduleManager = currentTrace.getModuleManager();
		moduleTableModel.addAllItems(moduleManager.getAllModules());
	}

	public void setTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadModules();
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		setTrace(coordinates.getTrace());
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(modulesListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(modulesListener);
	}

	public void setSelectedModules(Set<TraceModule> sel) {
		DebuggerResources.setSelectedRows(sel, moduleTableModel::getRow, moduleTable,
			moduleTableModel, moduleFilterPanel);
	}
}
