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
import docking.widgets.table.TableFilter;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.modules.*;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerLegacySectionsPanel extends JPanel {

	protected static Set<TraceModule> getSelectedModulesFromContext(
			DebuggerSectionActionContext context) {
		return context.getSelectedSections()
				.stream()
				.map(r -> r.getModule())
				.collect(Collectors.toSet());
	}

	protected static Set<TraceSection> getSelectedSectionsFromContext(
			DebuggerSectionActionContext context) {
		return context.getSelectedSections()
				.stream()
				.map(r -> r.getSection())
				.collect(Collectors.toSet());
	}

	protected static AddressSetView getSelectedAddressesFromContext(
			DebuggerSectionActionContext context) {
		AddressSet sel = new AddressSet();
		for (TraceSection section : getSelectedSectionsFromContext(context)) {
			sel.add(section.getRange());
		}
		return sel;
	}

	protected enum SectionTableColumns
		implements EnumeratedTableColumn<SectionTableColumns, SectionRow> {
		START("Start Address", Address.class, SectionRow::getStart),
		END("End Address", Address.class, SectionRow::getEnd),
		NAME("Section Name", String.class, SectionRow::getName, SectionRow::setName),
		MODULE("Module Name", String.class, SectionRow::getModuleName),
		LENGTH("Length", Long.class, SectionRow::getLength);

		private final String header;
		private final Function<SectionRow, ?> getter;
		private final BiConsumer<SectionRow, Object> setter;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> SectionTableColumns(String header, Class<T> cls, Function<SectionRow, T> getter,
				BiConsumer<SectionRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<SectionRow, Object>) setter;
		}

		<T> SectionTableColumns(String header, Class<T> cls, Function<SectionRow, T> getter) {
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
		public boolean isEditable(SectionRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(SectionRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public Object getValueOf(SectionRow row) {
			return getter.apply(row);
		}
	}

	protected static class SectionTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					SectionTableColumns, ObjectKey, SectionRow, TraceSection> {

		public SectionTableModel(PluginTool tool) {
			super(tool, "Sections", SectionTableColumns.class, TraceSection::getObjectKey,
				SectionRow::new);
		}

		@Override
		public List<SectionTableColumns> defaultSortOrder() {
			return List.of(SectionTableColumns.START);
		}
	}

	private class SectionsListener extends TraceDomainObjectListener {
		public SectionsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			/**
			 * NOTE: No need for Module.ADDED here. A TraceModule is created empty, so when each
			 * section is added, we'll get the call.
			 */
			listenFor(TraceModuleChangeType.CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.LIFESPAN_CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.DELETED, this::moduleDeleted);

			listenFor(TraceSectionChangeType.ADDED, this::sectionAdded);
			listenFor(TraceSectionChangeType.CHANGED, this::sectionChanged);
			listenFor(TraceSectionChangeType.DELETED, this::sectionDeleted);
		}

		private void objectRestored() {
			loadSections();
		}

		private void moduleChanged(TraceModule module) {
			sectionTableModel.fireTableDataChanged(); // Because module name in section row
		}

		private void moduleDeleted(TraceModule module) {
			// NOTE: module.getSections() will be empty, now
			sectionTableModel.deleteAllItems(sectionTableModel.getMap()
					.values()
					.stream()
					.filter(r -> r.getModule() == module)
					.map(r -> r.getSection())
					.collect(Collectors.toList()));
		}

		private void sectionAdded(TraceSection section) {
			sectionTableModel.addItem(section);
		}

		private void sectionChanged(TraceSection section) {
			sectionTableModel.updateItem(section);
		}

		private void sectionDeleted(TraceSection section) {
			sectionTableModel.deleteItem(section);
		}
	}

	class SectionsBySelectedModulesTableFilter implements TableFilter<SectionRow> {
		@Override
		public boolean acceptsRow(SectionRow sectionRow) {
			List<ModuleRow> selModuleRows =
				provider.legacyModulesPanel.moduleFilterPanel.getSelectedItems();
			if (selModuleRows == null || selModuleRows.isEmpty()) {
				return true;
			}
			for (ModuleRow moduleRow : selModuleRows) {
				if (moduleRow.getModule() == sectionRow.getModule()) {
					return true;
				}
			}
			return false;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			return false;
		}
	}

	private final DebuggerModulesProvider provider;

	private Trace currentTrace;

	private final SectionsListener sectionsListener = new SectionsListener();
	protected final SectionTableModel sectionTableModel;
	protected final GhidraTable sectionTable;
	protected final GhidraTableFilterPanel<SectionRow> sectionFilterPanel;
	private final SectionsBySelectedModulesTableFilter filterSectionsBySelectedModules =
		new SectionsBySelectedModulesTableFilter();

	private DebuggerSectionActionContext myActionContext;

	public DebuggerLegacySectionsPanel(DebuggerModulesProvider provider) {
		super(new BorderLayout());
		this.provider = provider;

		sectionTableModel = new SectionTableModel(provider.getTool());
		sectionTable = new GhidraTable(sectionTableModel);
		sectionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		add(new JScrollPane(sectionTable));
		sectionFilterPanel = new GhidraTableFilterPanel<>(sectionTable, sectionTableModel);
		add(sectionFilterPanel, BorderLayout.SOUTH);

		sectionTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			myActionContext = new DebuggerSectionActionContext(provider,
				sectionFilterPanel.getSelectedItems(), sectionTable);
			provider.legacySectionsPanelContextChanged();
		});
		// Note, ProgramTableModel will not work here, since that would navigate the "static" view
		sectionTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedSection();
				}
			}
		});
		sectionTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					navigateToSelectedSection();
					e.consume();
				}
			}
		});

		TableColumnModel colModel = sectionTable.getColumnModel();
		TableColumn startCol = colModel.getColumn(SectionTableColumns.START.ordinal());
		startCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn endCol = colModel.getColumn(SectionTableColumns.END.ordinal());
		endCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn lenCol = colModel.getColumn(SectionTableColumns.LENGTH.ordinal());
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	protected void contextChanged() {
		provider.contextChanged();
	}

	protected void navigateToSelectedSection() {
		if (provider.listingService != null) {
			int selectedRow = sectionTable.getSelectedRow();
			int selectedColumn = sectionTable.getSelectedColumn();
			Object value = sectionTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				provider.listingService.goTo((Address) value, true);
			}
		}
	}

	public DebuggerSectionActionContext getActionContext() {
		return myActionContext;
	}

	void loadSections() {
		sectionTable.getSelectionModel().clearSelection();
		sectionTableModel.clear();

		if (currentTrace == null) {
			return;
		}

		TraceModuleManager moduleManager = currentTrace.getModuleManager();
		sectionTableModel.addAllItems(moduleManager.getAllSections());
	}

	public void setTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadSections();
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		setTrace(coordinates.getTrace());
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(sectionsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(sectionsListener);
	}

	public void setSelectedSections(Set<TraceSection> sel) {
		DebuggerResources.setSelectedRows(sel, sectionTableModel::getRow, sectionTable,
			sectionTableModel, sectionFilterPanel);
	}

	public void setFilteredBySelectedModules(boolean filtered) {
		sectionFilterPanel.setSecondaryFilter(filtered ? filterSectionsBySelectedModules : null);
	}
}
