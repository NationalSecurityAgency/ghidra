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
import java.io.File;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import com.google.common.collect.Range;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.TableFilter;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.service.modules.MapModulesBackgroundCommand;
import ghidra.app.plugin.core.debug.service.modules.MapSectionsBackgroundCommand;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerStaticMappingService.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.modules.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.database.ObjectKey;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerModulesProvider extends ComponentProviderAdapter {
	protected enum ModuleTableColumns
		implements EnumeratedTableColumn<ModuleTableColumns, ModuleRow> {
		BASE("Base Address", Address.class, ModuleRow::getBase),
		MAX("Max Address", Address.class, ModuleRow::getMaxAddress),
		SHORT_NAME("Name", String.class, ModuleRow::getShortName),
		NAME("Module Name", String.class, ModuleRow::getName, ModuleRow::setName),
		LIFESPAN("Lifespan", Range.class, ModuleRow::getLifespan),
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

	protected static ModuleRow getSelectedModuleRow(ActionContext context) {
		if (!(context instanceof DebuggerModuleActionContext)) {
			return null;
		}
		DebuggerModuleActionContext ctx = (DebuggerModuleActionContext) context;
		Set<ModuleRow> modules = ctx.getSelectedModules();
		if (modules.size() != 1) {
			return null;
		}
		return modules.iterator().next();
	}

	protected static SectionRow getSelectedSectionRow(ActionContext context) {
		if (!(context instanceof DebuggerSectionActionContext)) {
			return null;
		}
		DebuggerSectionActionContext ctx = (DebuggerSectionActionContext) context;
		Set<SectionRow> sections = ctx.getSelectedSections();
		if (sections.size() != 1) {
			return null;
		}
		return sections.iterator().next();
	}

	protected static class ModuleTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					ModuleTableColumns, ObjectKey, ModuleRow, TraceModule> {

		public ModuleTableModel() {
			super("Modules", ModuleTableColumns.class, TraceModule::getObjectKey, ModuleRow::new);
		}
	}

	protected static class SectionTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					SectionTableColumns, ObjectKey, SectionRow, TraceSection> {

		public SectionTableModel() {
			super("Sections", SectionTableColumns.class, TraceSection::getObjectKey,
				SectionRow::new);
		}
	}

	protected static Set<TraceModule> getSelectedModules(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext) {
			DebuggerModuleActionContext ctx = (DebuggerModuleActionContext) context;
			return ctx.getSelectedModules()
					.stream()
					.map(r -> r.getModule())
					.collect(Collectors.toSet());
		}
		if (context instanceof DebuggerSectionActionContext) {
			DebuggerSectionActionContext ctx = (DebuggerSectionActionContext) context;
			return ctx.getSelectedSections()
					.stream()
					.map(r -> r.getModule())
					.collect(Collectors.toSet());
		}
		return null;
	}

	protected static Set<TraceSection> getSelectedSections(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext) {
			DebuggerModuleActionContext ctx = (DebuggerModuleActionContext) context;
			return ctx.getSelectedModules()
					.stream()
					.flatMap(r -> r.getModule().getSections().stream())
					.collect(Collectors.toSet());
		}
		if (context instanceof DebuggerSectionActionContext) {
			DebuggerSectionActionContext ctx = (DebuggerSectionActionContext) context;
			return ctx.getSelectedSections()
					.stream()
					.map(r -> r.getSection())
					.collect(Collectors.toSet());
		}
		return null;
	}

	private class ModulesListener extends TraceDomainObjectListener {
		public ModulesListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceModuleChangeType.ADDED, this::moduleAdded);
			listenFor(TraceModuleChangeType.CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.LIFESPAN_CHANGED, this::moduleChanged);
			listenFor(TraceModuleChangeType.DELETED, this::moduleDeleted);

			listenFor(TraceSectionChangeType.ADDED, this::sectionAdded);
			listenFor(TraceSectionChangeType.CHANGED, this::sectionChanged);
			listenFor(TraceSectionChangeType.DELETED, this::sectionDeleted);
		}

		private void objectRestored() {
			loadModules();
		}

		private void moduleAdded(TraceModule module) {
			moduleTableModel.addItem(module);
			/**
			 * NOTE: No need to add sections here. A TraceModule is created empty, so when each
			 * section is added, we'll get the call.
			 */
		}

		private void moduleChanged(TraceModule module) {
			moduleTableModel.updateItem(module);
			sectionTableModel.fireTableDataChanged(); // Because module name in section row
		}

		private void moduleDeleted(TraceModule module) {
			moduleTableModel.deleteItem(module);
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

	protected class RecordersChangedListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder element) {
			contextChanged();
		}

		@Override
		public void elementRemoved(TraceRecorder element) {
			contextChanged();
		}

		@Override
		public void elementModified(TraceRecorder element) {
			contextChanged();
		}
	}

	protected class SelectAddressesAction extends AbstractSelectAddressesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public SelectAddressesAction() {
			super(plugin);
			setDescription("Select addresses contained in modules or sections");
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (listingService == null) {
				return;
			}
			Set<TraceSection> sections = getSelectedSections(myActionContext);
			if (sections == null) {
				return;
			}
			AddressSet sel = new AddressSet();
			for (TraceSection s : sections) {
				sel.add(s.getRange());
			}
			ProgramSelection ps = new ProgramSelection(sel);
			listingService.setCurrentSelection(ps);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isContextNonEmpty(context);
		}
	}

	protected class CaptureTypesAction extends AbstractCaptureTypesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public CaptureTypesAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			// TODO: Until we support this in an agent, hide it
			//addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<TraceModule> modules = getSelectedModules(myActionContext);
			if (modules == null) {
				return;
			}
			TraceRecorder recorder = modelService.getRecorder(currentTrace);
			BackgroundUtils.async(tool, currentTrace, "Capture Types", true, true, false,
				(__, monitor) -> AsyncUtils.each(TypeSpec.VOID, modules.iterator(), (m, loop) -> {
					if (recorder.getTargetModule(m) == null) {
						loop.repeatWhile(!monitor.isCancelled());
					}
					else {
						recorder.captureDataTypes(m, monitor)
								.thenApply(v -> !monitor.isCancelled())
								.handle(loop::repeatWhile);
					}
				}));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isCaptureApplicable(myActionContext);
		}
	}

	protected class CaptureSymbolsAction extends AbstractCaptureSymbolsAction {
		public static final String GROUP = DebuggerResources.GROUP_MAINTENANCE;

		public CaptureSymbolsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<TraceModule> modules = getSelectedModules(myActionContext);
			if (modules == null) {
				return;
			}
			TraceRecorder recorder = modelService.getRecorder(currentTrace);
			BackgroundUtils.async(tool, currentTrace, NAME, true, true, false,
				(__, monitor) -> AsyncUtils.each(TypeSpec.VOID, modules.iterator(), (m, loop) -> {
					if (recorder.getTargetModule(m) == null) {
						loop.repeatWhile(!monitor.isCancelled());
					}
					else {
						recorder.captureSymbols(m, monitor)
								.thenApply(v -> !monitor.isCancelled())
								.handle(loop::repeatWhile);
					}
				}));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isCaptureApplicable(myActionContext);
		}
	}

	protected class ImportFromFileSystemAction extends AbstractImportFromFileSystemAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public ImportFromFileSystemAction() {
			super(plugin);
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (importerService == null) {
				return;
			}
			Set<TraceModule> modules = getSelectedModules(myActionContext);
			if (modules == null || modules.size() != 1) {
				return;
			}
			TraceModule mod = modules.iterator().next();
			importModuleFromFileSystem(mod);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Set<TraceModule> sel = getSelectedModules(myActionContext);
			return importerService != null && sel != null && sel.size() == 1;
		}
	}

	class SectionsBySelectedModulesTableFilter implements TableFilter<SectionRow> {
		@Override
		public boolean acceptsRow(SectionRow sectionRow) {
			List<ModuleRow> selModuleRows = moduleFilterPanel.getSelectedItems();
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

	private final DebuggerModulesPlugin plugin;

	// @AutoServiceConsumed via method
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	ProgramManager programManager;
	@AutoServiceConsumed
	private GoToService goToService;
	@AutoServiceConsumed
	private FileImporterService importerService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	Trace currentTrace;

	private final ModulesListener modulesListener = new ModulesListener();

	private final RecordersChangedListener recordersChangedListener =
		new RecordersChangedListener();

	protected final ModuleTableModel moduleTableModel = new ModuleTableModel();
	protected GhidraTable moduleTable;
	private GhidraTableFilterPanel<ModuleRow> moduleFilterPanel;

	protected final SectionTableModel sectionTableModel = new SectionTableModel();
	protected GhidraTable sectionTable;
	protected GhidraTableFilterPanel<SectionRow> sectionFilterPanel;
	private final SectionsBySelectedModulesTableFilter filterSectionsBySelectedModules =
		new SectionsBySelectedModulesTableFilter();

	private final JSplitPane mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

	// TODO: Lazy construction of these dialogs?
	private final DebuggerBlockChooserDialog blockChooserDialog;
	private final DebuggerModuleMapProposalDialog moduleProposalDialog;
	private final DebuggerSectionMapProposalDialog sectionProposalDialog;
	private DataTreeDialog programChooserDialog; // Already lazy

	private ActionContext myActionContext;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	DockingAction actionMapModules;
	DockingAction actionMapModuleTo;
	DockingAction actionMapSections;
	DockingAction actionMapSectionTo;
	DockingAction actionMapSectionsTo;

	DockingAction actionImportMissingModule;
	DockingAction actionMapMissingModule;

	SelectAddressesAction actionSelectAddresses;
	CaptureTypesAction actionCaptureTypes;
	CaptureSymbolsAction actionCaptureSymbols;
	ImportFromFileSystemAction actionImportFromFileSystem;
	// TODO: Save the state of this toggle? Not really compelled.
	ToggleDockingAction actionFilterSectionsByModules;
	DockingAction actionSelectCurrent;

	public DebuggerModulesProvider(final DebuggerModulesPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_MODULES, plugin.getName(), null);
		this.plugin = plugin;

		setIcon(DebuggerResources.ICON_PROVIDER_MODULES);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_MODULES);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		blockChooserDialog = new DebuggerBlockChooserDialog();
		moduleProposalDialog = new DebuggerModuleMapProposalDialog(this);
		sectionProposalDialog = new DebuggerSectionMapProposalDialog(this);

		setDefaultWindowPosition(WindowPosition.LEFT);
		setVisible(true);
		createActions();
	}

	private void importModuleFromFileSystem(TraceModule module) {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setSelectedFile(new File(module.getName()));
		File file = chooser.getSelectedFile();
		if (file == null) { // Perhaps cancelled
			return;
		}
		Project activeProject = Objects.requireNonNull(AppInfo.getActiveProject());
		DomainFolder root = activeProject.getProjectData().getRootFolder();
		importerService.importFile(root, file);
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeTraceRecordersChangedListener(recordersChangedListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addTraceRecordersChangedListener(recordersChangedListener);
		}
		contextChanged();
	}

	@AutoServiceConsumed
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionImportMissingModule != null) {
				consoleService.addResolutionAction(actionImportMissingModule);
			}
			if (actionMapMissingModule != null) {
				consoleService.addResolutionAction(actionMapMissingModule);
			}
		}
	}

	protected void dispose() {
		if (consoleService != null) {
			if (actionImportMissingModule != null) {
				consoleService.removeResolutionAction(actionImportMissingModule);
			}
			if (actionMapMissingModule != null) {
				consoleService.removeResolutionAction(actionMapMissingModule);
			}
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	private void loadModules() {
		moduleTableModel.clear();
		sectionTableModel.clear();

		if (currentTrace == null) {
			return;
		}

		TraceModuleManager moduleManager = currentTrace.getModuleManager();
		moduleTableModel.addAllItems(moduleManager.getAllModules());
		sectionTableModel.addAllItems(moduleManager.getAllSections());
	}

	protected void buildMainPanel() {
		mainPanel.setContinuousLayout(true);

		JPanel modulePanel = new JPanel(new BorderLayout());
		moduleTable = new GhidraTable(moduleTableModel);
		moduleTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		modulePanel.add(new JScrollPane(moduleTable));
		moduleFilterPanel = new GhidraTableFilterPanel<>(moduleTable, moduleTableModel);
		modulePanel.add(moduleFilterPanel, BorderLayout.SOUTH);
		mainPanel.setLeftComponent(modulePanel);

		JPanel sectionPanel = new JPanel(new BorderLayout());
		sectionTable = new GhidraTable(sectionTableModel);
		sectionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		sectionPanel.add(new JScrollPane(sectionTable));
		sectionFilterPanel = new GhidraTableFilterPanel<>(sectionTable, sectionTableModel);
		sectionPanel.add(sectionFilterPanel, BorderLayout.SOUTH);
		mainPanel.setRightComponent(sectionPanel);

		mainPanel.setResizeWeight(0.5);

		moduleTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerModuleActionContext(this,
				moduleFilterPanel.getSelectedItems(), moduleTable);
			contextChanged();
			if (actionFilterSectionsByModules.isSelected()) {
				sectionTableModel.fireTableDataChanged();
			}
		});
		moduleTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedModule();
				}
			}
		});
		sectionTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerSectionActionContext(this,
				sectionFilterPanel.getSelectedItems(), sectionTable);
			contextChanged();
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
				}
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel modColModel = moduleTable.getColumnModel();

		TableColumn baseCol = modColModel.getColumn(ModuleTableColumns.BASE.ordinal());
		baseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn maxCol = modColModel.getColumn(ModuleTableColumns.MAX.ordinal());
		maxCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn mLenCol = modColModel.getColumn(ModuleTableColumns.LENGTH.ordinal());
		mLenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);

		TableColumnModel secColModel = sectionTable.getColumnModel();
		TableColumn startCol = secColModel.getColumn(SectionTableColumns.START.ordinal());
		startCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn endCol = secColModel.getColumn(SectionTableColumns.END.ordinal());
		endCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn sLenCol = secColModel.getColumn(SectionTableColumns.LENGTH.ordinal());
		sLenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	protected void navigateToSelectedModule() {
		if (listingService != null) {
			int selectedRow = moduleTable.getSelectedRow();
			int selectedColumn = moduleTable.getSelectedColumn();
			Object value = moduleTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				listingService.goTo((Address) value, true);
			}
		}
	}

	protected void navigateToSelectedSection() {
		if (listingService != null) {
			int selectedRow = sectionTable.getSelectedRow();
			int selectedColumn = sectionTable.getSelectedColumn();
			Object value = sectionTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				listingService.goTo((Address) value, true);
			}
		}
	}

	protected void createActions() {
		actionMapModules = MapModulesAction.builder(plugin)
				.enabledWhen(this::isContextNonEmpty)
				.popupWhen(this::isContextNonEmpty)
				.onAction(this::activatedMapModules)
				.buildAndInstallLocal(this);
		actionMapModuleTo = MapModuleToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null)
				.withContext(DebuggerModuleActionContext.class)
				.popupWhen(ctx -> currentProgram != null && ctx.getSelectedModules().size() == 1)
				.onAction(this::activatedMapModuleTo)
				.buildAndInstallLocal(this);
		actionMapSections = MapSectionsAction.builder(plugin)
				.enabledWhen(this::isContextNonEmpty)
				.popupWhen(this::isContextNonEmpty)
				.onAction(this::activatedMapSections)
				.buildAndInstallLocal(this);
		actionMapSectionTo = MapSectionToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null)
				.withContext(DebuggerSectionActionContext.class)
				.popupWhen(ctx -> currentProgram != null && ctx.getSelectedSections().size() == 1)
				.onAction(this::activatedMapSectionTo)
				.buildAndInstallLocal(this);
		actionMapSectionsTo = MapSectionsToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null)
				.popupWhen(ctx -> currentProgram != null && isContextSectionsOfOneModule(ctx))
				.onAction(this::activatedMapSectionsTo)
				.buildAndInstallLocal(this);

		actionImportMissingModule = ImportMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedImportMissingModule)
				.build();
		actionMapMissingModule = MapMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedMapMissingModule)
				.build();

		actionSelectAddresses = new SelectAddressesAction();
		actionCaptureTypes = new CaptureTypesAction();
		actionCaptureSymbols = new CaptureSymbolsAction();
		actionImportFromFileSystem = new ImportFromFileSystemAction();
		actionFilterSectionsByModules = FilterAction.builder(plugin)
				.description("Filter sections to those in selected modules")
				.helpLocation(new HelpLocation(plugin.getName(), "filter_by_module"))
				.onAction(this::toggledFilter)
				.buildAndInstallLocal(this);
		actionSelectCurrent = SelectRowsAction.builder(plugin)
				.enabledWhen(ctx -> currentTrace != null)
				.description("Select modules and sections by trace selection")
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);

		contextChanged();
	}

	private boolean isContextNonEmpty(ActionContext ignored) {
		if (myActionContext instanceof DebuggerModuleActionContext) {
			DebuggerModuleActionContext ctx = (DebuggerModuleActionContext) myActionContext;
			return !ctx.getSelectedModules().isEmpty();
		}
		if (myActionContext instanceof DebuggerSectionActionContext) {
			DebuggerSectionActionContext ctx = (DebuggerSectionActionContext) myActionContext;
			return !ctx.getSelectedSections().isEmpty();
		}
		return false;
	}

	private boolean isContextSectionsOfOneModule(ActionContext ignored) {
		Set<TraceSection> sel = getSelectedSections(myActionContext);
		if (sel == null || sel.isEmpty()) {
			return false;
		}
		return sel.stream().map(TraceSection::getModule).distinct().count() == 1;
	}

	private void activatedMapModules(ActionContext ignored) {
		Set<TraceModule> sel = getSelectedModules(myActionContext);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapModules(sel);
	}

	private void activatedMapModuleTo(ActionContext ignored) {
		Set<TraceModule> sel = getSelectedModules(myActionContext);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapModuleTo(sel.iterator().next());
	}

	private void activatedMapSections(ActionContext ignored) {
		Set<TraceSection> sel = getSelectedSections(myActionContext);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSections(sel);
	}

	private void activatedMapSectionsTo(ActionContext ignored) {
		Set<TraceSection> sel = getSelectedSections(myActionContext);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSectionsTo(sel);
	}

	private void activatedMapSectionTo(ActionContext ignored) {
		Set<TraceSection> sel = getSelectedSections(myActionContext);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapSectionTo(sel.iterator().next());
	}

	private void activatedImportMissingModule(DebuggerMissingModuleActionContext context) {
		if (importerService == null) {
			Msg.error(this, "Import service is not present");
		}
		importModuleFromFileSystem(context.getModule());
		consoleService.removeFromLog(context); // TODO: Should remove when mapping is created
	}

	private void activatedMapMissingModule(DebuggerMissingModuleActionContext context) {
		mapModuleTo(context.getModule());
		consoleService.removeFromLog(context); // TODO: Should remove when mapping is created
	}

	private void toggledFilter(ActionContext ignored) {
		if (actionFilterSectionsByModules.isSelected()) {
			sectionFilterPanel.setSecondaryFilter(filterSectionsBySelectedModules);
		}
		else {
			sectionFilterPanel.setSecondaryFilter(null);
		}
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || currentTrace == null) {
			return;
		}

		ProgramSelection progSel = listingService.getCurrentSelection();
		TraceModuleManager moduleManager = currentTrace.getModuleManager();
		if (progSel != null && !progSel.isEmpty()) {
			long snap = traceManager.getCurrentSnap();
			Set<TraceModule> modSel = new HashSet<>();
			Set<TraceSection> sectionSel = new HashSet<>();
			for (AddressRange range : progSel) {
				for (TraceModule module : moduleManager
						.getModulesIntersecting(Range.singleton(snap), range)) {
					if (module.getSections().isEmpty()) {
						modSel.add(module);
					}
				}
				for (TraceSection section : moduleManager
						.getSectionsIntersecting(Range.singleton(snap), range)) {
					sectionSel.add(section);
					modSel.add(section.getModule());
				}
			}
			setSelectedModules(modSel);
			setSelectedSections(sectionSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			Address address = progLoc.getAddress();
			Set<TraceSection> sectionsAt =
				Set.copyOf(moduleManager.getSectionsAt(traceManager.getCurrentSnap(), address));
			if (!sectionsAt.isEmpty()) {
				Set<TraceModule> modulesAt =
					sectionsAt.stream().map(TraceSection::getModule).collect(Collectors.toSet());
				setSelectedModules(modulesAt);
				setSelectedSections(sectionsAt);
				return;
			}
			TraceModule bestModule = null;
			for (TraceModule module : moduleManager
					.getLoadedModules(traceManager.getCurrentSnap())) {
				Address base = module.getBase();
				if (base == null || base.getAddressSpace() != address.getAddressSpace()) {
					continue;
				}
				if (bestModule == null) {
					bestModule = module;
					continue;
				}
				if (base.compareTo(address) > 0) {
					continue;
				}
				if (base.compareTo(bestModule.getBase()) <= 0) {
					continue;
				}
				bestModule = module;
			}
			if (bestModule.getSections().isEmpty()) {
				setSelectedModules(Set.of(bestModule));
				return;
			}
		}
	}

	private boolean isCaptureApplicable(ActionContext context) {
		if (modelService == null) {
			return false;
		}
		if (!(context instanceof DebuggerModuleActionContext)) {
			return false;
		}
		DebuggerModuleActionContext ctx = (DebuggerModuleActionContext) context;
		if (ctx.getSelectedModules().isEmpty()) {
			return false;
		}
		if (currentTrace == null) {
			return false;
		}
		TraceRecorder recorder = modelService.getRecorder(currentTrace);
		if (recorder == null) {
			return false;
		}
		return true;
	}

	protected void promptModuleProposal(Collection<ModuleMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Modules",
				"Could not formulate a proposal for any selected module." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<ModuleMapEntry> adjusted =
			moduleProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapModulesBackgroundCommand(staticMappingService, adjusted), currentTrace);
	}

	protected void mapModules(Set<TraceModule> modules) {
		if (staticMappingService == null) {
			return;
		}
		Map<TraceModule, ModuleMapProposal> map = staticMappingService.proposeModuleMaps(modules,
			List.of(programManager.getAllOpenPrograms()));
		Collection<ModuleMapEntry> proposal = ModuleMapProposal.flatten(map.values());
		promptModuleProposal(proposal);
	}

	protected void mapModuleTo(TraceModule module) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		ModuleMapProposal proposal = staticMappingService.proposeModuleMap(module, program);
		Map<TraceModule, ModuleMapEntry> map = proposal.computeMap();
		promptModuleProposal(map.values());
	}

	protected void promptSectionProposal(Collection<SectionMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Sections",
				"Could not formulate a proposal for any selected section." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<SectionMapEntry> adjusted =
			sectionProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapSectionsBackgroundCommand(staticMappingService, adjusted), currentTrace);
	}

	protected void mapSections(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		Map<TraceModule, SectionMapProposal> map = staticMappingService.proposeSectionMaps(modules,
			List.of(programManager.getAllOpenPrograms()));
		Collection<SectionMapEntry> proposal = SectionMapProposal.flatten(map.values());
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionsTo(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		if (modules.size() != 1) {
			return;
		}
		TraceModule module = modules.iterator().next();
		SectionMapProposal map = staticMappingService.proposeSectionMap(module, program);
		Collection<SectionMapEntry> proposal = map.computeMap().values();
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionTo(TraceSection section) {
		if (staticMappingService == null) {
			return;
		}
		ProgramLocation location = currentLocation;
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return;
		}
		promptSectionProposal(List.of(new SectionMapEntry(section, location.getProgram(), block)));
	}

	protected Set<MemoryBlock> collectBlocksInOpenPrograms() {
		Set<MemoryBlock> result = new HashSet<>();
		for (Program p : programManager.getAllOpenPrograms()) {
			if (p instanceof Trace) {
				continue;
			}
			result.addAll(List.of(p.getMemory().getBlocks()));
		}
		return result;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setProgram(Program program) {
		currentProgram = program;
		String name = (program == null ? "..." : program.getName());
		actionMapModuleTo.getPopupMenuData().setMenuItemName(MapModuleToAction.NAME_PREFIX + name);
		actionMapSectionsTo.getPopupMenuData()
				.setMenuItemName(MapSectionsToAction.NAME_PREFIX + name);
	}

	public static MemoryBlock computeBlock(ProgramLocation location) {
		if (location == null) {
			return null;
		}
		Program program = location.getProgram();
		if (program == null) {
			return null;
		}
		Address addr = location.getAddress();
		if (addr == null) {
			return null;
		}
		return program.getMemory().getBlock(addr);
	}

	public static String computeBlockName(ProgramLocation location) {
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return "...";
		}
		return location.getProgram().getName() + ":" + block.getName();
	}

	public void setLocation(ProgramLocation location) {
		currentLocation = location;
		String name = MapSectionToAction.NAME_PREFIX + computeBlockName(location);
		actionMapSectionTo.getPopupMenuData().setMenuItemName(name);
	}

	public void programClosed(Program program) {
		if (currentProgram == program) {
			currentProgram = null;
		}
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

	public void setSelectedSections(Set<TraceSection> sel) {
		DebuggerResources.setSelectedRows(sel, sectionTableModel::getRow, sectionTable,
			sectionTableModel, sectionFilterPanel);
	}

	private DataTreeDialog getProgramChooserDialog() {
		if (programChooserDialog != null) {
			return programChooserDialog;
		}
		DomainFileFilter filter = df -> Program.class.isAssignableFrom(df.getDomainObjectClass());
		return programChooserDialog =
			new DataTreeDialog(null, "Map Module to Program", DataTreeDialog.OPEN, filter) {
				{ // TODO/HACK: I get an NPE setting the default selection if I don't fake this.
					dialogShown();
				}
			};
	}

	public DomainFile askProgram(Program program) {
		getProgramChooserDialog();
		if (program != null) {
			programChooserDialog.selectDomainFile(program.getDomainFile());
		}
		tool.showDialog(programChooserDialog);
		return programChooserDialog.getDomainFile();
	}

	public Entry<Program, MemoryBlock> askBlock(TraceSection section, Program program,
			MemoryBlock block) {
		if (programManager == null) {
			Msg.warn(this, "No program manager!");
			return null;
		}
		return blockChooserDialog.chooseBlock(getTool(), section,
			List.of(programManager.getAllOpenPrograms()));
	}
}
