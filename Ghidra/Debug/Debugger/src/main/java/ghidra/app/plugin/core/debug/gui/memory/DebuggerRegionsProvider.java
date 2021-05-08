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

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.*;
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
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.SelectRowsAction;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryRegionChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerRegionsProvider extends ComponentProviderAdapter {

	protected enum RegionTableColumns
		implements EnumeratedTableColumn<RegionTableColumns, RegionRow> {
		NAME("Name", String.class, RegionRow::getName, RegionRow::setName),
		LIFESPAN("Lifespan", Range.class, RegionRow::getLifespan),
		START("Start", Address.class, RegionRow::getMinAddress),
		END("End", Address.class, RegionRow::getMaxAddress),
		LENGTH("Length", Long.class, RegionRow::getLength),
		READ("Read", Boolean.class, RegionRow::isRead, RegionRow::setRead),
		WRITE("Write", Boolean.class, RegionRow::isWrite, RegionRow::setWrite),
		EXECUTE("Execute", Boolean.class, RegionRow::isExecute, RegionRow::setExecute),
		VOLATILE("Volatile", Boolean.class, RegionRow::isVolatile, RegionRow::setVolatile);

		private final String header;
		private final Function<RegionRow, ?> getter;
		private final BiConsumer<RegionRow, Object> setter;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> RegionTableColumns(String header, Class<T> cls, Function<RegionRow, T> getter,
				BiConsumer<RegionRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<RegionRow, Object>) setter;
		}

		<T> RegionTableColumns(String header, Class<T> cls, Function<RegionRow, T> getter) {
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
		public boolean isEditable(RegionRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(RegionRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public Object getValueOf(RegionRow row) {
			return getter.apply(row);
		}
	}

	protected static class RegionTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					RegionTableColumns, ObjectKey, RegionRow, TraceMemoryRegion> {

		public RegionTableModel() {
			super("Regions", RegionTableColumns.class, TraceMemoryRegion::getObjectKey,
				RegionRow::new);
		}
	}

	protected static RegionRow getSelectedRegionRow(ActionContext context) {
		if (!(context instanceof DebuggerRegionActionContext)) {
			return null;
		}
		DebuggerRegionActionContext ctx = (DebuggerRegionActionContext) context;
		Set<RegionRow> regions = ctx.getSelectedRegions();
		if (regions.size() != 1) {
			return null;
		}
		return regions.iterator().next();
	}

	protected static Set<TraceMemoryRegion> getSelectedRegions(ActionContext context) {
		if (!(context instanceof DebuggerRegionActionContext)) {
			return null;
		}
		DebuggerRegionActionContext ctx = (DebuggerRegionActionContext) context;
		return ctx.getSelectedRegions()
				.stream()
				.map(r -> r.getRegion())
				.collect(Collectors.toSet());
	}

	private class RegionsListener extends TraceDomainObjectListener {
		public RegionsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceMemoryRegionChangeType.ADDED, this::regionAdded);
			listenFor(TraceMemoryRegionChangeType.CHANGED, this::regionChanged);
			listenFor(TraceMemoryRegionChangeType.LIFESPAN_CHANGED, this::regionChanged);
			listenFor(TraceMemoryRegionChangeType.DELETED, this::regionDeleted);
		}

		private void objectRestored() {
			loadRegions();
		}

		private void regionAdded(TraceMemoryRegion region) {
			regionTableModel.addItem(region);
		}

		private void regionChanged(TraceMemoryRegion region) {
			regionTableModel.updateItem(region);
		}

		private void regionDeleted(TraceMemoryRegion region) {
			regionTableModel.deleteItem(region);
		}
	}

	protected class SelectAddressesAction extends AbstractSelectAddressesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public SelectAddressesAction() {
			super(plugin);
			setDescription("Select addresses contained in regions");
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
			Set<TraceMemoryRegion> regions = getSelectedRegions(myActionContext);
			if (regions == null) {
				return;
			}
			AddressSet sel = new AddressSet();
			for (TraceMemoryRegion s : regions) {
				sel.add(s.getRange());
			}
			ProgramSelection ps = new ProgramSelection(sel);
			listingService.setCurrentSelection(ps);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Set<TraceMemoryRegion> sel = getSelectedRegions(myActionContext);
			return sel != null && !sel.isEmpty();
		}
	}

	private final DebuggerRegionsPlugin plugin;

	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private Trace currentTrace;

	private final RegionsListener regionsListener = new RegionsListener();

	protected final RegionTableModel regionTableModel = new RegionTableModel();
	protected GhidraTable regionTable;
	private GhidraTableFilterPanel<RegionRow> regionFilterPanel;

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerRegionActionContext myActionContext;

	SelectAddressesAction actionSelectAddresses;
	DockingAction actionSelectRows;

	public DebuggerRegionsProvider(DebuggerRegionsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_REGIONS, plugin.getName(),
			DebuggerRegionActionContext.class);
		this.plugin = plugin;

		setIcon(DebuggerResources.ICON_PROVIDER_REGIONS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_REGIONS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		createActions();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	private void loadRegions() {
		regionTableModel.clear();

		if (currentTrace == null) {
			return;
		}
		TraceMemoryManager memoryManager = currentTrace.getMemoryManager();
		regionTableModel.addAllItems(memoryManager.getAllRegions());
	}

	protected void buildMainPanel() {
		regionTable = new GhidraTable(regionTableModel);
		regionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		mainPanel.add(new JScrollPane(regionTable));
		regionFilterPanel = new GhidraTableFilterPanel<>(regionTable, regionTableModel);
		mainPanel.add(regionFilterPanel, BorderLayout.SOUTH);

		regionTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerRegionActionContext(this,
				regionFilterPanel.getSelectedItems(), regionTable);
			contextChanged();
		});
		// Note, ProgramTableModel will not work here, since that would navigate the "static" view
		regionTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedRegion();
				}
			}
		});
		regionTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					navigateToSelectedRegion();
				}
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel columnModel = regionTable.getColumnModel();

		TableColumn startCol = columnModel.getColumn(RegionTableColumns.START.ordinal());
		startCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn endCol = columnModel.getColumn(RegionTableColumns.END.ordinal());
		endCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn lenCol = columnModel.getColumn(RegionTableColumns.LENGTH.ordinal());
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);

		final int small = 100;
		TableColumn rCol = columnModel.getColumn(RegionTableColumns.READ.ordinal());
		rCol.setPreferredWidth(small);
		TableColumn wCol = columnModel.getColumn(RegionTableColumns.WRITE.ordinal());
		wCol.setPreferredWidth(small);
		TableColumn eCol = columnModel.getColumn(RegionTableColumns.EXECUTE.ordinal());
		eCol.setPreferredWidth(small);
		TableColumn vCol = columnModel.getColumn(RegionTableColumns.VOLATILE.ordinal());
		vCol.setPreferredWidth(small);
	}

	protected void navigateToSelectedRegion() {
		if (listingService != null) {
			int selectedRow = regionTable.getSelectedRow();
			int selectedColumn = regionTable.getSelectedColumn();
			Object value = regionTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				listingService.goTo((Address) value, true);
			}
		}
	}

	protected void createActions() {
		actionSelectAddresses = new SelectAddressesAction();
		actionSelectRows = SelectRowsAction.builder(plugin)
				.description("Select regions by trace selection")
				.enabledWhen(ctx -> currentTrace != null)
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || currentTrace == null) {
			return;
		}
		// TODO: Select from other listings?
		ProgramSelection progSel = listingService.getCurrentSelection();

		TraceMemoryManager memoryManager = currentTrace.getMemoryManager();
		if (progSel != null && !progSel.isEmpty()) {
			Set<TraceMemoryRegion> regSel = new HashSet<>();
			for (AddressRange range : progSel) {
				regSel.addAll(memoryManager.getRegionsIntersecting(
					Range.singleton(traceManager.getCurrentSnap()), range));
			}
			setSelectedRegions(regSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			TraceMemoryRegion reg = memoryManager.getRegionContaining(traceManager.getCurrentSnap(),
				progLoc.getAddress());
			if (reg != null) {
				setSelectedRegions(Set.of(reg));
				return;
			}
		}
	}

	public void setSelectedRegions(Set<TraceMemoryRegion> sel) {
		DebuggerResources.setSelectedRows(sel, regionTableModel::getRow, regionTable,
			regionTableModel, regionFilterPanel);
	}

	public Collection<RegionRow> getSelectedRows() {
		return regionFilterPanel.getSelectedItems();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadRegions();
		contextChanged();
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(regionsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(regionsListener);
	}
}
