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
package ghidra.app.plugin.core.debug.gui.breakpoint;

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
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceBreakpointChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.util.*;
import ghidra.util.database.ObjectKey;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerBreakpointsProvider extends ComponentProviderAdapter
		implements LogicalBreakpointsChangeListener {

	protected enum LogicalBreakpointTableColumns
		implements EnumeratedTableColumn<LogicalBreakpointTableColumns, LogicalBreakpointRow> {
		ENABLED("", Enablement.class, LogicalBreakpointRow::getEnablement, LogicalBreakpointRow::setEnablement, true),
		IMAGE("Image", String.class, LogicalBreakpointRow::getImageName, true),
		ADDRESS("Address", Address.class, LogicalBreakpointRow::getAddress, true),
		LENGTH("Length", Long.class, LogicalBreakpointRow::getLength, true),
		KINDS("Kinds", String.class, LogicalBreakpointRow::getKinds, true),
		LOCATIONS("Locations", Integer.class, LogicalBreakpointRow::getLocationCount, true);

		private final String header;
		private final Function<LogicalBreakpointRow, ?> getter;
		private final BiConsumer<LogicalBreakpointRow, Object> setter;
		private final boolean sortable;
		private final Class<?> cls;

		<T> LogicalBreakpointTableColumns(String header, Class<T> cls,
				Function<LogicalBreakpointRow, T> getter, boolean sortable) {
			this(header, cls, getter, null, sortable);
		}

		@SuppressWarnings("unchecked")
		<T> LogicalBreakpointTableColumns(String header, Class<T> cls,
				Function<LogicalBreakpointRow, T> getter,
				BiConsumer<LogicalBreakpointRow, T> setter, boolean sortable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<LogicalBreakpointRow, Object>) setter;
			this.sortable = sortable;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(LogicalBreakpointRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(LogicalBreakpointRow row) {
			return setter != null;
		}

		@Override
		public boolean isSortable() {
			return sortable;
		}

		@Override
		public void setValueOf(LogicalBreakpointRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class LogicalBreakpointTableModel extends RowWrappedEnumeratedColumnTableModel< //
			LogicalBreakpointTableColumns, LogicalBreakpoint, LogicalBreakpointRow, LogicalBreakpoint> {

		public LogicalBreakpointTableModel(DebuggerBreakpointsProvider provider) {
			super("Breakpoints", LogicalBreakpointTableColumns.class, lb -> lb,
				lb -> new LogicalBreakpointRow(provider, lb));
		}

		@Override
		public List<LogicalBreakpointTableColumns> defaultSortOrder() {
			return List.of(LogicalBreakpointTableColumns.ADDRESS);
		}
	}

	protected enum BreakpointLocationTableColumns
		implements EnumeratedTableColumn<BreakpointLocationTableColumns, BreakpointLocationRow> {
		ENABLED("", Boolean.class, BreakpointLocationRow::isEnabled, BreakpointLocationRow::setEnabled, true),
		NAME("Name", String.class, BreakpointLocationRow::getName, BreakpointLocationRow::setName, true),
		ADDRESS("Address", Address.class, BreakpointLocationRow::getAddress, true),
		TRACE("Trace", String.class, BreakpointLocationRow::getTraceName, true),
		THREADS("Threads", String.class, BreakpointLocationRow::getThreads, true),
		COMMENT("Comment", String.class, BreakpointLocationRow::getComment, BreakpointLocationRow::setComment, true);

		private final String header;
		private final Function<BreakpointLocationRow, ?> getter;
		private final BiConsumer<BreakpointLocationRow, Object> setter;
		private final boolean sortable;
		private final Class<?> cls;

		<T> BreakpointLocationTableColumns(String header, Class<T> cls,
				Function<BreakpointLocationRow, T> getter, boolean sortable) {
			this(header, cls, getter, null, sortable);
		}

		@SuppressWarnings("unchecked")
		<T> BreakpointLocationTableColumns(String header, Class<T> cls,
				Function<BreakpointLocationRow, T> getter,
				BiConsumer<BreakpointLocationRow, T> setter, boolean sortable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<BreakpointLocationRow, Object>) setter;
			this.sortable = sortable;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(BreakpointLocationRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(BreakpointLocationRow row) {
			return setter != null;
		}

		@Override
		public boolean isSortable() {
			return sortable;
		}

		@Override
		public void setValueOf(BreakpointLocationRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class BreakpointLocationTableModel
			extends RowWrappedEnumeratedColumnTableModel< //
					BreakpointLocationTableColumns, ObjectKey, BreakpointLocationRow, TraceBreakpoint> {

		public BreakpointLocationTableModel(DebuggerBreakpointsProvider provider) {
			super("Locations", BreakpointLocationTableColumns.class, TraceBreakpoint::getObjectKey,
				loc -> new BreakpointLocationRow(provider, loc));
		}

		@Override
		public List<BreakpointLocationTableColumns> defaultSortOrder() {
			return List.of(BreakpointLocationTableColumns.ADDRESS);
		}
	}

	protected static boolean contextIsNonEmptyBreakpoints(ActionContext context) {
		if (context == null) {
			return false;
		}
		if (context instanceof DebuggerLogicalBreakpointsActionContext) {
			DebuggerLogicalBreakpointsActionContext ctx =
				(DebuggerLogicalBreakpointsActionContext) context;
			return !ctx.getSelection().isEmpty();
		}
		if (context instanceof DebuggerBreakpointLocationsActionContext) {
			DebuggerBreakpointLocationsActionContext ctx =
				(DebuggerBreakpointLocationsActionContext) context;
			return !ctx.getSelection().isEmpty();
		}
		return false;
	}

	protected class EnableSelectedBreakpointsAction
			extends AbstractEnableSelectedBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public EnableSelectedBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (context == null) {
				return;
			}
			if (context instanceof DebuggerLogicalBreakpointsActionContext) {
				DebuggerLogicalBreakpointsActionContext ctx =
					(DebuggerLogicalBreakpointsActionContext) context;
				Collection<LogicalBreakpoint> sel = ctx.getSelection();
				breakpointService.enableAll(sel, null).exceptionally(ex -> {
					breakpointError("Enable Breakpoints", "Could not enable breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getSelection();
				breakpointService.enableLocs(sel).exceptionally(ex -> {
					breakpointError("Enable Breakpoints", "Could not enable breakpoints", ex);
					return null;
				});
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return contextIsNonEmptyBreakpoints(context);
		}
	}

	protected class EnableAllBreakpointsAction extends AbstractEnableAllBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public EnableAllBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
			breakpointService.enableAll(all, null).exceptionally(ex -> {
				breakpointError("Enable All Breakpoints", "Could not enable breakpoints", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return breakpointService != null && !breakpointService.getAllBreakpoints().isEmpty();
		}
	}

	protected class DisableSelectedBreakpointsAction
			extends AbstractDisableSelectedBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public DisableSelectedBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (context == null) {
				return;
			}
			if (context instanceof DebuggerLogicalBreakpointsActionContext) {
				DebuggerLogicalBreakpointsActionContext ctx =
					(DebuggerLogicalBreakpointsActionContext) context;
				Collection<LogicalBreakpoint> sel = ctx.getSelection();
				breakpointService.disableAll(sel, null).exceptionally(ex -> {
					breakpointError("Disable Breakpoints", "Could not disable breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getSelection();
				breakpointService.disableLocs(sel).exceptionally(ex -> {
					breakpointError("Disable Breakpoints", "Could not disable breakpoints", ex);
					return null;
				});
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return contextIsNonEmptyBreakpoints(context);
		}
	}

	protected class DisableAllBreakpointsAction extends AbstractDisableAllBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public DisableAllBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
			breakpointService.disableAll(all, null).exceptionally(ex -> {
				breakpointError("Disable All Breakpoints", "Could not disable breakpoints", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return breakpointService != null && !breakpointService.getAllBreakpoints().isEmpty();
		}
	}

	protected class ClearSelectedBreakpointsAction extends AbstractClearSelectedBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS + "Clear";

		public ClearSelectedBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (context instanceof DebuggerLogicalBreakpointsActionContext) {
				DebuggerLogicalBreakpointsActionContext ctx =
					(DebuggerLogicalBreakpointsActionContext) context;
				Collection<LogicalBreakpoint> sel = ctx.getSelection();
				breakpointService.deleteAll(sel, null).exceptionally(ex -> {
					breakpointError("Clear Breakpoints", "Could not clear breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getSelection();
				breakpointService.deleteLocs(sel).exceptionally(ex -> {
					breakpointError("Clear Breakpoints", "Could not clear breakpoints", ex);
					return null;
				});
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return contextIsNonEmptyBreakpoints(context);
		}
	}

	protected class ClearAllBreakpointsAction extends AbstractClearAllBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS + "Clear";

		public ClearAllBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
			breakpointService.deleteAll(all, null).exceptionally(ex -> {
				breakpointError("Clear All Breakpoints", "Could not clear breakpoints", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return breakpointService != null && !breakpointService.getAllBreakpoints().isEmpty();
		}
	}

	protected abstract class CommonMakeBreakpointsEffectiveAction
			extends AbstractMakeBreakpointsEffectiveAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public CommonMakeBreakpointsEffectiveAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Set<LogicalBreakpoint> enablable = breakpointService.getAllBreakpoints()
					.stream()
					.filter(lb -> lb.computeEnablement() == Enablement.INEFFECTIVE_ENABLED &&
						!lb.getMappedTraces().isEmpty())
					.collect(Collectors.toSet());
			breakpointService.enableAll(enablable, null).exceptionally(ex -> {
				breakpointError("Make Breakpoints Effective", "Could not enable breakpoints", ex);
				return null;
			});
		}
	}

	protected class MakeBreakpointsEffectiveAction extends CommonMakeBreakpointsEffectiveAction {
		public MakeBreakpointsEffectiveAction() {
			super();
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (breakpointService == null) {
				return false;
			}
			Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
			for (LogicalBreakpoint lb : all) {
				if (lb.computeEnablement() != Enablement.INEFFECTIVE_ENABLED) {
					continue;
				}
				if (lb.getMappedTraces().isEmpty()) {
					continue;
				}
				return true;
			}
			return false;
		}
	}

	protected class MakeBreakpointsEffectiveResolutionAction
			extends CommonMakeBreakpointsEffectiveAction {
		@Override
		public boolean isValidContext(ActionContext context) {
			return context instanceof DebuggerMakeBreakpointsEffectiveActionContext;
		}
	}

	class LocationsBySelectedBreakpointsTableFilter implements TableFilter<BreakpointLocationRow> {
		@Override
		public boolean acceptsRow(BreakpointLocationRow locationRow) {
			if (isFilterByCurrentTrace() &&
				locationRow.getTraceBreakpoint().getTrace() != currentTrace) {
				return false;
			}
			if (isFilterLocationsByBreakpoints()) {
				List<LogicalBreakpointRow> selBreakRows = breakpointFilterPanel.getSelectedItems();
				if (selBreakRows == null || selBreakRows.isEmpty()) {
					return true;
				}
				for (LogicalBreakpointRow breakRow : selBreakRows) {
					if (breakRow.getLogicalBreakpoint()
							.getTraceBreakpoints()
							.contains(locationRow.getTraceBreakpoint())) {
						return true;
					}
				}
				return false;
			}
			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			return false;
		}
	}

	protected class TrackRecordersListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceRecordingStarted(element));
		}

		@Override
		public void elementRemoved(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceRecordingStopped(element));
		}
	}

	protected class ForBreakpointLocationsTraceListener extends TraceDomainObjectListener {
		private final TraceRecorder recorder;
		private final Trace trace;

		public ForBreakpointLocationsTraceListener(TraceRecorder recorder) {
			// TODO: What if recorder advances past a trace breakpoint?
			// Tends never to happen during recording, since upper is unbounded
			// (Same in LogicalBreak service)
			this.recorder = recorder;
			this.trace = recorder.getTrace();
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());
			listenFor(TraceBreakpointChangeType.ADDED, this::locationAdded);
			listenFor(TraceBreakpointChangeType.CHANGED, this::locationChanged);
			listenFor(TraceBreakpointChangeType.LIFESPAN_CHANGED, this::locationLifespanChanged);
			listenFor(TraceBreakpointChangeType.DELETED, this::locationDeleted);

			trace.addListener(this);
		}

		private void objectRestored() {
			reloadBreakpointLocations(recorder);
		}

		private boolean isLive(TraceBreakpoint location) {
			return location.getLifespan().contains(recorder.getSnap());
		}

		private void locationAdded(TraceBreakpoint location) {
			if (!isLive(location)) {
				return;
			}
			breakpointLocationAdded(location);
		}

		private void locationChanged(TraceBreakpoint location) {
			if (!isLive(location)) {
				return;
			}
			breakpointLocationUpdated(location);
		}

		private void locationLifespanChanged(TraceBreakpoint location, Range<Long> oldSpan,
				Range<Long> newSpan) {
			boolean isLiveOld = oldSpan.contains(recorder.getSnap());
			boolean isLiveNew = newSpan.contains(recorder.getSnap());
			if (isLiveOld == isLiveNew) {
				return;
			}
			if (isLiveOld) {
				breakpointLocationRemoved(location);
			}
			else {
				breakpointLocationAdded(location);
			}
		}

		private void locationDeleted(TraceBreakpoint location) {
			if (!isLive(location)) {
				return;
			}
			breakpointLocationRemoved(location);
		}

		private void dispose() {
			trace.removeListener(this);
		}
	}

	private final DebuggerBreakpointsPlugin plugin;

	// @AutoServiceConsumed via method
	private DebuggerLogicalBreakpointService breakpointService;
	// @AutoServiceConsumed via method, package access for BreakpointLogicalRow
	DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	private GoToService goToService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	private final TrackRecordersListener recorderListener = new TrackRecordersListener();
	private final Map<Trace, ForBreakpointLocationsTraceListener> listenersByTrace =
		new HashMap<>();

	Trace currentTrace;

	private final JSplitPane mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

	LogicalBreakpointTableModel breakpointTableModel = new LogicalBreakpointTableModel(this);
	GhidraTable breakpointTable;
	GhidraTableFilterPanel<LogicalBreakpointRow> breakpointFilterPanel;

	BreakpointLocationTableModel locationTableModel = new BreakpointLocationTableModel(this);
	GhidraTable locationTable;
	GhidraTableFilterPanel<BreakpointLocationRow> locationFilterPanel;
	private final LocationsBySelectedBreakpointsTableFilter filterLocationsBySelectedBreakpoints =
		new LocationsBySelectedBreakpointsTableFilter();

	private ActionContext myActionContext;

	private final DebuggerMakeBreakpointsEffectiveActionContext makeEffectiveResolutionContext =
		new DebuggerMakeBreakpointsEffectiveActionContext();

	// package access for testing
	EnableSelectedBreakpointsAction actionEnableSelectedBreakpoints;
	EnableAllBreakpointsAction actionEnableAllBreakpoints;
	DisableSelectedBreakpointsAction actionDisableSelectedBreakpoints;
	DisableAllBreakpointsAction actionDisableAllBreakpoints;
	ClearSelectedBreakpointsAction actionClearSelectedBreakpoints;
	ClearAllBreakpointsAction actionClearAllBreakpoints;
	MakeBreakpointsEffectiveAction actionMakeBreakpointsEffective;
	MakeBreakpointsEffectiveResolutionAction actionMakeBreakpointsEffectiveResolution;
	ToggleDockingAction actionFilterByCurrentTrace;
	ToggleDockingAction actionFilterLocationsByBreakpoints;

	public DebuggerBreakpointsProvider(final DebuggerBreakpointsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_BREAKPOINTS, plugin.getName());
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_BREAKPOINTS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_BREAKPOINTS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.RIGHT);
		setVisible(true);
		createActions();
	}

	protected void dispose() {
		if (consoleService != null) {
			if (actionMakeBreakpointsEffectiveResolution != null) {
				consoleService.removeResolutionAction(actionMakeBreakpointsEffectiveResolution);
			}
		}
	}

	@Override
	public void contextChanged() {
		super.contextChanged();
		if (consoleService == null) {
			return;
		}
		// TODO: This should probably check for its existence first
		// Kind of a hack, but it works.
		if (actionMakeBreakpointsEffective != null &&
			actionMakeBreakpointsEffective.isEnabledForContext(myActionContext)) {
			if (!consoleService.logContains(makeEffectiveResolutionContext)) {
				consoleService.log(DebuggerResources.ICON_PROVIDER_BREAKPOINTS,
					"There are ineffective breakpoints that can be placed",
					makeEffectiveResolutionContext);
			}
		}
		else {
			consoleService.removeFromLog(makeEffectiveResolutionContext);
		}
	}

	@AutoServiceConsumed
	private void setBreakpointService(DebuggerLogicalBreakpointService breakpointService) {
		if (this.breakpointService != null) {
			this.breakpointService.removeChangeListener(this);
			breakpointTableModel.clear();
		}
		this.breakpointService = breakpointService;
		if (this.breakpointService != null) {
			this.breakpointService.addChangeListener(this);
			loadBreakpoints();
		}
		contextChanged();
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeTraceRecordersChangedListener(recorderListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addTraceRecordersChangedListener(recorderListener);
		}
	}

	@AutoServiceConsumed
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionMakeBreakpointsEffectiveResolution != null) {
				consoleService.addResolutionAction(actionMakeBreakpointsEffectiveResolution);
			}
		}
	}

	protected void loadBreakpoints() {
		Set<LogicalBreakpoint> all = breakpointService.getAllBreakpoints();
		breakpointTableModel.addAllItems(all);
	}

	@Override
	public void breakpointAdded(LogicalBreakpoint lb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.addItem(lb);
			contextChanged(); // TODO: Debounce these?
		});
	}

	@Override
	public void breakpointsAdded(Collection<LogicalBreakpoint> clb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.addAllItems(clb);
			contextChanged();
		});
	}

	@Override
	public void breakpointUpdated(LogicalBreakpoint lb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.updateItem(lb);
			contextChanged();
		});
	}

	@Override
	public void breakpointsUpdated(Collection<LogicalBreakpoint> clb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.updateAllItems(clb);
			contextChanged();
		});
	}

	@Override
	public void breakpointRemoved(LogicalBreakpoint lb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.deleteItem(lb);
			contextChanged();
		});
	}

	@Override
	public void breakpointsRemoved(Collection<LogicalBreakpoint> clb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.deleteAllItems(clb);
			contextChanged();
		});
	}

	private void loadBreakpointLocations(TraceRecorder recorder) {
		Trace trace = recorder.getTrace();
		for (AddressRange range : trace.getBaseAddressFactory().getAddressSet()) {
			locationTableModel.addAllItems(trace.getBreakpointManager()
					.getBreakpointsIntersecting(Range.singleton(recorder.getSnap()), range));
		}
	}

	private void unloadBreakpointLocations(Trace trace) {
		locationTableModel.deleteWith(r -> r.getTraceBreakpoint().getTrace() == trace);
	}

	private void reloadBreakpointLocations(TraceRecorder recorder) {
		Trace trace = recorder.getTrace();
		unloadBreakpointLocations(trace);
		loadBreakpointLocations(recorder);
	}

	private void breakpointLocationAdded(TraceBreakpoint location) {
		locationTableModel.addItem(location);
	}

	private void breakpointLocationUpdated(TraceBreakpoint location) {
		locationTableModel.updateItem(location);
	}

	private void breakpointLocationRemoved(TraceBreakpoint location) {
		locationTableModel.deleteItem(location);
	}

	private void doTrackTrace(Trace trace, TraceRecorder recorder) {
		if (listenersByTrace.containsKey(trace)) {
			Msg.warn(this, "Already tracking trace breakpoints");
			return;
		}
		listenersByTrace.put(trace, new ForBreakpointLocationsTraceListener(recorder));
		loadBreakpointLocations(recorder);
	}

	private void doUntrackTrace(Trace trace) {
		ForBreakpointLocationsTraceListener l = listenersByTrace.remove(trace);
		if (l != null) { // Could be from close or recorder stop
			l.dispose();
			unloadBreakpointLocations(trace);
		}
	}

	private void traceRecordingStarted(TraceRecorder recorder) {
		Trace trace = recorder.getTrace();
		if (!traceManager.getOpenTraces().contains(trace)) {
			return;
		}
		doTrackTrace(trace, recorder);
	}

	private void traceRecordingStopped(TraceRecorder recorder) {
		doUntrackTrace(recorder.getTrace());
	}

	protected void traceOpened(Trace trace) {
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder == null) {
			return;
		}
		doTrackTrace(trace, recorder);
	}

	protected void traceClosed(Trace trace) {
		doUntrackTrace(trace);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return myActionContext;
	}

	protected void buildMainPanel() {
		mainPanel.setContinuousLayout(true);

		JPanel breakpointPanel = new JPanel(new BorderLayout());
		breakpointTable = new GhidraTable(breakpointTableModel);
		breakpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		breakpointPanel.add(new JScrollPane(breakpointTable));
		breakpointTable.setAutoLookupColumn(LogicalBreakpointTableColumns.ADDRESS.ordinal());
		breakpointFilterPanel = new GhidraTableFilterPanel<>(breakpointTable, breakpointTableModel);
		breakpointPanel.add(breakpointFilterPanel, BorderLayout.SOUTH);
		mainPanel.setLeftComponent(breakpointPanel);

		JPanel locationPanel = new JPanel(new BorderLayout());
		locationTable = new GhidraTable(locationTableModel);
		locationTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		locationPanel.add(new JScrollPane(locationTable));
		locationFilterPanel = new GhidraTableFilterPanel<>(locationTable, locationTableModel);
		locationFilterPanel.setSecondaryFilter(filterLocationsBySelectedBreakpoints);
		locationPanel.add(locationFilterPanel, BorderLayout.SOUTH);
		mainPanel.setRightComponent(locationPanel);

		mainPanel.setResizeWeight(0.5);

		breakpointTable.getSelectionModel().addListSelectionListener(evt -> {
			List<LogicalBreakpoint> set = breakpointFilterPanel.getSelectedItems()
					.stream()
					.map(LogicalBreakpointRow::getLogicalBreakpoint)
					.collect(Collectors.toList());
			// Do this first to prevent overriding context in event chain
			if (!set.isEmpty()) {
				locationTable.clearSelection();
				locationTable.getSelectionManager().clearSavedSelection();
			}
			myActionContext = new DebuggerLogicalBreakpointsActionContext(set);
			if (isFilterLocationsByBreakpoints()) {
				locationTableModel.fireTableDataChanged();
			}
			contextChanged();
		});
		// TODO: We could probably factor these two listeners into a utility
		breakpointTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				if (e.getClickCount() != 2) {
					return;
				}
				navigateToSelectedBreakpoint();
			}
		});
		breakpointTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER || e.getModifiersEx() != 0) {
					return;
				}
				navigateToSelectedBreakpoint();
			}
		});

		locationTable.getSelectionModel().addListSelectionListener(evt -> {
			List<TraceBreakpoint> set = locationFilterPanel.getSelectedItems()
					.stream()
					.map(BreakpointLocationRow::getTraceBreakpoint)
					.collect(Collectors.toList());
			// Do this first to avoid overriding context in event chain
			if (!set.isEmpty()) {
				breakpointTable.clearSelection();
				breakpointTable.getSelectionManager().clearSavedSelection();
			}
			myActionContext = new DebuggerBreakpointLocationsActionContext(set);
			contextChanged();
		});
		locationTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				if (e.getClickCount() != 2) {
					return;
				}
				navigateToSelectedLocation();
			}
		});
		locationTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER || e.getModifiersEx() != 0) {
					return;
				}
				navigateToSelectedLocation();
			}
		});

		TableColumnModel bptColModel = breakpointTable.getColumnModel();
		TableColumn bptEnCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.ENABLED.ordinal());
		bptEnCol.setCellRenderer(new DebuggerBreakpointEnablementTableCellRenderer());
		bptEnCol.setCellEditor(
			new DebuggerBreakpointEnablementTableCellEditor(breakpointFilterPanel));
		bptEnCol.setMaxWidth(24);
		bptEnCol.setMinWidth(24);
		TableColumn bptAddrCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.ADDRESS.ordinal());
		bptAddrCol.setPreferredWidth(150);
		bptAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn lenCol = bptColModel.getColumn(LogicalBreakpointTableColumns.LENGTH.ordinal());
		lenCol.setPreferredWidth(60);
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
		TableColumn kindCol = bptColModel.getColumn(LogicalBreakpointTableColumns.KINDS.ordinal());
		kindCol.setPreferredWidth(150);
		TableColumn locsCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.LOCATIONS.ordinal());
		locsCol.setPreferredWidth(20);

		TableColumnModel locColModel = locationTable.getColumnModel();
		TableColumn locEnCol =
			locColModel.getColumn(BreakpointLocationTableColumns.ENABLED.ordinal());
		locEnCol.setCellRenderer(new DebuggerBreakpointLocEnabledTableCellRenderer());
		locEnCol.setCellEditor(new DebuggerBreakpointLocEnabledTableCellEditor());
		locEnCol.setMaxWidth(24);
		locEnCol.setMinWidth(24);
		TableColumn locAddrCol =
			locColModel.getColumn(BreakpointLocationTableColumns.ADDRESS.ordinal());
		locAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
	}

	protected void navigateToSelectedBreakpoint() {
		if (listingService == null) {
			return;
		}
		LogicalBreakpointRow row = breakpointFilterPanel.getSelectedItem();
		if (row == null) {
			return;
		}
		LogicalBreakpoint lb = row.getLogicalBreakpoint();

		Trace trace;
		Set<Trace> traces = lb.getParticipatingTraces();
		if (traces.size() == 1) {
			trace = traces.iterator().next();
		}
		else {
			trace = traceManager.getCurrentTrace();
		}

		Address traceAddress = lb.getTraceAddress(trace);
		if (traceAddress != null) {
			// Yes, current view, even if it's in the past. Breakpoint's address is from present. 
			ProgramLocation loc = new ProgramLocation(trace.getProgramView(), traceAddress);
			listingService.goTo(loc, true);
		}

		ProgramLocation programLocation = lb.getProgramLocation();
		if (programLocation != null) {
			goToService.goTo(programLocation);
		}
	}

	protected void navigateToSelectedLocation() {
		if (listingService == null) {
			return;
		}
		BreakpointLocationRow row = locationFilterPanel.getSelectedItem();
		if (row == null) {
			return;
		}
		Trace trace = row.getTraceBreakpoint().getTrace();
		if (trace != currentTrace) {
			if (traceManager == null) {
				return;
			}
			traceManager.activateTrace(trace);
		}
		listingService.goTo(row.getAddress(), true);
	}

	protected void createActions() {
		actionEnableSelectedBreakpoints = new EnableSelectedBreakpointsAction();
		actionEnableAllBreakpoints = new EnableAllBreakpointsAction();
		actionDisableSelectedBreakpoints = new DisableSelectedBreakpointsAction();
		actionDisableAllBreakpoints = new DisableAllBreakpointsAction();
		actionClearSelectedBreakpoints = new ClearSelectedBreakpointsAction();
		actionClearAllBreakpoints = new ClearAllBreakpointsAction();
		actionMakeBreakpointsEffective = new MakeBreakpointsEffectiveAction();
		actionFilterByCurrentTrace = FilterAction.builder(plugin)
				.toolBarIcon(DebuggerResources.ICON_TRACE)
				.description("Filter locations to those in current trace")
				.helpLocation(new HelpLocation(plugin.getName(), "filter_by_trace"))
				.onAction(this::toggledFilterByCurrentTrace)
				.buildAndInstallLocal(this);
		actionFilterLocationsByBreakpoints = FilterAction.builder(plugin)
				.description("Filter locations to those in selected breakpoints")
				.helpLocation(new HelpLocation(plugin.getName(), "filter_by_logical"))
				.onAction(this::toggledFilterLocationsByBreakpoints)
				.buildAndInstallLocal(this);

		actionMakeBreakpointsEffectiveResolution = new MakeBreakpointsEffectiveResolutionAction();
	}

	private void toggledFilterByCurrentTrace(ActionContext ignored) {
		breakpointTableModel.fireTableDataChanged();
		locationTableModel.fireTableDataChanged();
	}

	public boolean isFilterByCurrentTrace() {
		return actionFilterByCurrentTrace.isSelected();
	}

	private void toggledFilterLocationsByBreakpoints(ActionContext ignored) {
		locationTableModel.fireTableDataChanged();
	}

	public boolean isFilterLocationsByBreakpoints() {
		return actionFilterLocationsByBreakpoints.isSelected();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setTrace(Trace trace) {
		currentTrace = trace;
		if (isFilterByCurrentTrace()) {
			breakpointTableModel.fireTableDataChanged();
			locationTableModel.fireTableDataChanged();
		}
	}

	public void setSelectedBreakpoints(Set<LogicalBreakpoint> sel) {
		DebuggerResources.setSelectedRows(sel, breakpointTableModel::getRow, breakpointTable,
			breakpointTableModel, breakpointFilterPanel);
	}

	public void setSelectedLocations(Set<TraceBreakpoint> sel) {
		DebuggerResources.setSelectedRows(sel, locationTableModel::getRow, locationTable,
			locationTableModel, locationFilterPanel);
	}

	protected void breakpointError(String title, String message, Throwable ex) {
		if (consoleService == null) {
			Msg.showError(this, null, title, message, ex);
			return;
		}
		Msg.error(this, message, ex);
		consoleService.log(DebuggerResources.ICON_LOG_ERROR, message + " (" + ex + ")");
	}
}
