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
import java.util.function.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.menu.MultiActionDockingAction;
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.InvokeActionEntryAction;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.ControlModeChangeListener;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpoint.State;
import ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerBreakpointsProvider extends ComponentProviderAdapter
		implements LogicalBreakpointsChangeListener, ControlModeChangeListener {

	protected enum LogicalBreakpointTableColumns
		implements EnumeratedTableColumn<LogicalBreakpointTableColumns, LogicalBreakpointRow> {
		STATE("State", State.class, LogicalBreakpointRow::getState, LogicalBreakpointRow::setState, true),
		NAME("Name", String.class, LogicalBreakpointRow::getName, LogicalBreakpointRow::setName, //
				LogicalBreakpointRow::isNamable, true),
		ADDRESS("Address", Address.class, LogicalBreakpointRow::getAddress, true),
		IMAGE("Image", String.class, LogicalBreakpointRow::getImageName, true),
		LENGTH("Length", Long.class, LogicalBreakpointRow::getLength, true),
		KINDS("Kinds", String.class, LogicalBreakpointRow::getKinds, true),
		LOCATIONS("Locations", Integer.class, LogicalBreakpointRow::getLocationCount, true),
		SLEIGH("Sleigh", Boolean.class, LogicalBreakpointRow::hasSleigh, true);

		private final String header;
		private final Class<?> cls;
		private final Function<LogicalBreakpointRow, ?> getter;
		private final BiConsumer<LogicalBreakpointRow, Object> setter;
		private final Predicate<LogicalBreakpointRow> editable;
		private final boolean sortable;

		<T> LogicalBreakpointTableColumns(String header, Class<T> cls,
				Function<LogicalBreakpointRow, T> getter, boolean sortable) {
			this(header, cls, getter, null, null, sortable);
		}

		<T> LogicalBreakpointTableColumns(String header, Class<T> cls,
				Function<LogicalBreakpointRow, T> getter,
				BiConsumer<LogicalBreakpointRow, T> setter, boolean sortable) {
			this(header, cls, getter, setter, null, sortable);
		}

		@SuppressWarnings("unchecked")
		<T> LogicalBreakpointTableColumns(String header, Class<T> cls,
				Function<LogicalBreakpointRow, T> getter,
				BiConsumer<LogicalBreakpointRow, T> setter,
				Predicate<LogicalBreakpointRow> editable, boolean sortable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<LogicalBreakpointRow, Object>) setter;
			this.editable = editable;
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
			return setter != null && (editable == null || editable.test(row));
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
			super(provider.getTool(), "Breakpoints", LogicalBreakpointTableColumns.class, lb -> lb,
				lb -> new LogicalBreakpointRow(provider, lb),
				LogicalBreakpointRow::getLogicalBreakpoint);
		}

		@Override
		public List<LogicalBreakpointTableColumns> defaultSortOrder() {
			return List.of(LogicalBreakpointTableColumns.IMAGE,
				LogicalBreakpointTableColumns.ADDRESS, LogicalBreakpointTableColumns.NAME);
		}
	}

	protected enum BreakpointLocationTableColumns
		implements EnumeratedTableColumn<BreakpointLocationTableColumns, BreakpointLocationRow> {
		STATE("State", State.class, BreakpointLocationRow::getState, BreakpointLocationRow::setState, true, true),
		NAME("Name", String.class, BreakpointLocationRow::getName, BreakpointLocationRow::setName, true, true),
		ADDRESS("Address", Address.class, BreakpointLocationRow::getAddress, true, true),
		TRACE("Trace", String.class, BreakpointLocationRow::getTraceName, true, true),
		THREADS("Threads", String.class, BreakpointLocationRow::getThreads, true, false),
		COMMENT("Comment", String.class, BreakpointLocationRow::getComment, BreakpointLocationRow::setComment, true, true),
		SLEIGH("Sleigh", Boolean.class, BreakpointLocationRow::hasSleigh, true, true);

		private final String header;
		private final Function<BreakpointLocationRow, ?> getter;
		private final BiConsumer<BreakpointLocationRow, Object> setter;
		private final boolean sortable;
		private final boolean visible;
		private final Class<?> cls;

		<T> BreakpointLocationTableColumns(String header, Class<T> cls,
				Function<BreakpointLocationRow, T> getter, boolean sortable, boolean visible) {
			this(header, cls, getter, null, sortable, visible);
		}

		@SuppressWarnings("unchecked")
		<T> BreakpointLocationTableColumns(String header, Class<T> cls,
				Function<BreakpointLocationRow, T> getter,
				BiConsumer<BreakpointLocationRow, T> setter, boolean sortable, boolean visible) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<BreakpointLocationRow, Object>) setter;
			this.sortable = sortable;
			this.visible = visible;
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
		public boolean isVisible() {
			return visible;
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
			super(provider.getTool(), "Locations", BreakpointLocationTableColumns.class,
				TraceBreakpoint::getObjectKey, loc -> new BreakpointLocationRow(provider, loc),
				BreakpointLocationRow::getTraceBreakpoint);
		}

		@Override
		public List<BreakpointLocationTableColumns> defaultSortOrder() {
			return List.of(BreakpointLocationTableColumns.ADDRESS,
				BreakpointLocationTableColumns.NAME);
		}
	}

	protected static boolean contextHasMatchingBreakpoints(ActionContext context,
			Predicate<? super LogicalBreakpointRow> logicalCase,
			Predicate<? super BreakpointLocationRow> locationCase) {
		if (context == null) {
			return false;
		}
		if (context instanceof DebuggerLogicalBreakpointsActionContext) {
			DebuggerLogicalBreakpointsActionContext ctx =
				(DebuggerLogicalBreakpointsActionContext) context;
			return ctx.getSelection().stream().anyMatch(logicalCase);
		}
		if (context instanceof DebuggerBreakpointLocationsActionContext) {
			DebuggerBreakpointLocationsActionContext ctx =
				(DebuggerBreakpointLocationsActionContext) context;
			return ctx.getSelection().stream().anyMatch(locationCase);
		}
		return false;
	}

	protected static boolean contextIsNonEmptyBreakpoints(ActionContext context) {
		return contextHasMatchingBreakpoints(context, lb -> true, loc -> true);
	}

	protected class GenericSetBreakpointAction extends InvokeActionEntryAction {
		public GenericSetBreakpointAction(ActionEntry entry) {
			super(plugin, entry);
			setMenuBarData(new MenuData(new String[] { getName() }, entry.icon()));
			setHelpLocation(AbstractSetBreakpointAction.help(plugin));
		}
	}

	protected class StubSetBreakpointAction extends DockingAction {
		public StubSetBreakpointAction() {
			super("(Use the Listings to Set Breakpoints)", plugin.getName());
			setMenuBarData(new MenuData(new String[] { getName() }));
			setHelpLocation(AbstractSetBreakpointAction.help(plugin));
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
		}
	}

	protected class SetBreakpointAction extends MultiActionDockingAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		private final List<DockingActionIf> stub = List.of(new StubSetBreakpointAction());

		public SetBreakpointAction() {
			super("Set Breakpoint", plugin.getName());
			// TODO: Different icon?
			setToolBarData(new ToolBarData(DebuggerResources.ICON_ADD, GROUP));
			setHelpLocation(AbstractSetBreakpointAction.help(plugin));
			addLocalAction(this);
		}

		@Override
		public List<DockingActionIf> getActionList(ActionContext context) {
			if (traceManager == null) {
				return stub;
			}
			Trace trace = traceManager.getCurrentTrace();
			if (trace == null) {
				return stub;
			}

			// TODO: Set-by-address (like the listing one) always present?
			if (controlService == null) {
				return stub;
			}
			ControlMode mode = controlService.getCurrentMode(trace);
			if (!mode.isTarget()) {
				return stub;
				// TODO: Consider a Sleigh expression for emulation?
				// Actually, any "Address" field could be a Sleigh expression....
			}

			Target target = traceManager.getCurrent().getTarget();
			if (target == null) {
				return stub;
			}
			List<DockingActionIf> result = new ArrayList<>();
			for (ActionEntry entry : target.collectActions(ActionName.BREAK_EXT, context)
					.values()) {
				result.add(new GenericSetBreakpointAction(entry));
			}
			if (result.isEmpty()) {
				return stub;
			}
			Collections.sort(result, Comparator.comparing(a -> a.getName()));
			return result;
		}
	}

	protected class EnableSelectedBreakpointsAction
			extends AbstractEnableSelectedBreakpointsAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public EnableSelectedBreakpointsAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
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
				Collection<LogicalBreakpoint> sel = ctx.getBreakpoints();
				Trace trace = isFilterByCurrentTrace() ? currentTrace : null;
				String status = breakpointService.generateStatusEnable(sel, trace);
				if (status != null) {
					tool.setStatusInfo(status, true);
				}
				breakpointService.enableAll(sel, trace).exceptionally(ex -> {
					breakpointError("Enable Breakpoints", "Could not enable breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getLocations();
				breakpointService.enableLocs(sel).exceptionally(ex -> {
					breakpointError("Enable Breakpoints", "Could not enable breakpoints", ex);
					return null;
				});
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return contextHasMatchingBreakpoints(context, row -> row.getState() != State.ENABLED,
				row -> row.getState() != State.ENABLED);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return isEnabledForContext(context);
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
			Trace trace = isFilterByCurrentTrace() ? currentTrace : null;
			String status = breakpointService.generateStatusEnable(all, trace);
			if (status != null) {
				tool.setStatusInfo(status, true);
			}
			breakpointService.enableAll(all, trace).exceptionally(ex -> {
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
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
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
				Collection<LogicalBreakpoint> sel = ctx.getBreakpoints();
				breakpointService.disableAll(sel, null).exceptionally(ex -> {
					breakpointError("Disable Breakpoints", "Could not disable breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getLocations();
				breakpointService.disableLocs(sel).exceptionally(ex -> {
					breakpointError("Disable Breakpoints", "Could not disable breakpoints", ex);
					return null;
				});
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return contextHasMatchingBreakpoints(context, row -> row.getState() != State.DISABLED,
				row -> row.getState() != State.DISABLED);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return isEnabledForContext(context);
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
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (context instanceof DebuggerLogicalBreakpointsActionContext) {
				DebuggerLogicalBreakpointsActionContext ctx =
					(DebuggerLogicalBreakpointsActionContext) context;
				Collection<LogicalBreakpoint> sel = ctx.getBreakpoints();
				breakpointService.deleteAll(sel, null).exceptionally(ex -> {
					breakpointError("Clear Breakpoints", "Could not clear breakpoints", ex);
					return null;
				});
			}
			if (context instanceof DebuggerBreakpointLocationsActionContext) {
				DebuggerBreakpointLocationsActionContext ctx =
					(DebuggerBreakpointLocationsActionContext) context;
				Collection<TraceBreakpoint> sel = ctx.getLocations();
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
					.filter(lb -> lb.computeState() == State.INEFFECTIVE_ENABLED &&
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
				if (lb.computeState() != State.INEFFECTIVE_ENABLED) {
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

	interface SetEmulatedBreakpointConditionAction {
		String NAME = "Set Condition (Emulator)";
		String DESCRIPTION = "Set a Sleigh condition for this emulated breakpoint";
		String GROUP = DebuggerResources.GROUP_BREAKPOINTS;
		String HELP_ANCHOR = "set_condition";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SetEmulatedBreakpointInjectionAction {
		String NAME = "Set Injection (Emulator)";
		String DESCRIPTION = "Set a Sleigh injection for this emulated breakpoint";
		String GROUP = DebuggerResources.GROUP_BREAKPOINTS;
		String HELP_ANCHOR = "set_injection";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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

	protected class ForBreakpointLocationsTraceListener extends TraceDomainObjectListener {
		private final Trace trace;

		public ForBreakpointLocationsTraceListener(Trace trace) {
			this.trace = trace;
			listenForUntyped(DomainObjectEvent.RESTORED, e -> objectRestored());
			listenFor(TraceEvents.BREAKPOINT_ADDED, this::locationAdded);
			listenFor(TraceEvents.BREAKPOINT_CHANGED, this::locationChanged);
			listenFor(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, this::locationLifespanChanged);
			listenFor(TraceEvents.BREAKPOINT_DELETED, this::locationDeleted);

			trace.addListener(this);
		}

		private void objectRestored() {
			reloadBreakpointLocations(trace);
		}

		private boolean isVisible(TraceBreakpoint location) {
			long snap = traceManager.getCurrentFor(trace).getSnap();
			return location.isAlive(snap);
		}

		private void locationAdded(TraceBreakpoint location) {
			if (!isVisible(location)) {
				return;
			}
			breakpointLocationAdded(location);
		}

		private void locationChanged(TraceBreakpoint location) {
			if (!isVisible(location)) {
				return;
			}
			breakpointLocationUpdated(location);
		}

		private void locationLifespanChanged(TraceBreakpoint location, Lifespan oldSpan,
				Lifespan newSpan) {
			long snap = traceManager.getCurrentFor(trace).getSnap();
			boolean isLiveOld = oldSpan.contains(snap);
			boolean isLiveNew = newSpan.contains(snap);
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
			if (!isVisible(location)) {
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
	DebuggerLogicalBreakpointService breakpointService;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	// @AutoServiceConsumed via method
	private DebuggerControlService controlService;
	@AutoServiceConsumed
	private GoToService goToService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

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
	SetBreakpointAction actionSetBreakpoint;
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
	DockingAction actionSetCondition;
	DockingAction actionSetInjection;

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
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionMakeBreakpointsEffectiveResolution != null) {
				consoleService.addResolutionAction(actionMakeBreakpointsEffectiveResolution);
			}
		}
	}

	@AutoServiceConsumed
	private void setControlService(DebuggerControlService editingService) {
		if (this.controlService != null) {
			this.controlService.removeModeChangeListener(this);
		}
		this.controlService = editingService;
		if (this.controlService != null) {
			this.controlService.addModeChangeListener(this);
		}
	}

	@Override
	public void modeChanged(Trace trace, ControlMode mode) {
		Swing.runIfSwingOrRunLater(() -> {
			reloadBreakpointLocations(trace);
			contextChanged();
		});
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
			breakpointLocationsUpdated(lb.getTraceBreakpoints());
			contextChanged();
		});
	}

	@Override
	public void breakpointsUpdated(Collection<LogicalBreakpoint> clb) {
		Swing.runIfSwingOrRunLater(() -> {
			breakpointTableModel.updateAllItems(clb);
			breakpointLocationsUpdated(clb.stream()
					.flatMap(lb -> lb.getTraceBreakpoints().stream())
					.collect(Collectors.toSet()));
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

	private void loadBreakpointLocations(Trace trace) {
		ControlMode mode =
			controlService == null ? ControlMode.DEFAULT : controlService.getCurrentMode(trace);
		DebuggerCoordinates currentFor = traceManager.getCurrentFor(trace);
		Target target = currentFor.getTarget();
		if (!mode.useEmulatedBreakpoints() && target == null) {
			return;
		}
		Lifespan span = Lifespan.at(currentFor.getSnap());
		Collection<TraceBreakpoint> visible = new ArrayList<>();
		for (AddressRange range : trace.getBaseAddressFactory().getAddressSet()) {
			Collection<? extends TraceBreakpoint> breaks =
				trace.getBreakpointManager().getBreakpointsIntersecting(span, range);
			if (mode.useEmulatedBreakpoints()) {
				visible.addAll(breaks);
			}
			else {
				for (TraceBreakpoint l : breaks) {
					if (target.isBreakpointValid(l)) {
						visible.add(l);
					}
				}
			}
		}
		locationTableModel.addAllItems(visible);
	}

	private void unloadBreakpointLocations(Trace trace) {
		locationTableModel.deleteItemsWith(l -> l.getTrace() == trace);
	}

	private void reloadBreakpointLocations(Trace trace) {
		unloadBreakpointLocations(trace);
		loadBreakpointLocations(trace);
	}

	private void breakpointLocationAdded(TraceBreakpoint location) {
		locationTableModel.addItem(location);
	}

	private void breakpointLocationUpdated(TraceBreakpoint location) {
		locationTableModel.updateItem(location);
	}

	private void breakpointLocationsUpdated(Collection<TraceBreakpoint> locations) {
		locationTableModel.updateAllItems(locations);
	}

	private void breakpointLocationRemoved(TraceBreakpoint location) {
		locationTableModel.deleteItem(location);
	}

	private void doTrackTrace(Trace trace) {
		if (listenersByTrace.containsKey(trace)) {
			Msg.warn(this, "Already tracking trace breakpoints");
			return;
		}
		listenersByTrace.put(trace, new ForBreakpointLocationsTraceListener(trace));
		loadBreakpointLocations(trace);
	}

	private void doUntrackTrace(Trace trace) {
		ForBreakpointLocationsTraceListener l = listenersByTrace.remove(trace);
		if (l != null) { // Could be from close or recorder stop
			l.dispose();
			unloadBreakpointLocations(trace);
		}
	}

	protected void traceOpened(Trace trace) {
		doTrackTrace(trace);
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

		String namePrefix = "Breakpoints";
		breakpointTable.setAccessibleNamePrefix(namePrefix);
		breakpointFilterPanel.setAccessibleNamePrefix(namePrefix);

		JPanel locationPanel = new JPanel(new BorderLayout());
		locationTable = new GhidraTable(locationTableModel);
		locationTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		locationPanel.add(new JScrollPane(locationTable));
		locationFilterPanel = new GhidraTableFilterPanel<>(locationTable, locationTableModel);
		locationFilterPanel.setSecondaryFilter(filterLocationsBySelectedBreakpoints);
		locationPanel.add(locationFilterPanel, BorderLayout.SOUTH);
		mainPanel.setRightComponent(locationPanel);
		mainPanel.setResizeWeight(0.5);

		String locationsNamePrefix = "Breakpoint Locations";
		locationTable.setAccessibleNamePrefix(locationsNamePrefix);
		locationFilterPanel.setAccessibleNamePrefix(locationsNamePrefix);

		breakpointTable.getSelectionModel().addListSelectionListener(evt -> {
			List<LogicalBreakpointRow> sel = breakpointFilterPanel.getSelectedItems();
			// Do this first to prevent overriding context in event chain
			if (!sel.isEmpty()) {
				locationTable.clearSelection();
				locationTable.getSelectionManager().clearSavedSelection();
			}
			myActionContext = new DebuggerLogicalBreakpointsActionContext(sel);
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
			List<BreakpointLocationRow> sel = locationFilterPanel.getSelectedItems();
			// Do this first to avoid overriding context in event chain
			if (!sel.isEmpty()) {
				breakpointTable.clearSelection();
				breakpointTable.getSelectionManager().clearSavedSelection();
			}
			myActionContext = new DebuggerBreakpointLocationsActionContext(sel);
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
		TableColumn bptEnCol = bptColModel.getColumn(LogicalBreakpointTableColumns.STATE.ordinal());
		bptEnCol.setCellRenderer(new DebuggerBreakpointStateTableCellRenderer());
		bptEnCol.setCellEditor(new DebuggerBreakpointStateTableCellEditor<>(breakpointFilterPanel) {
			@Override
			protected State getToggledState(LogicalBreakpointRow row, State current) {
				boolean mapped = row.isMapped();
				if (!mapped) {
					tool.setStatusInfo("Breakpoint has no locations. Only toggling its bookmark.",
						true);
				}
				return current.getToggled(mapped);
			}
		});
		bptEnCol.setMaxWidth(24);
		bptEnCol.setMinWidth(24);
		TableColumn bptNameCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.NAME.ordinal());
		bptNameCol.setPreferredWidth(150);
		TableColumn bptAddrCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.ADDRESS.ordinal());
		bptAddrCol.setPreferredWidth(150);
		bptAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn bptImgCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.IMAGE.ordinal());
		bptImgCol.setPreferredWidth(100);
		TableColumn lenCol = bptColModel.getColumn(LogicalBreakpointTableColumns.LENGTH.ordinal());
		lenCol.setPreferredWidth(60);
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
		TableColumn kindCol = bptColModel.getColumn(LogicalBreakpointTableColumns.KINDS.ordinal());
		kindCol.setPreferredWidth(150);
		TableColumn locsCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.LOCATIONS.ordinal());
		locsCol.setPreferredWidth(20);
		TableColumn bptSleighCol =
			bptColModel.getColumn(LogicalBreakpointTableColumns.SLEIGH.ordinal());
		bptSleighCol.setMaxWidth(30);
		bptSleighCol.setMinWidth(30);

		GTableColumnModel locColModel = (GTableColumnModel) locationTable.getColumnModel();
		TableColumn locEnCol =
			locColModel.getColumn(BreakpointLocationTableColumns.STATE.ordinal());
		locEnCol.setCellRenderer(new DebuggerBreakpointStateTableCellRenderer());
		locEnCol.setCellEditor(new DebuggerBreakpointStateTableCellEditor<>(locationFilterPanel) {
			@Override
			protected State getToggledState(BreakpointLocationRow row, State current) {
				return current.getToggled(false);
			}
		});
		locEnCol.setMaxWidth(24);
		locEnCol.setMinWidth(24);
		TableColumn locAddrCol =
			locColModel.getColumn(BreakpointLocationTableColumns.ADDRESS.ordinal());
		locAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn locThreadsCol =
			locColModel.getColumn(BreakpointLocationTableColumns.THREADS.ordinal());
		TableColumn locSleighCol =
			locColModel.getColumn(BreakpointLocationTableColumns.SLEIGH.ordinal());
		locSleighCol.setMaxWidth(30);
		locSleighCol.setMinWidth(30);

		locColModel.setVisible(locThreadsCol, false);
		locColModel.setVisible(locSleighCol, false);

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
		listingService.goTo(row.getProgramLocation(), true);
	}

	protected void createActions() {
		actionSetBreakpoint = new SetBreakpointAction();
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

		actionSetCondition = SetEmulatedBreakpointConditionAction.builder(plugin)
				.popupWhen(this::isPopupSetCondition)
				.onAction(this::activatedSetCondition)
				.buildAndInstall(tool);
		actionSetInjection = SetEmulatedBreakpointInjectionAction.builder(plugin)
				.popupWhen(this::isPopupSetInjection)
				.onAction(this::activatedSetInjection)
				.buildAndInstall(tool);

		actionMakeBreakpointsEffectiveResolution = new MakeBreakpointsEffectiveResolutionAction();
	}

	private Collection<LogicalBreakpoint> getLogicalBreakpoints(ActionContext ctx) {
		if (ctx instanceof DebuggerLogicalBreakpointsActionContext lbCtx) {
			return lbCtx.getBreakpoints();
		}
		if (ctx instanceof ProgramLocationActionContext locCtx) {
			return breakpointService.getBreakpointsAt(locCtx.getLocation());
		}
		if (ctx.getContextObject() instanceof MarkerLocation ml) {
			return breakpointService
					.getBreakpointsAt(new ProgramLocation(ml.getProgram(), ml.getAddr()));
		}
		return null;
	}

	private boolean isAllInvolvedTracesUsingEmulatedBreakpoints(ActionContext ctx) {
		if (controlService == null) {
			return false;
		}
		Set<Trace> traces = new HashSet<>();
		Collection<LogicalBreakpoint> breakpoints = getLogicalBreakpoints(ctx);
		if (breakpoints != null) {
			if (breakpoints.isEmpty()) {
				return false;
			}
			for (LogicalBreakpoint lb : breakpoints) {
				traces.addAll(lb.getParticipatingTraces());
			}
		}
		else if (ctx instanceof DebuggerBreakpointLocationsActionContext locCtx) {
			Collection<TraceBreakpoint> locations = locCtx.getLocations();
			if (locations.isEmpty()) {
				return false;
			}
			for (TraceBreakpoint tb : locations) {
				traces.add(tb.getTrace());
			}
		}
		else {
			return false;
		}
		for (Trace trace : traces) {
			if (!controlService.getCurrentMode(trace).useEmulatedBreakpoints()) {
				return false;
			}
		}
		return true;
	}

	private static final Set<TraceBreakpointKind> EXECUTE_KINDS =
		Set.of(TraceBreakpointKind.SW_EXECUTE, TraceBreakpointKind.HW_EXECUTE);

	private boolean isAllBreakpointsExecution(ActionContext ctx) {
		// TODO GP-2988: Remove this. Implement injection on emu access breakpoints, too
		Collection<LogicalBreakpoint> breakpoints = getLogicalBreakpoints(ctx);
		if (breakpoints != null) {
			for (LogicalBreakpoint lb : breakpoints) {
				if (!EXECUTE_KINDS.containsAll(lb.getKinds())) {
					return false;
				}
			}
			return true;
		}
		else if (ctx instanceof DebuggerBreakpointLocationsActionContext locCtx) {
			for (TraceBreakpoint tb : locCtx.getLocations()) {
				if (!EXECUTE_KINDS.containsAll(tb.getKinds())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	private boolean isPopupSetCondition(ActionContext ctx) {
		return isAllInvolvedTracesUsingEmulatedBreakpoints(ctx) && isAllBreakpointsExecution(ctx);
	}

	private boolean isPopupSetInjection(ActionContext ctx) {
		return isAllInvolvedTracesUsingEmulatedBreakpoints(ctx) && isAllBreakpointsExecution(ctx);
	}

	private String deriveCurrentSleigh(ActionContext ctx) {
		String sleigh = null;
		Collection<LogicalBreakpoint> breakpoints = getLogicalBreakpoints(ctx);
		if (breakpoints != null) {
			for (LogicalBreakpoint lb : breakpoints) {
				String s = lb.getEmuSleigh();
				if (sleigh != null && !sleigh.equals(s)) {
					return null;
				}
				sleigh = s;
			}
			return sleigh;
		}
		else if (ctx instanceof DebuggerBreakpointLocationsActionContext locCtx) {
			for (TraceBreakpoint tb : locCtx.getLocations()) {
				String s = tb.getEmuSleigh();
				if (sleigh != null && !sleigh.equals(s)) {
					return null;
				}
				sleigh = s;
			}
			return sleigh;
		}
		return null;
	}

	private String deriveCurrentCondition(ActionContext ctx) {
		String sleigh = deriveCurrentSleigh(ctx);
		return sleigh == null ? null : SleighUtils.recoverConditionFromBreakpoint(sleigh);
	}

	private void injectSleigh(ActionContext ctx, String sleigh) {
		Collection<LogicalBreakpoint> breakpoints = getLogicalBreakpoints(ctx);
		if (breakpoints != null) {
			for (LogicalBreakpoint lb : breakpoints) {
				lb.setEmuSleigh(sleigh);
			}
		}
		else if (ctx instanceof DebuggerBreakpointLocationsActionContext locCtx) {
			for (TraceBreakpoint tb : locCtx.getLocations()) {
				tb.setEmuSleigh(sleigh);
			}
		}
		else {
			throw new AssertionError();
		}
	}

	private void activatedSetCondition(ActionContext ctx) {
		String curCondition = deriveCurrentCondition(ctx);
		if (curCondition == null) {
			curCondition = SleighUtils.CONDITION_ALWAYS;
		}
		String condition = DebuggerSleighExpressionInputDialog.INSTANCE.prompt(tool, curCondition);
		if (condition == null) {
			return; // Cancelled
		}
		injectSleigh(ctx, SleighUtils.sleighForConditionalBreak(condition));
	}

	private void activatedSetInjection(ActionContext ctx) {
		String curSleigh = deriveCurrentSleigh(ctx);
		if (curSleigh == null) {
			curSleigh = SleighUtils.UNCONDITIONAL_BREAK;
		}
		String sleigh = DebuggerSleighSemanticInputDialog.INSTANCE.prompt(tool, curSleigh);
		if (sleigh == null) {
			return; // Cancelled
		}
		injectSleigh(ctx, sleigh);
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
		consoleService.log(DebuggerResources.ICON_LOG_ERROR, message, ex);
	}
}
