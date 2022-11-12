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

import java.awt.Color;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.margin.LineNumberDecompilerMarginProvider;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.app.util.viewer.listingpanel.MarkerClickedListener;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;

@PluginInfo(
	shortDescription = "Debugger breakpoint marker service plugin",
	description = "Marks logical breakpoints and provides actions in the listings",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerLogicalBreakpointService.class,
		MarkerService.class,
	})
public class DebuggerBreakpointMarkerPlugin extends Plugin
		implements PopupActionProvider {

	protected static ProgramLocation getSingleLocationFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof DecompilerActionContext ctx) {
			// Use the token here, not the line
			if (!(ctx.getSourceComponent() instanceof LineNumberDecompilerMarginProvider) &&
				ctx.getTokenAtCursor() instanceof ClangVariableToken tok) {
				Varnode varnode = tok.getVarnode();
				Address address = varnode == null ? null : varnode.getAddress();
				if (address != null && address.isMemoryAddress()) {
					return new ProgramLocation(ctx.getProgram(), address);
				}
			}
		}
		if (context instanceof ProgramLocationActionContext ctx) {
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return new ProgramLocation(ctx.getProgram(), range.getMinAddress());
				}
			}
			return ctx.getLocation();
		}
		Object obj = context.getContextObject();
		if (obj instanceof MarkerLocation ml) {
			return new ProgramLocation(ml.getProgram(), ml.getAddr());
		}
		return null;
	}

	protected static List<Address> getAddressesFromLine(ClangLine line) {
		Set<Address> result = new TreeSet<>();
		for (int i = 0; i < line.getNumTokens(); i++) {
			ClangToken tok = line.getToken(i);
			if (tok instanceof ClangLabelToken) {
				continue;
			}
			if (tok instanceof ClangCommentToken) {
				/*
				 * Comment tokens should never have an address anyway, but sometimes the decompiler
				 * assigns the entry address to a warning comment that precedes the function header.
				 * This will filter that oddity.
				 */
				continue;
			}
			// Don't let line-wrapped calls display one breakpoint on all lines
			// NOTE: The call itself will be represented by the ClangFuncNameToken
			if (tok instanceof ClangVariableToken varTok &&
				varTok.getPcodeOp() != null && varTok.getPcodeOp().getOpcode() == PcodeOp.CALL) {
				continue;
			}
			if (tok instanceof ClangOpToken opTok &&
				opTok.getPcodeOp() != null && opTok.getPcodeOp().getOpcode() == PcodeOp.CALL) {
				continue;
			}
			// NOTE: I've seen no case where max != min
			Address min = tok.getMinAddress();
			if (min == null) {
				continue;
			}
			result.add(min);
		}
		return List.copyOf(result);
	}

	protected static List<ProgramLocation> getLocationsFromLine(Program program, ClangLine line) {
		List<ProgramLocation> result = new ArrayList<>();
		for (Address addr : getAddressesFromLine(line)) {
			result.add(new ProgramLocation(program, addr));
		}
		return result;
	}

	/**
	 * Find the nearest line, only looking forward, having an address and get its addresses wrapped
	 * in program locations
	 * 
	 * @param program the current program, for generating program locations
	 * @param index the index of the first line to consider, the current/context line
	 * @param lines the complete list of decompiled source lines of the current function
	 * @return the locations, or null if no such line is found
	 */
	protected static List<ProgramLocation> nearestLocationsToLine(Program program, int index,
			List<ClangLine> lines) {
		if (index < 0) {
			return null;
		}
		for (int n = index; n < lines.size(); n++) {
			ClangLine clangLine = lines.get(n);
			List<ProgramLocation> locs = getLocationsFromLine(program, clangLine);
			if (locs != null && !locs.isEmpty()) {
				return locs;
			}
		}
		return null;
	}

	/**
	 * Attempt to derive one or more locations from the given context
	 * 
	 * @param context a possible location context
	 * @return the program location, or {@code null}
	 */
	protected static List<ProgramLocation> getLocationsFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof DecompilerActionContext ctx) {
			int lineNumber = ctx.getLineNumber();
			// Return even if null, to prevent token from being used
			// Using the token might surprise the user, esp., if it's not on screen
			return nearestLocationsToLine(ctx.getProgram(), lineNumber - 1,
				ctx.getDecompilerPanel().getLines());
		}
		ProgramLocation loc = getSingleLocationFromContext(context);
		return loc == null ? null : List.of(loc);
	}

	protected static long computeLengthFromContext(ActionContext context) {
		if (context == null) {
			return 1;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return range.getLength();
				}
			}
			CodeUnit cu = ctx.getCodeUnit();
			if (cu instanceof Data) {
				return cu.getLength();
			}
		}
		return 1;
	}

	protected static boolean contextHasLocation(ActionContext context) {
		List<ProgramLocation> locs = getLocationsFromContext(context);
		return locs != null && !locs.isEmpty();
	}

	protected static Trace getTraceFromContext(ActionContext context) {
		List<ProgramLocation> locs = getLocationsFromContext(context);
		if (locs == null || locs.isEmpty()) {
			return null;
		}
		Program progOrView = locs.get(0).getProgram();
		if (progOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) progOrView;
			return view.getTrace();
		}
		return null;
	}

	protected static boolean contextHasTrace(ActionContext context) {
		return getTraceFromContext(context) != null;
	}

	protected static long computeDefaultLength(ActionContext context,
			Collection<TraceBreakpointKind> selected) {
		if (selected.isEmpty() ||
			selected.contains(TraceBreakpointKind.HW_EXECUTE) ||
			selected.contains(TraceBreakpointKind.SW_EXECUTE)) {
			return 1;
		}
		return computeLengthFromContext(context);
	}

	protected static Set<TraceBreakpointKind> computeDefaultKinds(ActionContext ctx,
			Collection<TraceBreakpointKind> supported) {
		if (supported.isEmpty()) {
			return Set.of();
		}
		long length = computeLengthFromContext(ctx);
		if (length == 1) {
			ProgramLocation loc = getSingleLocationFromContext(ctx);
			Listing listing = loc.getProgram().getListing();
			CodeUnit cu = listing.getCodeUnitContaining(loc.getAddress());
			if (cu instanceof Instruction) {
				if (supported.contains(TraceBreakpointKind.SW_EXECUTE)) {
					return Set.of(TraceBreakpointKind.SW_EXECUTE);
				}
				else if (supported.contains(TraceBreakpointKind.HW_EXECUTE)) {
					return Set.of(TraceBreakpointKind.HW_EXECUTE);
				}
				return Set.of();
			}
			Data data = (Data) cu;
			if (!data.isDefined()) {
				if (supported.size() == 1) {
					return Set.copyOf(supported);
				}
				return Set.of();
			}
		}
		// TODO: Consider memory protections?
		Set<TraceBreakpointKind> result =
			new HashSet<>(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
		result.retainAll(supported);
		return result;
	}

	protected Color colorForState(State state) {
		return state.isEnabled()
				? state.isEffective()
						? breakpointEnabledMarkerColor
						: breakpointIneffEnMarkerColor
				: state.isEffective()
						? breakpointDisabledMarkerColor
						: breakpointIneffDisMarkerColor;
	}

	protected boolean stateColorsBackground(State state) {
		return state.isEnabled()
				? state.isEffective()
						? breakpointEnabledColoringBackground
						: breakpointIneffEnColoringBackground
				: state.isEffective()
						? breakpointDisabledColoringBackground
						: breakpointIneffDisColoringBackground;
	}

	protected static class DualMarkerSet {
		private static final String SUFFIX = " (Point)";
		final MarkerSet area;
		final MarkerSet point;

		public DualMarkerSet(MarkerService service, String name, String description,
				Program program,
				int priority, boolean showMarks, boolean showNavigation, boolean colorBackground,
				Color color, Icon icon, boolean preferred) {
			MarkerSet areaExisting = service.getMarkerSet(name, program);
			if (areaExisting != null) {
				area = areaExisting;
			}
			else {
				area = service.createAreaMarker(name, description, program, priority - 1, showMarks,
					showNavigation, colorBackground, color, preferred);
			}
			MarkerSet pointExisting = service.getMarkerSet(name + SUFFIX, program);
			if (pointExisting != null) {
				point = pointExisting;
			}
			else {
				point = service.createPointMarker(name + SUFFIX, description, program, priority,
					showMarks, showNavigation, false, color, icon, preferred);
			}
		}

		public void add(Address start, Address end) {
			area.add(start, end);
			point.add(start);
		}

		public void clearAll() {
			area.clearAll();
			point.clearAll();
		}

		public void setMarkerColor(Color color) {
			area.setMarkerColor(color);
			point.setMarkerColor(color);
		}

		public void setColoringBackground(boolean coloringBackground) {
			area.setColoringBackground(coloringBackground);
			// point never colors background
		}

		public void remove(MarkerService service, Program program) {
			service.removeMarker(area, program);
			service.removeMarker(point, program);
		}
	}

	/**
	 * A variety of marker sets (one for each logical state) attached to a program or trace view
	 */
	protected class BreakpointMarkerSets {
		final Program program;

		final Map<State, DualMarkerSet> sets = new HashMap<>();

		protected BreakpointMarkerSets(Program program) {
			this.program = program;

			// Prevent default bookmark icons from obscuring breakpoints
			if (!(program instanceof TraceProgramView)) {
				BookmarkManager manager = program.getBookmarkManager();
				manager.defineType(LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					MarkerService.BREAKPOINT_PRIORITY - 1);
				manager.defineType(LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					MarkerService.BREAKPOINT_PRIORITY - 1);
			}

			for (State state : State.values()) {
				getMarkerSet(state);
			}
		}

		DualMarkerSet getMarkerSet(State state) {
			return sets.computeIfAbsent(state, this::doGetMarkerSet);
		}

		DualMarkerSet doGetMarkerSet(State state) {
			if (state.icon == null) {
				return null;
			}
			return new DualMarkerSet(markerService, state.display, state.display, program,
				MarkerService.BREAKPOINT_PRIORITY, true, true, stateColorsBackground(state),
				colorForState(state), state.icon, true);
		}

		public void setEnabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setDisabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setIneffectiveEnabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setIneffectiveDisabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setEnabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setDisabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveEnabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveDisabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void dispose() {
			for (State state : State.values()) {
				DualMarkerSet set = sets.get(state);
				if (set != null) {
					set.remove(markerService, program);
				}
			}
		}

		public void clear() {
			for (State state : State.values()) {
				DualMarkerSet set = sets.get(state);
				if (set != null) {
					set.clearAll();
				}
			}
		}
	}

	private class UpdateMarksBreakpointRecordChangeListener
			implements LogicalBreakpointsChangeListener {
		@Override
		public void breakpointAdded(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}

		@Override
		public void breakpointUpdated(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}

		@Override
		public void breakpointRemoved(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}
	}

	private class ToggleBreakpointsMarkerClickedListener implements MarkerClickedListener {
		@Override
		public void markerDoubleClicked(MarkerLocation location) {
			ProgramLocationActionContext context =
				new ProgramLocationActionContext(null, location.getProgram(),
					new ProgramLocation(location.getProgram(), location.getAddr()), null, null);
			if (contextCanManipulateBreakpoints(context)) {
				doToggleBreakpointsAt(ToggleBreakpointAction.NAME, context);
			}
		}
	}

	protected static State computeState(LogicalBreakpoint breakpoint, Program programOrView) {
		if (programOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) programOrView;
			return breakpoint.computeStateForTrace(view.getTrace());
		}
		// Program view should consider all trace placements
		// TODO: A mode for only considering the current trace (for effectiveness in program)
		return breakpoint.computeState();
	}

	protected Set<LogicalBreakpoint> collectBreakpoints(Collection<ProgramLocation> locs) {
		return locs.stream()
				.flatMap(l -> breakpointService.getBreakpointsAt(l).stream())
				.collect(Collectors.toSet());
	}

	protected State computeState(List<ProgramLocation> locs) {
		if (locs.isEmpty()) {
			return State.NONE;
		}
		Set<LogicalBreakpoint> col = collectBreakpoints(locs);
		return breakpointService.computeState(col, locs.get(0));
	}

	protected class ToggleBreakpointAction extends AbstractToggleBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public ToggleBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			doToggleBreakpointsAt(NAME, context);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			return true;
		}
	}

	protected class SetBreakpointAction extends AbstractSetBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		private final Set<TraceBreakpointKind> kinds;

		public SetBreakpointAction(Set<TraceBreakpointKind> kinds) {
			super(DebuggerBreakpointMarkerPlugin.this);
			this.kinds = kinds;
			setPopupMenuData(new MenuData(
				new String[] { NAME, TraceBreakpointKindSet.encode(kinds) }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			ProgramLocation location = getSingleLocationFromContext(context);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, NAME, location, length, kinds,
				"");
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation loc = getSingleLocationFromContext(context);
			if (!(loc.getProgram() instanceof TraceProgramView)) {
				return true;
			}
			TraceRecorder recorder = getRecorderFromContext(context);
			if (recorder == null) {
				return false;
			}
			if (!recorder.getSupportedBreakpointKinds().containsAll(kinds)) {
				return false;
			}
			return true;
		}
	}

	protected class EnableBreakpointAction extends AbstractEnableBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public EnableBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			Set<LogicalBreakpoint> col = collectBreakpoints(locs);
			Trace trace = getTraceFromContext(context);
			String status = breakpointService.generateStatusEnable(col, trace);
			if (status != null) {
				tool.setStatusInfo(status, true);
			}
			breakpointService.enableAll(col, trace).exceptionally(ex -> {
				breakpointError(NAME, "Could not enable breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			State state = computeState(locs);
			if (state == State.ENABLED || state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	protected class DisableBreakpointAction extends AbstractDisableBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public DisableBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			Set<LogicalBreakpoint> col = collectBreakpoints(locs);
			breakpointService.disableAll(col, getTraceFromContext(context)).exceptionally(ex -> {
				breakpointError(NAME, "Could not disable breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			State state = computeState(locs);
			if (state == State.DISABLED || state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	// TODO: Make sub-menu listing all breakpoints present here?
	// TODO:     If so, include a "remove all" (at this address) action
	protected class ClearBreakpointAction extends AbstractClearBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public ClearBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			Set<LogicalBreakpoint> col = collectBreakpoints(locs);
			breakpointService.deleteAll(col, getTraceFromContext(context)).exceptionally(ex -> {
				breakpointError(NAME, "Could not delete breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			List<ProgramLocation> locs = getLocationsFromContext(context);
			State state = computeState(locs);
			if (state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	// @AutoServiceConsumed via method
	private MarkerService markerService;
	// @AutoServiceConsumed via method
	DebuggerLogicalBreakpointService breakpointService;
	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	// @AutoServiceConsumed via method
	DecompilerMarginService decompilerMarginService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an enabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointEnabledMarkerColor =
		DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an enabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointEnabledColoringBackground =
		DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_MARKERS, //
		description = "Background color for memory at a disabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointDisabledMarkerColor =
		DebuggerResources.DEFAULT_COLOR_DISABLED_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at a disabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointDisabledColoringBackground =
		DebuggerResources.DEFAULT_COLOR_DISABLED_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffEnMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFF_EN_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffEnColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffDisMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFF_DIS_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffDisColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final Map<Program, BreakpointMarkerSets> markersByProgram = new HashMap<>();

	private final LogicalBreakpointsChangeListener updateMarksListener =
		new UpdateMarksBreakpointRecordChangeListener();
	private final MarkerClickedListener markerClickedListener =
		new ToggleBreakpointsMarkerClickedListener();

	private final AsyncDebouncer<Void> updateDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 50);

	// package access for testing
	SetBreakpointAction actionSetSoftwareBreakpoint;
	SetBreakpointAction actionSetExecuteBreakpoint;
	SetBreakpointAction actionSetReadWriteBreakpoint;
	SetBreakpointAction actionSetReadBreakpoint;
	SetBreakpointAction actionSetWriteBreakpoint;
	ToggleBreakpointAction actionToggleBreakpoint;
	EnableBreakpointAction actionEnableBreakpoint;
	DisableBreakpointAction actionDisableBreakpoint;
	ClearBreakpointAction actionClearBreakpoint;

	DebuggerPlaceBreakpointDialog placeBreakpointDialog = new DebuggerPlaceBreakpointDialog();

	BreakpointsDecompilerMarginProvider decompilerMarginProvider;

	public DebuggerBreakpointMarkerPlugin(PluginTool tool) {
		super(tool);
		this.decompilerMarginProvider = new BreakpointsDecompilerMarginProvider(this);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.autoOptionsWiring = AutoOptions.wireOptions(this);

		updateDebouncer.addListener(__ -> SwingUtilities.invokeLater(() -> updateAllMarks()));

		tool.addPopupActionProvider(this);
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_MARKERS)
	private void setEnabledBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setEnabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND)
	private void setEnabledBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setEnabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_MARKERS)
	private void setDisabledBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setDisabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND)
	private void setDisabledBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setDisabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_MARKERS)
	private void setIneffectiveEBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND)
	private void setIneffectiveEBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_MARKERS)
	private void setIneffectiveDBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveDisabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND)
	private void setIneffectiveDBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveDisabledColoringBackground(breakpointColoringBackground);
		}
	}

	protected TraceRecorder getRecorderFromContext(ActionContext context) {
		if (modelService == null) {
			return null;
		}
		Trace trace = getTraceFromContext(context);
		return modelService.getRecorder(trace);
	}

	protected Set<TraceRecorder> getRecordersFromContext(ActionContext context) {
		TraceRecorder single = getRecorderFromContext(context);
		if (single != null) {
			return Set.of(single);
		}
		if (mappingService == null || modelService == null) {
			return Set.of();
		}
		ProgramLocation loc = getSingleLocationFromContext(context);
		if (loc == null || loc.getProgram() instanceof TraceProgramView) {
			return Set.of();
		}
		Set<TraceLocation> mappedLocs = mappingService.getOpenMappedLocations(loc);
		if (mappedLocs == null || mappedLocs.isEmpty()) {
			return Set.of();
		}
		Set<TraceRecorder> result = new HashSet<>();
		for (TraceLocation tloc : mappedLocs) {
			TraceRecorder rec = modelService.getRecorder(tloc.getTrace());
			if (rec != null) {
				result.add(rec);
			}
		}
		return result;
	}

	protected boolean contextHasRecorder(ActionContext ctx) {
		return getRecorderFromContext(ctx) != null;
	}

	protected boolean contextCanManipulateBreakpoints(ActionContext ctx) {
		if (breakpointService == null) {
			return false;
		}
		if (!contextHasLocation(ctx)) {
			return false;
		}
		// Programs, or live traces, but not dead traces
		if (contextHasTrace(ctx) && !contextHasRecorder(ctx)) {
			return false;
		}
		return true;
	}

	protected Set<TraceBreakpointKind> getSupportedKindsFromContext(ActionContext context) {
		Set<TraceRecorder> recorders = getRecordersFromContext(context);
		if (recorders.isEmpty()) {
			return EnumSet.allOf(TraceBreakpointKind.class);
		}
		return recorders.stream()
				.flatMap(rec -> rec.getSupportedBreakpointKinds().stream())
				.collect(Collectors.toSet());
	}

	protected void doToggleBreakpointsAt(String title, ActionContext context) {
		if (breakpointService == null) {
			return;
		}
		List<ProgramLocation> locs = getLocationsFromContext(context);
		if (locs == null || locs.isEmpty()) {
			return;
		}
		Set<LogicalBreakpoint> col = collectBreakpoints(locs);
		ProgramLocation loc = locs.get(0);
		String status = breakpointService.generateStatusToggleAt(col, loc);
		if (status != null) {
			tool.setStatusInfo(status, true);
		}
		breakpointService.toggleBreakpointsAt(col, loc, () -> {
			Set<TraceBreakpointKind> supported = getSupportedKindsFromContext(context);
			if (supported.isEmpty()) {
				breakpointError(title, "It seems this target does not support breakpoints.");
				return CompletableFuture.completedFuture(Set.of());
			}
			Set<TraceBreakpointKind> kinds = computeDefaultKinds(context, supported);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, title, loc, length, kinds,
				"");
			// Not great, but I'm not sticking around for the dialog
			return CompletableFuture.completedFuture(Set.of());
		}).exceptionally(ex -> {
			breakpointError(title, "Could not toggle breakpoints", ex);
			return null;
		});
	}

	/**
	 * Instantiate a marker set for the given program or trace view
	 * 
	 * @param program the (static) program or (dynamic) trace view
	 * @return the marker sets
	 */
	protected BreakpointMarkerSets createMarkers(Program program) {
		synchronized (markersByProgram) {
			BreakpointMarkerSets newSets = new BreakpointMarkerSets(program);
			BreakpointMarkerSets oldSets = markersByProgram.put(program, newSets);
			assert oldSets == null;
			return newSets;
		}
	}

	protected void removeMarkers(Program program) {
		synchronized (markersByProgram) {
			BreakpointMarkerSets oldSets = markersByProgram.remove(program);
			oldSets.dispose();
		}
	}

	protected void doMarks(BreakpointMarkerSets marks,
			Map<Address, Set<LogicalBreakpoint>> byAddress,
			java.util.function.Function<LogicalBreakpoint, State> stateFunc) {
		for (Map.Entry<Address, Set<LogicalBreakpoint>> bEnt : byAddress.entrySet()) {
			Map<Long, State> byLength = new HashMap<>();
			for (LogicalBreakpoint lb : bEnt.getValue()) {
				byLength.compute(lb.getLength(), (l, e) -> (e == null ? State.NONE : e)
						.sameAdddress(stateFunc.apply(lb)));
			}
			Address start = bEnt.getKey();
			for (Map.Entry<Long, State> sEnt : byLength.entrySet()) {
				Address end = start.add(sEnt.getKey() - 1);
				DualMarkerSet set = marks.getMarkerSet(sEnt.getValue());
				if (set != null) {
					set.add(start, end);
				}
			}
		}
	}

	protected void updateAllMarks() {
		synchronized (markersByProgram) {
			for (BreakpointMarkerSets markerSet : markersByProgram.values()) {
				markerSet.clear();
			}
			if (breakpointService == null) {
				return;
			}
			for (Map.Entry<Program, BreakpointMarkerSets> pEnt : markersByProgram.entrySet()) {
				Program program = pEnt.getKey();
				BreakpointMarkerSets marks = pEnt.getValue();
				if (program instanceof TraceProgramView) {
					TraceProgramView view = (TraceProgramView) program;
					Trace trace = view.getTrace();
					doMarks(marks, breakpointService.getBreakpoints(trace),
						lb -> lb.computeStateForTrace(trace));
				}
				else {
					doMarks(marks, breakpointService.getBreakpoints(program),
						lb -> lb.computeStateForProgram(program));
				}
			}
		}
	}

	@AutoServiceConsumed
	private void setMarkerService(MarkerService markerService) {
		if (this.markerService != null) {
			this.markerService.setMarkerClickedListener(null);
		}
		this.markerService = markerService;
		if (this.markerService != null) {
			this.markerService.setMarkerClickedListener(markerClickedListener);
		}
	}

	@AutoServiceConsumed
	private void setLogicalBreakpointService(DebuggerLogicalBreakpointService breakpointService) {
		if (this.breakpointService != null) {
			this.breakpointService.removeChangeListener(updateMarksListener);
		}
		this.breakpointService = breakpointService;
		if (this.breakpointService != null) {
			breakpointService.addChangeListener(updateMarksListener);
			updateAllMarks();
		}
	}

	@AutoServiceConsumed
	private void setDecompilerMarginService(DecompilerMarginService decompilerMarginService) {
		if (this.decompilerMarginService != null) {
			this.decompilerMarginService.removeMarginProvider(decompilerMarginProvider);
		}
		this.decompilerMarginService = decompilerMarginService;
		if (this.decompilerMarginService != null) {
			this.decompilerMarginService.addMarginProvider(decompilerMarginProvider);
		}
	}

	protected void createActions() {
		actionSetSoftwareBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.SW_EXECUTE));
		actionSetExecuteBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.HW_EXECUTE));
		actionSetReadWriteBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
		actionSetReadBreakpoint = new SetBreakpointAction(Set.of(TraceBreakpointKind.READ));
		actionSetWriteBreakpoint = new SetBreakpointAction(Set.of(TraceBreakpointKind.WRITE));
		actionToggleBreakpoint = new ToggleBreakpointAction();
		actionEnableBreakpoint = new EnableBreakpointAction();
		actionDisableBreakpoint = new DisableBreakpointAction();
		actionClearBreakpoint = new ClearBreakpointAction();

		tool.setMenuGroup(new String[] { SetBreakpointAction.NAME }, SetBreakpointAction.GROUP);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool __, ActionContext context) {
		return List.of(); // TODO: Actions by individual breakpoint?
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent evt = (ProgramOpenedPluginEvent) event;
			createMarkers(evt.getProgram());
			updateAllMarks();
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent evt = (ProgramClosedPluginEvent) event;
			removeMarkers(evt.getProgram());
		}
		else if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent evt = (TraceOpenedPluginEvent) event;
			TraceProgramView view = evt.getTrace().getProgramView();
			createMarkers(view);
			updateAllMarks();
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
			Trace trace = evt.getTrace();
			Map<Program, BreakpointMarkerSets> copyOfMarkers;
			synchronized (markersByProgram) {
				copyOfMarkers = Map.copyOf(markersByProgram);
			}
			for (Map.Entry<Program, BreakpointMarkerSets> ent : copyOfMarkers.entrySet()) {
				Program program = ent.getKey();
				if (!(program instanceof TraceProgramView)) {
					continue;
				}
				TraceProgramView view = (TraceProgramView) program;
				if (view.getTrace() != trace) {
					continue;
				}
				removeMarkers(view);
			}
		}
	}

	protected void breakpointError(String title, String message) {
		if (consoleService == null) {
			Msg.showError(this, null, title, message);
			return;
		}
		consoleService.log(DebuggerResources.ICON_LOG_ERROR, message);
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
