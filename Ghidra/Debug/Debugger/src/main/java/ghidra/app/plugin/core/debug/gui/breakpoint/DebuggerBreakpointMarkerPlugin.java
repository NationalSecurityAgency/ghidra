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
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.app.util.viewer.listingpanel.MarkerClickedListener;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
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

	protected static Address computeAddressFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return range.getMinAddress();
				}
			}
			return ctx.getAddress();
		}
		Object obj = context.getContextObject();
		if (obj instanceof MarkerLocation) {
			MarkerLocation ml = (MarkerLocation) obj;
			return ml.getAddr();
		}
		return null;
	}

	/**
	 * Attempt to derive a location from the given context
	 * 
	 * <p>
	 * Currently, this supports {@link ProgramLocationActionContext} and {@link MarkerLocation}.
	 * 
	 * @param context a possible location context
	 * @return the program location, or {@code null}
	 */
	protected static ProgramLocation getLocationFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
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
		if (obj instanceof MarkerLocation) {
			MarkerLocation ml = (MarkerLocation) obj;
			return new ProgramLocation(ml.getProgram(), ml.getAddr());
		}
		return null;
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
		return getLocationFromContext(context) != null;
	}

	protected static Trace getTraceFromContext(ActionContext context) {
		ProgramLocation loc = getLocationFromContext(context);
		if (loc == null) {
			return null;
		}
		Program progOrView = loc.getProgram();
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
			ProgramLocation loc = getLocationFromContext(ctx);
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

	/**
	 * A variety of marker sets (one for each logical state) attached to a program or trace view
	 */
	protected class BreakpointMarkerSets {
		final Program program;

		final MarkerSet enabled;
		final MarkerSet disabled;
		final MarkerSet ineffectiveE;
		final MarkerSet ineffectiveD;
		final MarkerSet mixedED;
		final MarkerSet mixedDE;

		protected BreakpointMarkerSets(Program program) {
			this.program = program;

			// Prevent default bookmark icons from obscuring breakpoints
			if (!(program instanceof TraceProgramView)) {
				BookmarkManager manager = program.getBookmarkManager();
				manager.defineType(LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					DebuggerResources.PRIORITY_BREAKPOINT_ENABLED_MARKER - 1);
				manager.defineType(LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					DebuggerResources.PRIORITY_BREAKPOINT_DISABLED_MARKER - 1);
			}

			enabled = getEnabledMarkerSet();
			disabled = getDisabledMarkerSet();
			ineffectiveE = getIneffectiveEMarkerSet();
			ineffectiveD = getIneffectiveDMarkerSet();
			mixedED = getMixedEDMarkerSet();
			mixedDE = getMixedDEMarkerSet();
		}

		private MarkerSet getEnabledMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_ENABLED, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_ENABLED,
				DebuggerResources.MARKER_NAME_BREAKPOINT_ENABLED, program,
				DebuggerResources.PRIORITY_BREAKPOINT_ENABLED_MARKER, true, true, true,
				breakpointEnabledMarkerColor, DebuggerResources.ICON_BREAKPOINT_ENABLED_MARKER,
				true);
		}

		private MarkerSet getDisabledMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_DISABLED, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_DISABLED,
				DebuggerResources.MARKER_NAME_BREAKPOINT_DISABLED, program,
				DebuggerResources.PRIORITY_BREAKPOINT_DISABLED_MARKER, true, false, false,
				breakpointEnabledMarkerColor, DebuggerResources.ICON_BREAKPOINT_DISABLED_MARKER,
				false);
		}

		private MarkerSet getIneffectiveEMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_E, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_E,
				DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_E, program,
				DebuggerResources.PRIORITY_BREAKPOINT_INEFFECTIVE_E_MARKER, true, false, true,
				breakpointIneffectiveEMarkerColor,
				DebuggerResources.ICON_BREAKPOINT_INEFFECTIVE_E_MARKER,
				false);
		}

		private MarkerSet getIneffectiveDMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_D, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_D,
				DebuggerResources.MARKER_NAME_BREAKPOINT_INEFFECTIVE_D, program,
				DebuggerResources.PRIORITY_BREAKPOINT_INEFFECTIVE_D_MARKER, true, false, false,
				breakpointIneffectiveDMarkerColor,
				DebuggerResources.ICON_BREAKPOINT_INEFFECTIVE_D_MARKER,
				false);
		}

		private MarkerSet getMixedEDMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_ED, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_ED,
				DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_ED, program,
				DebuggerResources.PRIORITY_BREAKPOINT_MIXED_ED_MARKER, true, true, true,
				breakpointEnabledMarkerColor, DebuggerResources.ICON_BREAKPOINT_MIXED_ED_MARKER,
				false);
		}

		private MarkerSet getMixedDEMarkerSet() {
			MarkerSet set = markerService
					.getMarkerSet(DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_DE, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(
				DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_DE,
				DebuggerResources.MARKER_NAME_BREAKPOINT_MIXED_DE, program,
				DebuggerResources.PRIORITY_BREAKPOINT_MIXED_DE_MARKER, true, false, false,
				breakpointEnabledMarkerColor, DebuggerResources.ICON_BREAKPOINT_MIXED_DE_MARKER,
				false);
		}

		MarkerSet get(Enablement en) {
			switch (en) {
				case ENABLED:
					return enabled;
				case DISABLED:
					return disabled;
				case INEFFECTIVE_ENABLED:
					return ineffectiveE;
				case INEFFECTIVE_DISABLED:
					return ineffectiveD;
				case ENABLED_DISABLED:
					return mixedED;
				case DISABLED_ENABLED:
					return mixedDE;
				case NONE:
					return null;
				default:
					throw new AssertionError();
			}
		}

		public void setEnabledMarkerColor(Color color) {
			if (enabled != null) {
				enabled.setMarkerColor(color);
			}
			if (mixedED != null) {
				mixedED.setMarkerColor(color);
			}
		}

		public void setDisabledMarkerColor(Color color) {
			if (disabled != null) {
				disabled.setMarkerColor(color);
			}
			if (mixedDE != null) {
				mixedDE.setMarkerColor(color);
			}
		}

		public void setIneffectiveEnabledMarkerColor(Color color) {
			if (ineffectiveE != null) {
				ineffectiveE.setMarkerColor(color);
			}
		}

		public void setIneffectiveDisabledMarkerColor(Color color) {
			if (ineffectiveD != null) {
				ineffectiveD.setMarkerColor(color);
			}
		}

		public void setEnabledColoringBackground(boolean coloringBackground) {
			if (enabled != null) {
				enabled.setColoringBackground(coloringBackground);
			}
			if (mixedED != null) {
				mixedED.setColoringBackground(coloringBackground);
			}
		}

		public void setDisabledColoringBackground(boolean coloringBackground) {
			if (disabled != null) {
				disabled.setColoringBackground(coloringBackground);
			}
			if (mixedDE != null) {
				mixedDE.setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveEnabledColoringBackground(boolean coloringBackground) {
			if (ineffectiveE != null) {
				ineffectiveE.setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveDisabledColoringBackground(boolean coloringBackground) {
			if (ineffectiveD != null) {
				ineffectiveD.setColoringBackground(coloringBackground);
			}
		}

		public void dispose() {
			if (enabled != null) {
				markerService.removeMarker(enabled, program);
			}
			if (disabled != null) {
				markerService.removeMarker(disabled, program);
			}
			if (ineffectiveE != null) {
				markerService.removeMarker(ineffectiveE, program);
			}
			if (ineffectiveD != null) {
				markerService.removeMarker(ineffectiveD, program);
			}
			if (mixedED != null) {
				markerService.removeMarker(mixedED, program);
			}
			if (mixedDE != null) {
				markerService.removeMarker(mixedDE, program);
			}
		}

		public void clear() {
			if (enabled != null) {
				enabled.clearAll();
			}
			if (disabled != null) {
				disabled.clearAll();
			}
			if (ineffectiveE != null) {
				ineffectiveE.clearAll();
			}
			if (ineffectiveD != null) {
				ineffectiveD.clearAll();
			}
			if (mixedED != null) {
				mixedED.clearAll();
			}
			if (mixedDE != null) {
				mixedDE.clearAll();
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
			doToggleBreakpointsAt(ToggleBreakpointAction.NAME,
				new ProgramLocationActionContext(null, location.getProgram(),
					new ProgramLocation(location.getProgram(), location.getAddr()), null, null));
		}
	}

	protected static Enablement computeEnablement(LogicalBreakpoint breakpoint,
			Program programOrView) {
		if (programOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) programOrView;
			return breakpoint.computeEnablementForTrace(view.getTrace());
		}
		// Program view should consider all trace placements
		// TODO: A mode for only considering the current trace (for effectiveness in program)
		return breakpoint.computeEnablement();
	}

	/**
	 * TODO: Document me
	 * 
	 * <p>
	 * This is a little different from that in the breakpoint service.
	 * 
	 * @param loc
	 * @return
	 */
	protected Enablement computeEnablement(ProgramLocation loc) {
		Program programOrView = loc.getProgram();
		if (programOrView instanceof TraceProgramView) {
			return breakpointService.computeEnablement(loc).getPrimary();
		}
		// Program view should consider all trace breakpoints, too
		// breakpointService.computeEnablement(loc) only considers program breakpoint
		Set<LogicalBreakpoint> bs = breakpointService.getBreakpointsAt(loc);
		return breakpointService.computeEnablement(bs);
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
			ProgramLocation location = getLocationFromContext(context);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, NAME, location, length, kinds);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation loc = getLocationFromContext(context);
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
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
			breakpointService.enableAll(col, getTraceFromContext(context)).exceptionally(ex -> {
				breakpointError(NAME, "Could not enable breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation location = getLocationFromContext(context);
			Enablement en = computeEnablement(location);
			if (en == Enablement.ENABLED || en == Enablement.NONE) {
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
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
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
			ProgramLocation location = getLocationFromContext(context);
			Enablement en = computeEnablement(location);
			if (en == Enablement.DISABLED || en == Enablement.NONE) {
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
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
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
			ProgramLocation location = getLocationFromContext(context);
			Enablement en = computeEnablement(location);
			if (en == Enablement.NONE) {
				return false;
			}
			return true;
		}
	}

	// @AutoServiceConsumed via method
	private MarkerService markerService;
	// @AutoServiceConsumed via method
	private DebuggerLogicalBreakpointService breakpointService;
	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
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
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffectiveEMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFFECTIVE_E_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffectiveEColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFFECTIVE_E_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffectiveDMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFFECTIVE_D_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffectiveDColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFFECTIVE_D_BREAKPOINT_COLORING_BACKGROUND;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final Map<Program, BreakpointMarkerSets> markersByProgram = new HashMap<>();

	private final LogicalBreakpointsChangeListener updateMarksListener =
		new UpdateMarksBreakpointRecordChangeListener();
	private final MarkerClickedListener markerClickedListener =
		new ToggleBreakpointsMarkerClickedListener();

	private final AsyncDebouncer<Void> updateDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);

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

	public DebuggerBreakpointMarkerPlugin(PluginTool tool) {
		super(tool);
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
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_MARKERS)
	private void setIneffectiveEBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_COLORING_BACKGROUND)
	private void setIneffectiveEBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_MARKERS)
	private void setIneffectiveDBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveDisabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_COLORING_BACKGROUND)
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
		ProgramLocation loc = getLocationFromContext(context); // must be static location
		if (loc == null) {
			return Set.of();
		}
		Set<TraceRecorder> result = new HashSet<>();
		for (TraceLocation tloc : mappingService.getOpenMappedLocations(loc)) {
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
		// TODO: Seems like this should be in logical breakpoint service?
		if (breakpointService == null) {
			return;
		}
		ProgramLocation loc = getLocationFromContext(context);
		if (loc == null) {
			return;
		}
		Set<LogicalBreakpoint> bs = breakpointService.getBreakpointsAt(loc);
		if (bs == null || bs.isEmpty()) {
			Set<TraceBreakpointKind> supported = getSupportedKindsFromContext(context);
			if (supported.isEmpty()) {
				breakpointError(title, "It seems this target does not support breakpoints.");
				return;
			}
			Set<TraceBreakpointKind> kinds = computeDefaultKinds(context, supported);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, title, loc, length, kinds);
			return;
		}
		Enablement en = breakpointService.computeEnablement(bs, loc);
		/**
		 * If we're in the static listing, this will return null, indicating we should use the
		 * program's perspective. The methods taking trace should accept a null trace and behave
		 * accordingly. If in the dynamic listing, we act in the context of the returned trace.
		 */
		Trace trace = getTraceFromContext(context);
		boolean mapped = breakpointService.anyMapped(bs, trace);
		Enablement toggled = en.getToggled(mapped);
		if (toggled.enabled) {
			breakpointService.enableAll(bs, trace).exceptionally(ex -> {
				breakpointError(title, "Could not enable breakpoints", ex);
				return null;
			});
		}
		else {
			breakpointService.disableAll(bs, trace).exceptionally(ex -> {
				breakpointError(title, "Could not disable breakpoints", ex);
				return null;
			});
		}
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
			java.util.function.Function<LogicalBreakpoint, Enablement> enFunc) {
		for (Map.Entry<Address, Set<LogicalBreakpoint>> bEnt : byAddress.entrySet()) {
			Map<Long, Enablement> en = new HashMap<>();
			for (LogicalBreakpoint lb : bEnt.getValue()) {
				en.compute(lb.getLength(), (l, e) -> (e == null ? Enablement.NONE : e)
						.sameAdddress(enFunc.apply(lb)));
			}
			Address start = bEnt.getKey();
			for (Map.Entry<Long, Enablement> eEnt : en.entrySet()) {
				Address end = start.add(eEnt.getKey() - 1);
				MarkerSet set = marks.get(eEnt.getValue());
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
						lb -> lb.computeEnablementForTrace(trace));
				}
				else {
					doMarks(marks, breakpointService.getBreakpoints(program),
						lb -> lb.computeEnablementForProgram(program));
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
