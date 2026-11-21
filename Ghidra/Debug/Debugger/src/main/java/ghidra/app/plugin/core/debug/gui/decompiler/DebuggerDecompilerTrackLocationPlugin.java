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
package ghidra.app.plugin.core.debug.gui.decompiler;

import java.awt.Color;
import java.util.Set;

import javax.swing.Icon;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TrackingChangedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.action.DebuggerTrackLocationTrait;
import ghidra.app.services.*;
import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;

/**
 * Marks the tracked location, e.g., the program counter, in the Decompiler
 *
 * <p>
 * The location is tracked the same way as in the primary dynamic listing, and follows that
 * listing's "Track Location" setting. The location is mapped into the static program and marked
 * independently of the Decompiler's cursor: the tokens of the instruction at the location get the
 * tracked-register background, and their lines get the tracked-register icon in the Debugger's
 * {@link DebuggerDecompilerMarginService margin}.
 */
@PluginInfo(
	shortDescription = "Debugger tracked location in the Decompiler",
	description = "Marks the tracked location, e.g., the program counter, in the Decompiler",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TrackingChangedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerStaticMappingService.class,
		DebuggerDecompilerMarginService.class,
	})
public class DebuggerDecompilerTrackLocationPlugin extends Plugin {
	static final String HIGHLIGHTER_ID = DebuggerDecompilerTrackLocationPlugin.class.getName();
	static final Color COLOR_TRACKED = DebuggerResources.COLOR_REGISTER_MARKERS;
	static final Icon ICON_TRACKED = DebuggerResources.ICON_REGISTER_MARKER;

	private class ForDecompilerTrackLocationTrait extends DebuggerTrackLocationTrait {
		ForDecompilerTrackLocationTrait() {
			super(DebuggerDecompilerTrackLocationPlugin.this.getTool(),
				DebuggerDecompilerTrackLocationPlugin.this, null);
		}

		@Override
		protected void locationTracked() {
			updateStaticLocation();
		}
	}

	private class TrackedTokenMatcher implements CTokenHighlightMatcher {
		private Program program;

		@Override
		public void start(ClangNode root) {
			ClangFunction clangFunction = root == null ? null : root.getClangFunction();
			HighFunction highFunction =
				clangFunction == null ? null : clangFunction.getHighFunction();
			Function function = highFunction == null ? null : highFunction.getFunction();
			program = function == null ? null : function.getProgram();
		}

		@Override
		public Color getTokenHighlight(ClangToken token) {
			ProgramLocation loc = staticLocation;
			if (loc == null || program != null && program != loc.getProgram()) {
				return null;
			}
			return isTrackedToken(loc, token) ? COLOR_TRACKED : null;
		}
	}

	private class TrackedLocationIconSource implements DecompilerMarginIconSource {
		@Override
		public Icon getIcon(Program program, ClangLine line) {
			return isTrackedLine(program, line) ? ICON_TRACKED : null;
		}

		@Override
		public int getPriority() {
			return DebuggerResources.PRIORITY_REGISTER_MARKER;
		}
	}

	private final DebuggerStaticMappingChangeListener mappingsListener = this::mappingsChanged;
	private final DecompilerMarginIconSource iconSource = new TrackedLocationIconSource();
	// package access for testing
	final ForDecompilerTrackLocationTrait trackingTrait;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed via method
	private DebuggerListingService listingService;
	// @AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	// @AutoServiceConsumed via method
	private DebuggerDecompilerMarginService marginService;
	// @AutoServiceConsumed via method
	private DecompilerHighlightService highlightService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	// package access for testing
	DecompilerHighlighter highlighter;
	/** The tracked location mapped into the static program, or null */
	private volatile ProgramLocation staticLocation;

	public DebuggerDecompilerTrackLocationPlugin(PluginTool tool) {
		super(tool);
		this.trackingTrait = new ForDecompilerTrackLocationTrait();
		this.autoServiceWiring = AutoService.wireServicesConsumed(this, this);
	}

	@Override
	protected void init() {
		super.init();
		syncTrackingSpec();
		if (traceManager != null) {
			trackingTrait.goToCoordinates(traceManager.getCurrent());
		}
	}

	@Override
	protected void dispose() {
		setMarginService(null);
		setHighlightService(null);
		setMappingService(null);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		switch (event) {
			case TraceActivatedPluginEvent ev -> {
				// The listing may have restored its spec without firing an event
				syncTrackingSpec();
				trackingTrait.goToCoordinates(ev.getActiveCoordinates());
			}
			case TrackingChangedPluginEvent ev -> setTrackingSpec(ev.getLocationTrackingSpec());
			default -> {
			}
		}
	}

	/**
	 * Adopt the tracking spec of the primary dynamic listing, if present
	 */
	private void syncTrackingSpec() {
		if (listingService == null) {
			return;
		}
		LocationTrackingSpec spec = listingService.getTrackingSpec();
		if (spec != null && spec != trackingTrait.getSpec()) {
			setTrackingSpec(spec);
		}
	}

	void setTrackingSpec(LocationTrackingSpec spec) {
		trackingTrait.setSpec(spec);
	}

	LocationTrackingSpec getTrackingSpec() {
		return trackingTrait.getSpec();
	}

	@AutoServiceConsumed
	private void setListingService(DebuggerListingService listingService) {
		this.listingService = listingService;
		syncTrackingSpec();
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(mappingsListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(mappingsListener);
		}
		updateStaticLocation();
	}

	@AutoServiceConsumed
	private void setMarginService(DebuggerDecompilerMarginService marginService) {
		if (this.marginService != null) {
			this.marginService.removeIconSource(iconSource);
		}
		this.marginService = marginService;
		if (this.marginService != null) {
			this.marginService.addIconSource(iconSource);
		}
	}

	@AutoServiceConsumed
	private void setHighlightService(DecompilerHighlightService highlightService) {
		if (highlighter != null) {
			highlighter.dispose();
			highlighter = null;
		}
		this.highlightService = highlightService;
		if (this.highlightService != null) {
			highlighter =
				this.highlightService.createHighlighter(HIGHLIGHTER_ID, new TrackedTokenMatcher());
			refreshMarks();
		}
	}

	private void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
		updateStaticLocation();
	}

	private void updateStaticLocation() {
		ProgramLocation dynamic = trackingTrait.getTrackedLocation();
		staticLocation = dynamic == null || mappingService == null ? null
				: mappingService.getStaticLocationFromDynamic(dynamic);
		Swing.runIfSwingOrRunLater(this::refreshMarks);
	}

	private void refreshMarks() {
		if (highlighter != null) {
			highlighter.clearHighlights();
			if (staticLocation != null) {
				highlighter.applyHighlights();
			}
		}
		if (marginService != null) {
			marginService.iconsChanged();
		}
	}

	/**
	 * Get the tracked location, mapped into the static program
	 *
	 * @return the location, or null if not tracking or not mapped
	 */
	ProgramLocation getStaticLocation() {
		return staticLocation;
	}

	private static boolean isTrackedToken(ProgramLocation loc, ClangToken token) {
		if (token == null) {
			return false;
		}
		Address min = token.getMinAddress();
		Address max = token.getMaxAddress();
		if (min == null || max == null) {
			return false;
		}
		Address addr = loc.getAddress();
		if (!addr.getAddressSpace().equals(min.getAddressSpace())) {
			return false;
		}
		return min.compareTo(addr) <= 0 && addr.compareTo(max) <= 0;
	}

	/**
	 * Check if any token of the given line is part of the instruction at the tracked location
	 *
	 * @param program the program the line was decompiled from
	 * @param line the line
	 * @return true if the line holds the tracked location
	 */
	boolean isTrackedLine(Program program, ClangLine line) {
		ProgramLocation loc = staticLocation;
		if (loc == null || loc.getProgram() != program) {
			return false;
		}
		for (ClangToken token : line.getAllTokens()) {
			if (isTrackedToken(loc, token)) {
				return true;
			}
		}
		return false;
	}
}
