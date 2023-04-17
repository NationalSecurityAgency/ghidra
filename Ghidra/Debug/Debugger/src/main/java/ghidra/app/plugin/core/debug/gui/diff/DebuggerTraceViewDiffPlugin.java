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
package ghidra.app.plugin.core.debug.gui.diff;

import java.awt.Color;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiPredicate;
import java.util.function.Function;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import generic.theme.GColor;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.debug.*;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.action.DebuggerTrackLocationTrait;
import ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.listing.MultiBlendedListingBackgroundColorModel;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimeSelectionDialog;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils.PluginToolExecutorService;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils.PluginToolExecutorService.TaskOpt;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;

@PluginInfo(shortDescription = "Compare memory state between times in a trace", description = "Provides a side-by-side diff view between snapshots (points in time) in a " +
	"trace. The comparison is limited to raw bytes.", category = PluginCategoryNames.DEBUGGER, packageName = DebuggerPluginPackage.NAME, status = PluginStatus.RELEASED, eventsConsumed = {
		TraceClosedPluginEvent.class,
	}, eventsProduced = {}, servicesRequired = {
		DebuggerListingService.class,
	}, servicesProvided = {})
public class DebuggerTraceViewDiffPlugin extends AbstractDebuggerPlugin {
	static final Color COLOR_DIFF = new GColor("color.bg.highlight.listing.diff");

	protected static final String MARKER_NAME = "Trace Diff";
	protected static final String MARKER_DESCRIPTION = "Difference between snapshots in this trace";

	protected class ListingCoordinationListener implements CoordinatedListingPanelListener {
		@Override
		public boolean listingClosed() {
			return endComparison();
		}

		@Override
		public void activeProgramChanged(Program activeProgram) {
			endComparison();
		}
	}

	protected class ForAltListingTrackingTrait extends DebuggerTrackLocationTrait {
		public ForAltListingTrackingTrait() {
			super(DebuggerTraceViewDiffPlugin.this.getTool(), DebuggerTraceViewDiffPlugin.this,
				null);
		}

		@Override
		protected void locationTracked() {
			if (altListingPanel == null) {
				return;
			}
			// NB. Don't goTo here. The left listing controls navigation
			altListingPanel.getFieldPanel().repaint();
		}
	}

	protected class SyncAltListingTrackingSpecChangeListener
			implements LocationTrackingSpecChangeListener {
		@Override
		public void locationTrackingSpecChanged(LocationTrackingSpec spec) {
			trackingTrait.setSpec(spec);
		}
	}

	protected class MarkerSetChangeListener implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			if (altListingPanel == null) {
				return;
			}
			altListingPanel.getFieldPanel().repaint();
		}
	}

	// @AutoServiceConsumed via method
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	//@AutoServiceConsumed via method
	private MarkerService markerService;

	protected final DebuggerTimeSelectionDialog timeDialog;

	protected ToggleDockingAction actionCompare;
	protected DockingAction actionPrevDiff;
	protected DockingAction actionNextDiff;

	protected ListingPanel altListingPanel;
	protected final ForAltListingTrackingTrait trackingTrait;
	protected boolean sessionActive;

	protected final ListingCoordinationListener coordinationListener =
		new ListingCoordinationListener();
	protected final SyncAltListingTrackingSpecChangeListener syncTrackingSpecListener =
		new SyncAltListingTrackingSpecChangeListener();

	protected MultiBlendedListingBackgroundColorModel colorModel;
	protected final MarkerSetChangeListener markerChangeListener = new MarkerSetChangeListener();
	protected MarkerServiceBackgroundColorModel markerServiceColorModel;

	protected MarkerSet diffMarkersL;
	protected MarkerSet diffMarkersR;

	public DebuggerTraceViewDiffPlugin(PluginTool tool) {
		super(tool);
		timeDialog = new DebuggerTimeSelectionDialog(tool);
		trackingTrait = new ForAltListingTrackingTrait();
		createActions();
	}

	protected void createActions() {
		actionCompare = CompareTimesAction.builder(this)
				.enabled(false)
				.enabledWhen(ctx -> traceManager != null && traceManager.getCurrentTrace() != null)
				.onAction(this::activatedCompare)
				.build();
		actionPrevDiff = PrevDifferenceAction.builder(this)
				.enabled(false)
				.enabledWhen(ctx -> hasPrevDiff())
				.onAction(ctx -> gotoPrevDiff())
				.build();
		actionNextDiff = NextDifferenceAction.builder(this)
				.enabled(false)
				.enabledWhen(ctx -> hasNextDiff())
				.onAction(ctx -> gotoNextDiff())
				.build();
	}

	protected void activatedCompare(ActionContext ctx) {
		if (!actionCompare.isSelected()) {
			endComparison();
			return;
		}
		if (sessionActive) {
			return;
		}

		DebuggerCoordinates current = traceManager.getCurrent();
		TraceSchedule time = timeDialog.promptTime(current.getTrace(), current.getTime());
		if (time == null) {
			// Cancelled
			return;
		}
		if (traceManager == null) {
			// Can happen if tool is closed while dialog was up
			return;
		}
		if (traceManager.getCurrentTrace() != current.getTrace()) {
			Msg.warn(this, "Trace changed during time prompt. Aborting");
			return;
		}
		// NB. startComparison will handle failure
		startComparison(time);
	}

	/**
	 * Begin a snapshot/time comparison session
	 * 
	 * <p>
	 * NOTE: This method handles asynchronous errors by popping an error dialog. Callers need not
	 * handle exceptional completion.
	 * 
	 * @param time the alternative time
	 * @return a future which completes when the alternative listing and difference is presented
	 */
	public CompletableFuture<Void> startComparison(TraceSchedule time) {
		sessionActive = true; // prevents the action from performing anything
		actionCompare.setSelected(true);

		DebuggerCoordinates current = traceManager.getCurrent();
		DebuggerCoordinates alternate = traceManager.resolveTime(time);
		PluginToolExecutorService toolExecutorService =
			new PluginToolExecutorService(tool, "Computing diff", null, 500,
				TaskOpt.HAS_PROGRESS, TaskOpt.CAN_CANCEL);
		return traceManager.materialize(alternate).thenApplyAsync(snap -> {
			clearMarkers();
			TraceProgramView altView = alternate.getTrace().getFixedProgramView(snap);
			altListingPanel.setProgram(altView);
			trackingTrait.goToCoordinates(alternate.view(altView));
			listingService.setListingPanel(altListingPanel);
			return altView;
		}, AsyncUtils.SWING_EXECUTOR).thenApplyAsync(altView -> {
			return computeDiff(current.getView(), altView);
		}, toolExecutorService).thenAcceptAsync(diffSet -> {
			addMarkers(diffSet);
			listingService.addLocalAction(actionNextDiff);
			listingService.addLocalAction(actionPrevDiff);
			updateActions();
		}, AsyncUtils.SWING_EXECUTOR).exceptionally(ex -> {
			Msg.showError(this, null, "Compare", "Could not compare trace snapshots/times", ex);
			return null;
		});
	}

	protected void updateActions() {
		// May not be necessary often, since contextChanged in ListingProvider should do it
		actionNextDiff.setEnabled(actionNextDiff.isEnabledForContext(null));
		actionPrevDiff.setEnabled(actionPrevDiff.isEnabledForContext(null));
	}

	public boolean endComparison() {
		sessionActive = false;
		actionCompare.setSelected(false);
		clearMarkers();
		if (altListingPanel.getProgram() != null) {
			listingService.removeListingPanel(altListingPanel);
			altListingPanel.setProgram(null);

			listingService.removeLocalAction(actionNextDiff);
			listingService.removeLocalAction(actionPrevDiff);

			return true;
		}
		return false;
	}

	protected Address getCurrentAddress() {
		if (listingService == null) {
			return null;
		}
		ProgramLocation loc = listingService.getCurrentLocation();
		if (loc == null) {
			return null;
		}
		return loc.getAddress();
	}

	public AddressSetView getDiffs() {
		if (diffMarkersL == null) {
			return null;
		}
		return diffMarkersL.getAddressSet();
	}

	protected boolean hasSeqDiff(Function<AddressSetView, AddressRange> getExtremeRange,
			BiPredicate<AddressRange, Address> checkRange) {
		Address cur = getCurrentAddress();
		if (cur == null) {
			return false;
		}
		AddressSetView set = getDiffs();
		if (set == null) {
			return false;
		}
		AddressRange extreme = getExtremeRange.apply(set);
		if (extreme == null) {
			return false;
		}
		return checkRange.test(extreme, cur);
	}

	public boolean hasPrevDiff() {
		return hasSeqDiff(AddressSetView::getFirstRange,
			(first, cur) -> first.getMaxAddress().compareTo(cur) < 0);
	}

	public boolean hasNextDiff() {
		return hasSeqDiff(AddressSetView::getLastRange,
			(last, cur) -> cur.compareTo(last.getMinAddress()) < 0);
	}

	protected Address getSeqDiff(boolean forward,
			Function<AddressRange, Address> getFarthestAddress,
			Function<Address, Address> getStepped) {
		Address cur = getCurrentAddress();
		if (cur == null) {
			return null;
		}
		AddressSetView set = getDiffs();
		if (set == null) {
			return null;
		}
		AddressRange range = set.getRangeContaining(cur);
		if (range != null) {
			cur = getFarthestAddress.apply(range);
		}
		cur = getStepped.apply(cur);
		if (cur == null) {
			return null;
		}
		AddressIterator it = set.getAddresses(cur, forward);
		if (!it.hasNext()) {
			return null;
		}
		return it.next();
	}

	public Address getPrevDiff() {
		return getSeqDiff(false, AddressRange::getMinAddress, Address::previous);
	}

	public Address getNextDiff() {
		return getSeqDiff(true, AddressRange::getMaxAddress, Address::next);
	}

	public boolean gotoPrevDiff() {
		Address prevDiff = getPrevDiff();
		if (prevDiff == null) {
			return false;
		}
		return listingService.goTo(prevDiff, true) && altListingPanel.goTo(prevDiff);
	}

	public boolean gotoNextDiff() {
		Address nextDiff = getNextDiff();
		if (nextDiff == null) {
			return false;
		}
		return listingService.goTo(nextDiff, true) && altListingPanel.goTo(nextDiff);
	}

	protected void injectOnListingService() {
		if (listingService != null) {
			listingService.addLocalAction(actionCompare);
			altListingPanel = new ListingPanel(listingService.getFormatManager());
			listingService.setCoordinatedListingPanelListener(coordinationListener);
			listingService.addTrackingSpecChangeListener(syncTrackingSpecListener);

			colorModel = listingService.createListingBackgroundColorModel(altListingPanel);
			colorModel.addModel(trackingTrait.createListingBackgroundColorModel(altListingPanel));
			altListingPanel.setBackgroundColorModel(colorModel);
			updateMarkerServiceColorModel();
		}
	}

	protected void ejectFromListingService() {
		if (altListingPanel != null) {
			altListingPanel.dispose();
			altListingPanel = null;
		}
		colorModel = null;
		if (listingService != null) {
			listingService.removeLocalAction(actionCompare);
			listingService.setCoordinatedListingPanelListener(null);
			listingService.removeTrackingSpecChangeListener(syncTrackingSpecListener);
		}
	}

	@AutoServiceConsumed
	private void setListingService(DebuggerListingService listingService) {
		ejectFromListingService();
		this.listingService = listingService;
		injectOnListingService();
	}

	protected void updateMarkerServiceColorModel() {
		if (colorModel == null) {
			return;
		}
		colorModel.removeModel(markerServiceColorModel);
		if (markerService != null && altListingPanel != null) {
			colorModel.addModel(markerServiceColorModel = new MarkerServiceBackgroundColorModel(
				markerService, altListingPanel.getProgram(), altListingPanel.getAddressIndexMap()));
		}
	}

	protected void createMarkers() {
		if (diffMarkersL != null) {
			return;
		}
		if (markerService == null) {
			diffMarkersL = null;
			diffMarkersR = null;
			return;
		}
		if (altListingPanel == null) {
			diffMarkersL = null;
			diffMarkersR = null;
			return;
		}
		Program viewR = altListingPanel.getProgram();
		if (viewR == null) {
			diffMarkersR = null;
			diffMarkersL = null;
			return;
		}
		TraceProgramView viewL = traceManager.getCurrentView();
		diffMarkersL = markerService.createAreaMarker(MARKER_NAME, MARKER_DESCRIPTION, viewL, 0,
			true, true, true, COLOR_DIFF, true);
		diffMarkersR = markerService.createAreaMarker(MARKER_NAME, MARKER_DESCRIPTION, viewR, 0,
			true, true, true, COLOR_DIFF, true);
		return;
	}

	protected void addMarkers(AddressSetView diffSet) {
		createMarkers();
		if (diffMarkersL != null) {
			diffMarkersL.add(diffSet);
		}
		if (diffMarkersR != null) {
			diffMarkersR.add(diffSet);
		}
	}

	protected void clearMarkers() {
		if (diffMarkersL != null) {
			diffMarkersL.clearAll();
		}
		if (diffMarkersR != null) {
			diffMarkersR.clearAll();
		}
	}

	protected void deleteMarkers() {
		if (diffMarkersL == null) {
			return;
		}
		if (markerService == null) {
			return;
		}
		if (altListingPanel == null) {
			return;
		}
		Program altView = altListingPanel.getProgram();
		if (altView == null) {
			return;
		}
		markerService.removeMarker(diffMarkersL, altView);
		markerService.removeMarker(diffMarkersR, altView);
	}

	@AutoServiceConsumed
	private void setMarkerService(MarkerService markerService) {
		if (this.markerService != null) {
			this.markerService.removeChangeListener(markerChangeListener);
			deleteMarkers();
		}
		this.markerService = markerService;
		updateMarkerServiceColorModel();

		if (this.markerService != null) {
			this.markerService.addChangeListener(markerChangeListener);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
			if (timeDialog.getTrace() == evt.getTrace()) {
				timeDialog.close();
			}
		}
	}

	public static int lenRemainsBlock(int blockSize, long off) {
		return blockSize - (int) (off % blockSize);
	}

	public static long minOfBlock(int blockSize, long off) {
		return off / blockSize * blockSize;
	}

	public static long maxOfBlock(int blockSize, long off) {
		return (off + blockSize - 1) / blockSize * blockSize - 1;
	}

	public static Address maxOfBlock(int blockSize, Address address) {
		long off = address.getOffset();
		long max = maxOfBlock(blockSize, off);
		AddressSpace space = address.getAddressSpace();
		return space.getAddress(max);
	}

	public static AddressRange blockFor(int blockSize, Address address) {
		long off = address.getOffset();
		// TODO: Require powers of 2?
		long min = minOfBlock(blockSize, off);
		long max = maxOfBlock(blockSize, off);
		AddressSpace space = address.getAddressSpace();
		return new AddressRangeImpl(space.getAddress(min), space.getAddress(max));
	}

	protected AddressSetView computeDiff(TraceProgramView view1, TraceProgramView view2) {
		Trace trace = view1.getTrace();
		assert trace == view2.getTrace();
		long snap1 = view1.getSnap();
		long snap2 = view2.getSnap();

		if (snap1 == snap2) {
			// Punt on the degenerate case
			return new AddressSet();
		}

		TraceMemoryManager mm = trace.getMemoryManager();

		AddressSetView known1 = mm.getAddressesWithState(snap1, s -> s == TraceMemoryState.KNOWN);
		AddressSetView known2 = mm.getAddressesWithState(snap2, s -> s == TraceMemoryState.KNOWN);

		//AddressSet knownEither = known1.union(known2);
		AddressSet knownBoth = known1.intersect(known2); // Will need byte-by-byte examination

		// Symmetric difference in state counts as difference?
		// TODO: Should that be togglable?

		AddressSet diff = new AddressSet(); //knownEither;
		//knownEither = null; // Don't need knownEither anymore. Avoid accidental use
		//diff.delete(knownBoth);

		int blockSize = mm.getBlockSize();
		if (blockSize == 0) {
			throw new UnsupportedOperationException("TODO: Unoptimized byte diff");
		}
		ByteBuffer buf1 = ByteBuffer.allocate(blockSize);
		ByteBuffer buf2 = ByteBuffer.allocate(blockSize);

		while (!knownBoth.isEmpty()) {
			Address next = knownBoth.getMinAddress();
			Long mrs1 = mm.getSnapOfMostRecentChangeToBlock(snap1, next);
			Long mrs2 = mm.getSnapOfMostRecentChangeToBlock(snap2, next);
			if (Objects.equals(mrs1, mrs2)) {
				knownBoth.delete(blockFor(blockSize, next));
				continue;
			}

			int len = lenRemainsBlock(blockSize, next.getOffset());
			buf1.clear();
			buf1.limit(len);
			if (len != mm.getBytes(snap1, next, buf1)) {
				throw new AssertionError("Read failed");
			}
			buf2.clear();
			buf2.limit(len);
			if (len != mm.getBytes(snap2, next, buf2)) {
				throw new AssertionError("Read failed");
			}

			compareBytes(diff, next, buf1, buf2);
			knownBoth.delete(blockFor(blockSize, next));
		}

		return diff;
	}

	protected void compareBytes(AddressSet diff, Address addr, ByteBuffer buf1, ByteBuffer buf2) {
		int len = buf1.limit();
		byte[] arr1 = buf1.array();
		byte[] arr2 = buf2.array();
		Address rngStart = null;
		for (int i = 0; i < len; i++) {
			if (arr1[i] != arr2[i]) {
				if (rngStart == null) {
					rngStart = addr.add(i);
				}
			}
			else {
				if (rngStart != null) {
					diff.add(rngStart, addr.add(i - 1));
					rngStart = null;
				}
			}
		}
		if (rngStart != null) {
			diff.add(rngStart, addr.add(len - 1));
		}
	}
}
