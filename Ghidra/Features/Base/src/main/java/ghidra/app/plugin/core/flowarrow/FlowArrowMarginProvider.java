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
package ghidra.app.plugin.core.flowarrow;

import java.awt.Color;
import java.awt.KeyboardFocusManager;
import java.awt.event.*;
import java.util.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.app.util.viewer.field.ListingColors.FlowArrowColors;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UniversalID;

class FlowArrowMarginProvider implements ListingMarginProvider {

	static final int LEFT_OFFSET = 3;
	private static final int MAX_DEPTH = 16;
	private static final int MAX_REFSTO_SHOW = 10;

	/** Start address to the index of the layout for that start address */
	private Map<Address, Integer> startAddressToPixel = new HashMap<>();

	/** End address to the index of the layout for that end address */
	private Map<Address, Integer> endAddressToPixel = new HashMap<>();

	private FlowArrowPlugin plugin;
	private ListingPanel listingPanel;
	private Program program;
	private Address currentAddr;
	private FlowArrowPanel flowArrowPanel;

	/** The column furthers away from the listing, to the left */
	private int maxColumn;
	private boolean isShowing = true;
	private boolean validState = false;

	/** On-screen layouts and their start/end addresses */
	private VerticalPixelAddressMap layoutToPixel;
	private Address screenTop;
	private Address screenBottom;

	/**
	 * We keep arrows in 3 sets: all arrows, selected arrows, and active arrows.
	 * Further, we rebuild the full set of arrows as the screen moves.  However, the selected and 
	 * active arrows do not get cleared when we move the screen. This allows us to keep painting
	 * selected arrows as the screen changes.  The selected arrows are changed by user clicking. The
	 * active arrows are changed by program location updates.
	 */
	private List<FlowArrow> flowArrows = new ArrayList<>();

	/** Arrows manually clicked by the user */
	private Set<FlowArrow> selectedArrows = new HashSet<>();

	/** Those arrows that start at the current address */
	private Set<FlowArrow> activeArrows = new HashSet<>();

	FlowArrowMarginProvider(FlowArrowPlugin plugin) {

		this.plugin = plugin;

		flowArrowPanel = new FlowArrowPanel(this);
		flowArrowPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				boolean previousState = isShowing;
				isShowing = flowArrowPanel.getWidth() > LEFT_OFFSET;
				if (isShowing && !previousState) {
					updateAndRepaint();
				}
			}

			@Override
			public void componentShown(ComponentEvent e) {
				boolean previousState = isShowing;
				isShowing = flowArrowPanel.getWidth() > LEFT_OFFSET;
				if (isShowing && !previousState) {
					updateAndRepaint();
				}
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				isShowing = false;
			}
		});

		flowArrowPanel.setBackground(ListingColors.BACKGROUND);
		flowArrowPanel.setForeground(FlowArrowColors.INACTIVE);
		flowArrowPanel.setHighlightColor(FlowArrowColors.ACTIVE);
		flowArrowPanel.setSelectedColor(FlowArrowColors.SELECTED);

	}

	@Override
	public void setOwnerId(UniversalID ownerId) {
		// we don't need the owner id 
	}

	@Override
	public JComponent getComponent() {
		return flowArrowPanel;
	}

	@Override
	public MarkerLocation getMarkerLocation(int x, int y) {
		return null;
	}

	@Override
	public boolean isResizeable() {
		return true;
	}

	@Override
	public void setLocation(ProgramLocation location) {

		currentAddr = location.getAddress();
		clearActiveArrows();
		assignActiveArrows();
		flowArrowPanel.repaint();
	}

	@Override
	public void screenDataChanged(ListingPanel listing, AddressIndexMap addrMap,
			VerticalPixelAddressMap pixMap) {

		this.listingPanel = listing;
		Program currentProgram = listing.getProgram();
		if (this.program != currentProgram) {
			clearAllArrows();
		}

		this.program = currentProgram;
		this.layoutToPixel = pixMap;
		validateState();
		updateAndRepaint();
	}

	Address getCurrentAddress() {
		return currentAddr;
	}

	Address getScreenBottomAddr() {
		return screenBottom;
	}

	int getMaxColumn() {
		return maxColumn;
	}

	boolean isOnScreen(Address address) {
		if (screenBottom == null || screenTop == null) {
			return true; // shouldn't happen
		}

		if (address.compareTo(screenTop) < 0) {
			// above the top of the screen
			return false;
		}

		if (address.compareTo(screenBottom) > 0) {
			// below the bottom of the screen
			return false;
		}
		return true;
	}

	boolean isOffscreen(FlowArrow arrow) {
		if (screenBottom == null || screenTop == null) {
			return true; // shouldn't happen
		}

		if (arrow.start.compareTo(screenTop) < 0 && arrow.end.compareTo(screenTop) < 0) {
			// start and end are above the top of the screen
			return true;
		}

		if (arrow.start.compareTo(screenBottom) > 0 && arrow.end.compareTo(screenBottom) > 0) {
			// start and end are below the bottom of the screen
			return true;
		}
		return false;
	}

	boolean isBelowScreen(Address address) {
		if (screenBottom == null || screenTop == null) {
			return true; // shouldn't happen
		}

		return address.compareTo(screenBottom) > 0;
	}

	/* The y value of the start of the layout at the given address. */
	Integer getStartPos(Address addr) {
		return startAddressToPixel.get(addr);
	}

	/* The y value of the end of the layout at the given address. */
	Integer getEndPos(Address addr) {
		return endAddressToPixel.get(addr);
	}

	void setArrowSelected(FlowArrow arrow, boolean selected) {
		if (selected) {
			selectedArrows.add(arrow);
		}
		else {
			selectedArrows.remove(arrow);
		}
	}

	Iterator<FlowArrow> getSelectedFlowArrows() {
		return selectedArrows.iterator();
	}

	Iterator<FlowArrow> getFlowArrowIterator() {
		return flowArrows.iterator();
	}

	/* Those arrows starting at the current address */
	Iterator<FlowArrow> getActiveArrows() {
		return activeArrows.iterator();
	}

	private void resetSelectedArrows() {
		for (FlowArrow arrow : selectedArrows) {
			arrow.resetShape();
		}
	}

	private void clearAllArrows() {
		flowArrows.clear();
		activeArrows.clear();
		selectedArrows.clear();
	}

	private void clearActiveArrows() {
		for (FlowArrow f : activeArrows) {
			f.active = false;
		}
		activeArrows.clear();
	}

	private void resetActiveArrows() {
		for (FlowArrow arrow : activeArrows) {
			arrow.resetShape();
		}
	}

	private void assignActiveArrows() {

		if (!activeArrows.isEmpty()) {
			resetActiveArrows();
			return; // don't overwrite existing values
		}

		if (currentAddr == null) {
			return;
		}

		for (FlowArrow arrow : flowArrows) {
			if (currentAddr.equals(arrow.start)) {
				arrow.active = true;
				activeArrows.add(arrow);
			}
		}
	}

	private void mapArrowsByEndpoints(Map<Address, List<FlowArrow>> arrowsByStart,
			Map<Address, List<FlowArrow>> arrowsByEnd) {

		for (FlowArrow arrow : flowArrows) {
			arrowsByStart.computeIfAbsent(arrow.start, f -> new ArrayList<>()).add(arrow);
			arrowsByEnd.computeIfAbsent(arrow.end, f -> new ArrayList<>()).add(arrow);
		}
	}

	private List<ArrowGroup> groupArrowsBySharedEndpoints() {

		Map<Address, List<FlowArrow>> arrowsByStart = new HashMap<>();
		Map<Address, List<FlowArrow>> arrowsByEnd = new HashMap<>();
		mapArrowsByEndpoints(arrowsByStart, arrowsByEnd);

		List<ArrowGroup> groups = new ArrayList<>();

		Set<FlowArrow> unprocessed = new HashSet<>(flowArrows);
		for (FlowArrow arrow : flowArrows) {

			if (!unprocessed.contains(arrow)) {
				continue; // already grouped
			}

			// put all arrows in this group that share a start or end, as they will all occupy the
			// same column
			ArrowGroup group = new ArrowGroup();
			List<FlowArrow> starts = arrowsByStart.get(arrow.start);
			for (FlowArrow f : starts) {
				group.add(f);
				unprocessed.remove(arrow);
			}
			List<FlowArrow> ends = arrowsByEnd.get(arrow.end);
			for (FlowArrow f : ends) {
				group.add(f);
				unprocessed.remove(arrow);
			}

			group.add(arrow);
			unprocessed.remove(arrow);

			groups.add(group);
		}

		// Sort the groups so that the lowest end address is first.  I'm assuming that we wish to 
		// start at the top of the screen and paint incoming arrows first, closest to the Listing.
		groups.sort((g1, g2) -> g1.getSortAddress().compareTo(g2.getSortAddress()));

		return groups;
	}

	/**
	 * Assigns all arrow columns (horizontal positioning).  All arrows that share a start and or
	 * end point will all share the same column.  This reduce clutter by having them all share the
	 * same vertical segment.
	 * <p>
	 * As the groups are assigned columns, each arrow in the group is updated.  When this method is
	 * finished, all arrows will have a column assigned.
	 */
	private void assignArrowColumns() {

		// assign groups and then assign columns to the groups
		List<ArrowGroup> groups = groupArrowsBySharedEndpoints();
		Map<Integer, ArrowGroup> groupsByColumn = new HashMap<>();
		for (ArrowGroup group : groups) {

			for (int nextCol = 0; nextCol < groups.size(); nextCol++) {

				ArrowGroup existingGroup = groupsByColumn.get(nextCol);
				if (existingGroup == null || !existingGroup.overlaps(group)) {

					int column = Math.min(MAX_DEPTH, nextCol);
					group.setColumn(column);
					groupsByColumn.put(column, group);
					maxColumn = Math.max(maxColumn, column);
					break;
				}

			}
		}
	}

	private List<FlowArrow> getFlowArrowsForScreenInstructions(AddressSetView screenAddresses) {

		// A cache of arrows encountered going off the screen, above or below.  For any given arrow
		// start, we wish to only show one arrow for each of three references flow types.  The cache
		// will record when we have seen each of the types so that we can skip adding arrows for 
		// that type from that address again.
		OffscreenArrowsFlow offscreenArrows = new OffscreenArrowsFlow();

		Set<FlowArrow> results = new HashSet<>();
		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(screenAddresses, true);
		for (Instruction inst : it) {

			// incoming
			ReferenceManager refManager = program.getReferenceManager();
			int refCount = refManager.getReferenceCountTo(inst.getMinAddress());
			if (refCount < MAX_REFSTO_SHOW) {
				for (Reference ref : inst.getReferenceIteratorTo()) {
					createFlowArrow(results, offscreenArrows, ref);
				}
			}

			// clearing the cache resets the check for duplicates, keeping incoming and outgoing
			// references separate
			offscreenArrows.clear();

			// outgoing
			for (Reference ref : inst.getReferencesFrom()) {
				createFlowArrow(results, offscreenArrows, ref);
			}
		}

		// not sure this is still needed; keeping for posterity
		ArrayList<FlowArrow> newArrows = new ArrayList<>(results);
		Collections.sort(newArrows, (a1, a2) -> (a1).end.compareTo((a2).end));

		return newArrows;
	}

	private void createFlowArrow(Set<FlowArrow> results, OffscreenArrowsFlow offscreenArrows,
			Reference ref) {
		RefType type = ref.getReferenceType();
		if (!(type.isJump() || type.isFallthrough())) {
			return;
		}

		FlowArrow arrow = doCreateFlowArrow(ref);
		if (arrow == null) {
			return;
		}

		if (results.contains(arrow)) {
			return;
		}

		if (offscreenArrows.exists(arrow)) {
			// We have already seen an offscreen arrow coming from the same start address in the 
			// same direction for this arrow's flow type.  No need to add another one.
			return;
		}

		results.add(arrow);
		updateArrowSets(arrow);
	}

	/**
	 * Unusual Code: We keep arrows in 3 sets: all arrows, selected arrows, and active arrows.
	 * Further, we rebuild arrows as the screen moves, causing the x coordinate to change as arrows
	 * that are no longer on the screen are removed and as new arrows are added. We want to make
	 * sure that we don't end up with an arrow in the selected/active sets that are the same as the
	 * one in the 'all' set, but with a different width. This causes both arrows to become
	 * visible--basically, the selected arrows can become stale as their width changes. This code is
	 * meant to address this out-of-sync behavior.
	 *
	 * @param arrow the updated form of the arrow
	 */
	private void updateArrowSets(FlowArrow arrow) {
		if (selectedArrows.remove(arrow)) {
			arrow.selected = true;
			selectedArrows.add(arrow);
		}

		if (activeArrows.remove(arrow)) {
			arrow.active = true;
			activeArrows.add(arrow);
		}
	}

	private FlowArrow doCreateFlowArrow(Reference ref) {
		Address start = toLayoutAddress(ref.getFromAddress());
		Address end = toLayoutAddress(ref.getToAddress());
		if (start == null || end == null) {
			return null;
		}

		if (!start.hasSameAddressSpace(end)) {
			return null;		// is this right??
		}

		Memory memory = program.getMemory();
		if (!memory.contains(end)) {
			return null; // bad disassembly
		}

		RefType refType = ref.getReferenceType();
		if (refType.isFallthrough()) {
			return new FallthroughFlowArrow(this, flowArrowPanel, start, end, refType);
		}
		else if (refType.isConditional()) {
			return new ConditionalFlowArrow(this, flowArrowPanel, start, end, refType);
		}

		return new DefaultFlowArrow(this, flowArrowPanel, start, end, refType);
	}

	private void validateState() {
		validState = true;
		if (program == null || layoutToPixel == null) {
			validState = false;
			return;
		}

		int n = layoutToPixel.getNumLayouts();
		validState = n != 0;
	}

	void updateAndRepaint() {
		update();
		flowArrowPanel.repaint();
	}

	private void update() {
		if (!isShowing || !validState) {
			return;
		}

		if (layoutToPixel == null) {
			return; // this can happen if the tool is in a bad state
		}

		int n = layoutToPixel.getNumLayouts();
		if (n == 0) {
			return;
		}

		Address startAddress = layoutToPixel.getLayoutAddress(0);
		Address endAddress = layoutToPixel.getLayoutAddress(n - 1);

		screenTop = startAddress;
		screenBottom = endAddress;
		flowArrows.clear();
		startAddressToPixel.clear();
		endAddressToPixel.clear();
		maxColumn = 0;

		resetSelectedArrows();

		if (screenTop == null || screenBottom == null || n > 500) {
			return;
		}

		// find all addresses that are on the screen and compute y co-ordinate
		for (int layout = 0; layout < n; layout++) {
			Address addr = layoutToPixel.getLayoutAddress(layout);
			if (addr != null) {
				startAddressToPixel.put(addr, layoutToPixel.getBeginPosition(layout));
				endAddressToPixel.put(addr, layoutToPixel.getEndPosition(layout));
			}
		}

		AddressSetView flowSet = layoutToPixel.getAddressSet();
		flowArrows = getFlowArrowsForScreenInstructions(flowSet);

		assignArrowColumns();

		assignActiveArrows();
	}

	private Address toLayoutAddress(Address addr) {
		Object pixel = startAddressToPixel.get(addr);
		if (pixel != null || addr.compareTo(screenTop) < 0 ||
			addr.compareTo(screenBottom) > 0) {
			return addr;
		}

		int n = layoutToPixel.getNumLayouts();
		for (int i = 0; i < n; i++) {
			Address layoutAddr = layoutToPixel.getLayoutAddress(i);
			Address endLayoutAddr = layoutToPixel.getLayoutEndAddress(i);
			if (layoutAddr == null || endLayoutAddr == null) {
				continue;
			}

			if (layoutAddr.compareTo(addr) >= 0) {
				// have gone past the address, then there is a gap
				return null;
			}

			// we are between the start and end; inside the layout
			if (addr.compareTo(endLayoutAddr) <= 0) {
				return layoutAddr;
			}
		}

		return addr;   // should never get here
	}

	void setBackground(Color c) {
		flowArrowPanel.setBackground(c);
	}

	void setForeground(Color c) {
		flowArrowPanel.setForeground(c);
	}

	void setHighlightColor(Color c) {
		flowArrowPanel.setHighlightColor(c);
	}

	@Override
	public void dispose() {
		plugin.remove(this);
		program = null;
		layoutToPixel = null;
		startAddressToPixel.clear();
		endAddressToPixel.clear();
		clearAllArrows();
		flowArrowPanel.dispose();
	}

	void goTo(Address address) {
		ProgramLocation location = new ProgramLocation(program, address);
		listingPanel.goTo(location);
	}

	void scrollTo(Address address) {
		ProgramLocation location = new ProgramLocation(program, address);
		listingPanel.scrollTo(location);
	}

	Address getLastAddressOnScreen(Address end, boolean up) {
		if (up) {
			return screenTop;
		}
		return screenBottom;
	}

	public void forwardMouseEventToListing(MouseWheelEvent e) {
		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		kfm.redispatchEvent(fieldPanel, e);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/**
	 * An arrow group is all arrows that will be in the same column.  The column for an arrow
	 * will be based on the first group to assign a column.
	 */
	private class ArrowGroup {

		private Set<FlowArrow> arrows = new HashSet<>();
		private AddressSet addrs = new AddressSet();
		private Address lowestEndAddress;

		@SuppressWarnings("unused") // for debug
		private int column;

		Address getSortAddress() {
			return lowestEndAddress;
		}

		void setColumn(int column) {
			this.column = column;

			for (FlowArrow f : arrows) {
				f.column = column;
			}
		}

		void add(FlowArrow f) {
			if (lowestEndAddress == null) {
				lowestEndAddress = f.end;
			}
			else if (lowestEndAddress.compareTo(f.end) >= 0) {
				lowestEndAddress = f.end;
			}

			arrows.add(f);
			addrs.add(f.addresses);
		}

		boolean overlaps(ArrowGroup other) {
			return addrs.intersects(other.addrs);
		}
	}

	/**
	 * A cache of all arrows that start at a given address.  This is only used while building the 
	 * set of arrows.  This tracks arrow usage from the start address to limit the number of arrows
	 * that go offscreen.   We allow 1 offscreen arrow above and below for each of the three flow
	 * types: conditional, fallthrough and other.   This is used to prevent too many arrows from 
	 * cluttering the screen when there are many references starting at the same address.
	 */
	private class OffscreenArrowsFlow {

		private Map<Address, OffScreenFlow> flowsAbove = new HashMap<>();
		private Map<Address, OffScreenFlow> flowsBelow = new HashMap<>();

		/**
		 * Tracks the given arrow and records whether we have seen an arrow at this start address,
		 * going offscreen in the same direction with the same flow category.
		 * 
		 * @param arrow the arrow
		 * @return true if we already have a representative arrow
		 */
		boolean exists(FlowArrow arrow) {

			boolean isAbove = arrow.end.compareTo(screenTop) < 0;
			boolean isBelow = arrow.end.compareTo(screenBottom) > 0;
			if (!(isAbove || isBelow)) {
				return false; // on-screen
			}

			OffScreenFlow flow;
			if (isAbove) {
				flow = flowsAbove.get(arrow.start);
				if (flow == null) {
					flow = new OffScreenFlow();
					flowsAbove.put(arrow.start, flow);
				}
			}
			else { // isBelow
				flow = flowsBelow.get(arrow.start);
				if (flow == null) {
					flow = new OffScreenFlow();
					flowsBelow.put(arrow.start, flow);
				}
			}

			// sets the flow type and returns true if that type was already set, signalling that we 
			// have seen this an offscreen arrow with this flow type coming from this address in the
			// up or down direction
			boolean alreadyHasArrow = flow.setFlow(arrow.refType);
			return alreadyHasArrow;
		}

		void clear() {
			flowsAbove.clear();
			flowsBelow.clear();
		}

		private class OffScreenFlow {
			private boolean conditional;
			private boolean fallthrough;
			private boolean other;

			boolean setFlow(RefType type) {
				boolean wasSet = false;
				if (type.isConditional()) {
					wasSet = conditional;
					conditional = true;
				}
				else if (type.isFallthrough()) {
					wasSet = fallthrough;
					fallthrough = true;
				}
				else {
					wasSet = other;
					other = true;
				}

				return wasSet;
			}
		}
	}

}
