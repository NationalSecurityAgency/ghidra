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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Plugin that has a margin provider to show the program flow.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Show arrows for execution flow",
	description = "This plugin shows arrows to graphically illustrate "
			+ "the flow of execution within a function. The arrows indicate "
			+ "source and destination for jumps; solid lines indicate "
			+ "unconditional jumps; dashed lines indicate conditional jumps.",
	servicesRequired = { CodeViewerService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramLocationPluginEvent.class }
)
//@formatter:on
public class FlowArrowPlugin extends Plugin implements MarginProvider, OptionsChangeListener {

	static final int LEFT_OFFSET = 3;
	static final int MAX_DEPTH = 16;
	private static final int MAX_REFSTO_SHOW = 10; // TODO this was 20--sounded like too many

	private FlowArrowPanel flowArrowPanel;
	private boolean enabled = true;
	private boolean validState = false;
	private Address currentAddr;

	/** Start address to the index of the layout for that start address */
	private Map<Address, Integer> startAddressToPixel = new HashMap<>();

	/** End address to the index of the layout for that end address */
	private Map<Address, Integer> endAddressToPixel = new HashMap<>();

	/** On-screen layouts and their start/end addresses */
	private VerticalPixelAddressMap layoutToPixel;
	private Address screenTop;
	private Address screenBottom;
	private int maxDepth;

	private Program program;
	private CodeViewerService codeViewerService;

	private List<FlowArrow> flowArrows = new ArrayList<>();
	private Set<FlowArrow> selectedArrows = new HashSet<>();
	/** Those arrows that start at the current address */
	private Set<FlowArrow> activeArrows = new HashSet<>();

	public FlowArrowPlugin(PluginTool tool) {
		super(tool);

		flowArrowPanel = new FlowArrowPanel(this);

		flowArrowPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				boolean previousState = enabled;
				enabled = flowArrowPanel.getWidth() > LEFT_OFFSET;
				if (enabled && !previousState) {
					updateAndRepaint();
				}
			}

			@Override
			public void componentShown(ComponentEvent e) {
				boolean previousState = enabled;
				enabled = flowArrowPanel.getWidth() > LEFT_OFFSET;
				if (enabled && !previousState) {
					updateAndRepaint();
				}
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				enabled = false;
			}
		});

		getOptions();
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
	public void setPixelMap(VerticalPixelAddressMap pixmap) {
		this.layoutToPixel = pixmap;
		validateState();
		updateFlowArrows();
	}

	@Override
	public void processEvent(PluginEvent event) {
		boolean repaintReqd = false;
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent evt = (ProgramActivatedPluginEvent) event;
			program = evt.getActiveProgram();
			flowArrows.clear();
			validateState();
			repaintReqd = true;
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent evt = (ProgramLocationPluginEvent) event;
			ProgramLocation location = evt.getLocation();
			currentAddr = location.getAddress();
			activeArrows.clear();
			repaintReqd = true;
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent programClosedPluginEvent = (ProgramClosedPluginEvent) event;
			Program closedProgram = programClosedPluginEvent.getProgram();
			if (program == closedProgram || program == null) {
				program = null;
				currentAddr = null;
				activeArrows.clear();
				flowArrows.clear();
				validateState();
				repaintReqd = true;
			}
		}
		if (repaintReqd) {
			updateAndRepaint();
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(OptionsGui.BACKGROUND.getColorOptionName())) {
			Color c = (Color) newValue;
			flowArrowPanel.setBackground(c);
		}
		else if (optionName.equals(OptionsGui.FLOW_ARROW_NON_ACTIVE.getColorOptionName())) {
			Color c = (Color) newValue;
			flowArrowPanel.setForeground(c);
		}
		else if (optionName.equals(OptionsGui.FLOW_ARROW_ACTIVE.getColorOptionName())) {
			Color c = (Color) newValue;
			flowArrowPanel.setHighlightColor(c);
		}
	}

	@Override
	protected void dispose() {

		startAddressToPixel.clear();
		endAddressToPixel.clear();
		layoutToPixel = null;
		flowArrows.clear();
		flowArrowPanel.dispose();

		codeViewerService.removeMarginProvider(this);
	}

	@Override
	protected void init() {
		codeViewerService = tool.getService(CodeViewerService.class);
		codeViewerService.addMarginProvider(this);
	}

	Address getCurrentAddress() {
		return currentAddr;
	}

	Address getScreenBottomAddr() {
		return screenBottom;
	}

	int getMaxDepth() {
		return maxDepth;
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

	private void resetActiveArrows() {
		for (FlowArrow arrow : activeArrows) {
			arrow.resetShape();
		}
	}

	private void saveActiveArrows() {

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

		if (activeArrows.isEmpty()) {
			return;
		}
	}

	/** 
	 * Iterate over each other FlowArrow object to check overlaps
	 * @return  FlowArrow objects that have a start/end address in common
	 */
	private List<FlowArrow> getArrowsAtSameDepth(FlowArrow jump, List<FlowArrow> allArrows) {

		List<FlowArrow> results = new ArrayList<>();
		for (FlowArrow otherArrows : allArrows) {
			if (jump == otherArrows) {
				continue;
			}

			if (sharesEndpoint(jump, otherArrows)) {
				results.add(otherArrows);
			}
		}

		return results;
	}

	private boolean sharesEndpoint(FlowArrow a1, FlowArrow a2) {
		return a1.start.equals(a2.start) || a1.end.equals(a2.end);
	}

	private void computeAllArrowsDepth() {

		// Find overlapping arrows and compute depth
		for (FlowArrow arrow : flowArrows) {

			List<FlowArrow> sameDepth = null;

			// If we have not already assigned a depth to this FlowArrow object
			if (arrow.depth == -1) {

				sameDepth = getArrowsAtSameDepth(arrow, flowArrows);

				// Compute the full address set for all same-depth arrows
				AddressSet sameDepthAddrs = new AddressSet(arrow.addressSet);

				for (FlowArrow otherArrow : sameDepth) {
					sameDepthAddrs.add(otherArrow.addressSet);
				}

				List<FlowArrow> differentDepth = new ArrayList<>(flowArrows);
				differentDepth.removeAll(sameDepth);
				differentDepth.remove(arrow);
				assignArrowDepth(arrow, sameDepthAddrs, differentDepth);
			}
			else {
				sameDepth = Collections.emptyList();
			}

			// If this is the deepest arrow seen, increase maxDepth
			if (arrow.depth > maxDepth) {
				maxDepth = arrow.depth;
			}

			// Make same source/dest arrows the same depth
			for (FlowArrow same : sameDepth) {
				same.depth = arrow.depth;
			}
		}
	}

	/** Calculates depth based on all other arrows that DO NOT share an endpoint */
	private void assignArrowDepth(FlowArrow arrow, AddressSet overlappingAddresses,
			List<FlowArrow> allArrows) {

		//Keep track of which depths are used over current arrow range
		boolean[] usedDepths = new boolean[MAX_DEPTH];

		// Find all intersecting used depths
		for (FlowArrow otherArrow : allArrows) {
			if (otherArrow.depth == -1 || otherArrow.depth >= MAX_DEPTH) {
				continue;
			}

			if (sharesEndpoint(arrow, otherArrow)) {
				continue;
			}

			if (overlappingAddresses.intersects(otherArrow.addressSet)) {
				usedDepths[otherArrow.depth] = true;
			}
		}

		arrow.depth = 0;
		while (arrow.depth < usedDepths.length && usedDepths[arrow.depth]) {
			arrow.depth++;
		}
	}

	private List<FlowArrow> getFlowArrowsForScreenInstructions(AddressSetView screenAddresses) {

		List<FlowArrow> results = new ArrayList<>();
		ArrowCache arrowCache = new ArrowCache();
		CodeUnitIterator it = program.getListing().getCodeUnitIterator(
			CodeUnit.INSTRUCTION_PROPERTY, screenAddresses, true);

		while (it.hasNext()) {
			CodeUnit cu = it.next();
			Instruction instruction = (Instruction) cu;

			// incoming
			int refCount = program.getReferenceManager().getReferenceCountTo(cu.getMinAddress());
			if (refCount < MAX_REFSTO_SHOW) {
				ReferenceIterator instructionIt = instruction.getReferenceIteratorTo();
				while (instructionIt.hasNext()) {
					Reference ref = instructionIt.next();
					createFlowArrow(results, arrowCache, ref);
				}
			}

			arrowCache.clear();

			// outgoing
			Reference[] refs = instruction.getReferencesFrom();
			for (Reference ref : refs) {
				createFlowArrow(results, arrowCache, ref);
			}

		}

		return results;
	}

	private void createFlowArrow(List<FlowArrow> results, ArrowCache arrowCache, Reference ref) {
		RefType type = ref.getReferenceType();
		if (!(type.isJump() || type.isFallthrough())) {
			return;
		}

		FlowArrow arrow = getFlowArrow(ref);
		if (arrow == null) {
			return;
		}

		if (!arrowCache.isDuplicateOffscreen(arrow.start, arrow.end, type)) {
			results.add(arrow);
			updateArrowSets(arrow);
		}
	}

	/**
	 * Unusual Code: We keep arrows in 3 sets: all arrows, selected arrows, and active arrows.
	 *               Further, we rebuild arrows as the screen moves, causing the x coordinate
	 *               to change as arrows that are no longer on the screen are removed and 
	 *               as new arrows are added.  We want to make sure that we don't end up 
	 *               with an arrow in the selected/active sets that are the same as the one
	 *               in the 'all' set, but with a different width.  This causes both arrows
	 *               to become visible--basically, the selected arrows can become stale as
	 *               their width changes.  This code is meant to address this out-of-sync
	 *               behavior.
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

	private FlowArrow getFlowArrow(Reference ref) {
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
		validState = false;
		if (program == null || layoutToPixel == null) {
			return;
		}

		int n = layoutToPixel.getNumLayouts();
		if (n == 0) {
			return;
		}

		Address bottomAddr = layoutToPixel.getLayoutAddress(n - 1);
		if (bottomAddr != null) {
			AddressSpace testSpace = bottomAddr.getAddressSpace();
			validState = (program.getAddressFactory().getAddressSpace(
						testSpace.getSpaceID()) == testSpace);
		}
	}

	void updateAndRepaint() {
		update();
		flowArrowPanel.repaint();
	}

	private void update() {
		if (!enabled || !validState) {
			return;
		}

		//Compute addresses in local range
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
		maxDepth = 0;

		resetSelectedArrows();

		if (screenTop == null || screenBottom == null || n > 500) {
			return;
		}

		// Find all addresses that are on the screen and compute y co-ordinate
		for (int layout = 0; layout < n; layout++) {
			Address addr = layoutToPixel.getLayoutAddress(layout);
			if (addr != null) {
				startAddressToPixel.put(addr, layoutToPixel.getBeginPosition(layout));
				endAddressToPixel.put(addr, layoutToPixel.getEndPosition(layout));
			}
		}

		// Intersect the screenTop and screenBottom with the currentView
		AddressSetView flowSet = layoutToPixel.getAddressSet();

		// Find references at the instructions on the screen
		flowArrows = getFlowArrowsForScreenInstructions(flowSet);

		Collections.sort(flowArrows, (a1, a2) -> (a1).end.compareTo((a2).end));

		computeAllArrowsDepth();

		saveActiveArrows();
	}

	private Address toLayoutAddress(Address addr) {
		Object pixel = startAddressToPixel.get(addr);
		if (pixel != null || addr.compareTo(screenTop) < 0 || addr.compareTo(screenBottom) > 0) {
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

	private void updateFlowArrows() {
		if (enabled) {
			updateAndRepaint();
		}
	}

	private void getOptions() {
		ToolOptions opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);

		opt.registerOption(OptionsGui.FLOW_ARROW_NON_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_NON_ACTIVE.getDefaultColor(), null,
			"The color for an arrow with no endpoint at the current address");
		opt.registerOption(OptionsGui.FLOW_ARROW_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_ACTIVE.getDefaultColor(), null,
			"The color for an arrow with an endpoint at the current address");
		opt.registerOption(OptionsGui.FLOW_ARROW_SELECTED.getColorOptionName(),
			OptionsGui.FLOW_ARROW_SELECTED.getDefaultColor(), null,
			"The color for an arrow that has been selected by the user");

		Color c = opt.getColor(OptionsGui.BACKGROUND.getColorOptionName(),
			OptionsGui.BACKGROUND.getDefaultColor());
		flowArrowPanel.setBackground(c);

		c = opt.getColor(OptionsGui.FLOW_ARROW_NON_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_NON_ACTIVE.getDefaultColor());
		flowArrowPanel.setForeground(c);

		c = opt.getColor(OptionsGui.FLOW_ARROW_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_ACTIVE.getDefaultColor());
		flowArrowPanel.setHighlightColor(c);

		c = opt.getColor(OptionsGui.FLOW_ARROW_SELECTED.getColorOptionName(),
			OptionsGui.FLOW_ARROW_SELECTED.getDefaultColor());
		flowArrowPanel.setSelectedColor(c);

		opt.addOptionsChangeListener(this);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ArrowCache {
		Address address;
		boolean conditionalOffTop;
		boolean conditionalOffBottom;
		boolean fallthroughOffTop;
		boolean fallthroughOffBottom;
		boolean otherOffTop;
		boolean otherOffBottom;

		void clear() {
			address = null;
			conditionalOffTop = false;
			conditionalOffBottom = false;
			fallthroughOffTop = false;
			fallthroughOffBottom = false;
			otherOffTop = false;
			otherOffBottom = false;
		}

		boolean isDuplicateOffscreen(Address pointOfInterest, Address otherEnd, RefType refType) {
			if (!pointOfInterest.equals(address)) {
				clear();
				address = pointOfInterest;
			}

			// above the top of the screen
			if (otherEnd.compareTo(screenTop) < 0) {
				if (refType.isConditional()) {
					if (conditionalOffTop) {
						return true;
					}
					conditionalOffTop = true;
				}
				else if (refType.isFallthrough()) {
					if (fallthroughOffTop) {
						return true;
					}
					fallthroughOffTop = true;
				}
				else {
					if (otherOffTop) {
						return true;
					}
					otherOffTop = true;
				}
			}

			// below the bottom of the screen
			else if (otherEnd.compareTo(screenBottom) > 0) {
				if (refType.isConditional()) {
					if (conditionalOffBottom) {
						return true;
					}
					conditionalOffBottom = true;
				}
				else if (refType.isFallthrough()) {
					if (fallthroughOffBottom) {
						return true;
					}
					fallthroughOffBottom = true;
				}
				else {
					if (otherOffBottom) {
						return true;
					}
					otherOffBottom = true;
				}
			}
			return false;
		}
	}

	void goTo(Address address) {
		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		ListingPanel listingPanel = codeViewer.getListingPanel();
		ProgramLocation location = new ProgramLocation(program, address);
		listingPanel.goTo(location, false);
	}

	void scrollTo(Address address) {
		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		ListingPanel listingPanel = codeViewer.getListingPanel();
		ProgramLocation location = new ProgramLocation(program, address);
//		listingPanel.setCursorPosition(location);
//		listingPanel.goTo(location, true);
		listingPanel.scrollTo(location);
	}

	void scrollToCenter(Address address) {
		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		ListingPanel listingPanel = codeViewer.getListingPanel();
		ProgramLocation location = new ProgramLocation(program, address);
		listingPanel.center(location);
	}

	Address getAddressAtPoint(Point p) {
		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		ListingPanel listingPanel = codeViewer.getListingPanel();
		ProgramLocation location = listingPanel.getProgramLocation(p);
		if (location == null) {
			return null;
		}
		return location.getAddress();
	}

	Address getLastAddressOnScreen(Address end, boolean up) {
		if (up) {
			return screenTop;
		}
		return screenBottom;
	}

	public void forwardMouseEventToListing(MouseWheelEvent e) {
		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		ListingPanel listingPanel = codeViewer.getListingPanel();
		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		KeyboardFocusManager.getCurrentKeyboardFocusManager().redispatchEvent(fieldPanel, e);
	}

}
