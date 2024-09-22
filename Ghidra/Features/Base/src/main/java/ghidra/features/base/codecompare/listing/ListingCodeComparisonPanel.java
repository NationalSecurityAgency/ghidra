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
package ghidra.features.base.codecompare.listing;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.*;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.*;
import docking.menu.MultiStateDockingAction;
import docking.options.OptionsService;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import generic.theme.GIcon;
import ghidra.app.plugin.core.functioncompare.actions.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.base.codecompare.panel.CodeComparisonPanelActionContext;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.correlate.HashedFunctionAddressCorrelation;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import help.Help;

/**
 * Panel that displays two listings for comparison.
 */

public class ListingCodeComparisonPanel
		extends CodeComparisonPanel implements
		FormatModelListener, OptionsChangeListener {

	public static final String NAME = "Listing View";
	private static final String DIFF_NAVIGATE_GROUP = "A2_DiffNavigate";

	//@formatter:off
	private static final Icon NEXT_DIFF_ICON = new GIcon("icon.base.util.listingcompare.diff.next");
	private static final Icon PREVIOUS_DIFF_ICON = new GIcon("icon.base.util.listingcompare.previous.next");
	private static final Icon BOTH_VIEWS_ICON = new GIcon("icon.base.util.listingcompare.area.markers.all");
	private static final Icon UNMATCHED_ICON = new GIcon("icon.base.util.listingcompare.area.markers.unmatched");
	private static final Icon DIFF_ICON = new GIcon("icon.base.util.listingcompare.area.markers.diff");
	private static final Icon HOVER_ON_ICON = new GIcon("icon.base.util.listingcompare.hover.on");
	private static final Icon HOVER_OFF_ICON = new GIcon("icon.base.util.listingcompare.hover.off");
	//@formatter:on

	private enum NavigateType {
		ALL, UNMATCHED, DIFF
	}

	private ListingCodeComparisonOptions comparisonOptions;

	private Duo<ListingDisplay> displays;

	private ListingAddressCorrelation addressCorrelator;
	private ListingDiff listingDiff;
	private ListingCoordinator coordinator;
	private boolean listingsLocked;

	private ListingDiffActionManager diffActionManager;
	private DockingAction nextDiffAction;
	private DockingAction previousDiffAction;
	private DockingAction optionsAction;
	private DockingAction applyFunctionNameAction;
	private DockingAction applyEmptySignatureAction;
	private DockingAction applySignatureAction;
	private ToggleDockingAction toggleHeaderAction;
	private ToggleDockingAction toggleHoverAction;
	private MultiStateDockingAction<NavigateType> nextPreviousAreaTypeAction;

	/**
	 * Creates a comparison panel with two listings.
	 * 
	 * @param owner the owner of this panel
	 * @param tool the tool displaying this panel
	 */
	public ListingCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);
		Help.getHelpService().registerHelp(this, new HelpLocation(HELP_TOPIC, "Listing_View"));
		initializeOptions();

		listingDiff = buildListingDiff();
		displays = buildListingDisplays();
		buildPanel();
		createActions();

		setSynchronizedScrolling(true);
	}

	private ListingDiff buildListingDiff() {
		ListingDiff diff = new ListingDiff();
		diffActionManager = new ListingDiffActionManager(diff);
		return diff;
	}

	private Duo<ListingDisplay> buildListingDisplays() {
		ListingDisplay leftDisplay =
			new ListingDisplay(tool, owner, listingDiff, comparisonOptions, LEFT);
		ListingDisplay rightDisplay =
			new ListingDisplay(tool, owner, listingDiff, comparisonOptions, RIGHT);

		// make the right format manager always be the same as the left format manager
		leftDisplay.getFormatManager().addFormatModelListener(this);

		leftDisplay.setProgramLocationListener((l, t) -> programLocationChanged(LEFT, l, t));
		rightDisplay.setProgramLocationListener((l, t) -> programLocationChanged(RIGHT, l, t));

		return new Duo<>(leftDisplay, rightDisplay);
	}

	@Override
	public JComponent getComparisonComponent(Side side) {
		return displays.get(side).getListingPanel();
	}

	public ListingPanel getListingPanel(Side side) {
		return displays.get(side).getListingPanel();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		comparisonOptions.loadOptions(options);
		updateProgramViews();
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void setVisible(boolean b) {
		super.setVisible(b);
		updateActionEnablement();
	}

	/**
	 * Adds the indicated highlight providers for the left and right listing panels.
	 * 
	 * @param leftHighlightProvider the highlight provider for the left side's listing.
	 * @param rightHighlightProvider the highlight provider for the right side's listing.
	 */
	public void addHighlightProviders(ListingHighlightProvider leftHighlightProvider,
			ListingHighlightProvider rightHighlightProvider) {
		displays.get(LEFT).addHighlightProvider(leftHighlightProvider);
		displays.get(RIGHT).addHighlightProvider(rightHighlightProvider);
	}

	/**
	 * Removes the indicated highlight providers from the left and right listing panels.
	 * 
	 * @param leftHighlightProvider the highlight provider for the left side's listing.
	 * @param rightHighlightProvider the highlight provider for the right side's listing.
	 */
	public void removeHighlightProviders(ListingHighlightProvider leftHighlightProvider,
			ListingHighlightProvider rightHighlightProvider) {
		displays.get(LEFT).removeHighlightProvider(leftHighlightProvider);
		displays.get(RIGHT).removeHighlightProvider(rightHighlightProvider);
	}

	@Override
	public List<DockingAction> getActions() {
		List<DockingAction> actions = super.getActions();

		actions.add(nextPreviousAreaTypeAction);
		actions.add(toggleHeaderAction);
		actions.add(toggleHoverAction);
		actions.add(applyFunctionNameAction);
		actions.add(applyEmptySignatureAction);
		actions.add(applySignatureAction);
		actions.add(nextDiffAction);
		actions.add(previousDiffAction);
		actions.add(optionsAction);

		actions.addAll(diffActionManager.getActions());

		return actions;
	}

	/**
	 * Updates the enablement for all actions provided by this panel.
	 */
	@Override
	public void updateActionEnablement() {
		boolean isShowing = isShowing();
		boolean listingDiffActionEnablement = isShowing && listingDiff.hasCorrelation();

		tool.contextChanged(tool.getActiveComponentProvider());

		diffActionManager.updateActionEnablement(listingDiffActionEnablement);
	}

	/**
	 * Sets the cursor for the side to the given location
	 * @param side The side to goto
	 * @param program the side's program
	 * @param location the location
	 */
	public void setLocation(Side side, Program program, ProgramLocation location) {
		if (isShowing()) {
			displays.get(side).goTo(location);
		}
	}

	public ListingPanel getActiveListingPanel() {
		return displays.get(activeSide).getListingPanel();
	}

	@Override
	public void dispose() {
		setSynchronizedScrolling(false);
		displays.each(ListingDisplay::dispose);
	}

	@Override
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {

		if (event == null) {
			ListingComparisonActionContext context =
				new ListingComparisonActionContext(provider, this);
			return context;
		}

		ListingPanel leftPanel = displays.get(LEFT).getListingPanel();
		ListingPanel rightPanel = displays.get(RIGHT).getListingPanel();

		Object leftMarginContext = getContextForMarginPanels(leftPanel, event);
		if (leftMarginContext != null) {
			return new DefaultActionContext(provider).setContextObject(leftMarginContext);
		}
		Object rightMarginContext = getContextForMarginPanels(rightPanel, event);
		if (rightMarginContext != null) {
			return new DefaultActionContext(provider).setContextObject(rightMarginContext);
		}

		Object source = event.getSource();
		if (source instanceof FieldHeaderComp) {
			FieldHeaderLocation fieldHeaderLocation =
				leftPanel.getFieldHeader().getFieldHeaderLocation(event.getPoint());
			return new DefaultActionContext(provider).setContextObject(fieldHeaderLocation);
		}

		return new ListingComparisonActionContext(provider, this);
	}

	/**
	 * Repaints both the left and right listing panels if they are visible.
	 */
	public void updateListings() {
		if (!isVisible()) {
			return;
		}
		displays.each(ListingDisplay::repaint);
	}

	@Override
	public void formatModelChanged(FieldFormatModel model) {
		changeRightToMatchLeftFormat(model);
	}

	/**
	 * Gets the left or right listing panel that contains the indicated field panel.
	 * 
	 * @param fieldPanel the field panel
	 * @return the listing panel or null.
	 */
	public ListingPanel getListingPanel(FieldPanel fieldPanel) {
		ListingPanel listingPanel = displays.get(LEFT).getListingPanel();
		if (listingPanel.getFieldPanel() == fieldPanel) {
			return listingPanel;
		}

		listingPanel = displays.get(RIGHT).getListingPanel();
		if (listingPanel.getFieldPanel() == fieldPanel) {
			return listingPanel;
		}

		return null;
	}

	/**
	 * Displays the indicated text int the tool's status area.
	 * 
	 * @param text the message to display
	 */
	public void setStatusInfo(String text) {
		tool.setStatusInfo(text);
	}

	/**
	 * Gets a marker margin or overview margin context object if the mouse event occurred on one of
	 * the GUI components for the indicated listing panel's marker margin (left edge of listing) or
	 * overview margin (right edge of listing).
	 * 
	 * @param panel The listing panel to check
	 * @param event the mouse event
	 * @return a marker margin context object if the event was on a margin.
	 */
	public Object getContextObjectForMarginPanels(ListingPanel panel, MouseEvent event) {
		Object source = event.getSource();
		// Is event source a marker margin provider on the left side of the listing?
		List<MarginProvider> marginProviders = panel.getMarginProviders();
		for (MarginProvider marginProvider : marginProviders) {
			JComponent c = marginProvider.getComponent();
			if (c == source) {
				MarkerLocation loc = marginProvider.getMarkerLocation(event.getX(), event.getY());
				if (loc != null) {
					return loc; // Return the marker margin location that was clicked.
				}
				return source; // Return the margin provider that was clicked.
			}
		}
		// Is event source an overview provider on the right side of the listing?
		List<OverviewProvider> overviewProviders = panel.getOverviewProviders();
		for (OverviewProvider overviewProvider : overviewProviders) {
			JComponent c = overviewProvider.getComponent();
			if (c == source) {
				return source; // Return the overview provider that was clicked.
			}
		}
		return null; // Not one of the listing panel's margin panels.
	}

	@Override
	public void setSynchronizedScrolling(boolean synchronize) {
		listingsLocked = synchronize;
		updateCoordinator();
	}

	/**
	 * Notification that a program location changed on one side.
	 * @param side the side that changed
	 * @param location the new location for the given side
	 * @param trigger the trigger for the change
	 */
	private void programLocationChanged(Side side, ProgramLocation location, EventTrigger trigger) {

		// only respond to GUI actions to avoid bouncing
		if (trigger != EventTrigger.GUI_ACTION) {
			return;
		}
		displays.get(side).updateCursorMarkers(location);
		displays.get(side.otherSide()).updateCursorMarkers(null);

		if (coordinator != null) {
			coordinator.setLocation(side, location);
		}

	}

	private void createActions() {
		nextDiffAction = new ActionBuilder("Dual Listing Go To Next Area Marker", owner)
				.description("Go to the next highlighted area.")
				.helpLocation(
					new HelpLocation(HELP_TOPIC, "Dual Listing Go To Next Highlighted Area"))
				.popupMenuPath("Go To Next Highlighted Area")
				.popupMenuIcon(NEXT_DIFF_ICON)
				.popupMenuGroup(DIFF_NAVIGATE_GROUP)
				.toolBarIcon(NEXT_DIFF_ICON)
				.toolBarGroup(DIFF_NAVIGATE_GROUP)
				.keyBinding("ctrl alt N")
				.validContextWhen(c -> isValidPanelContext(c))
				.enabledWhen(c -> isShowing() && listingDiff.hasCorrelation())
				.onAction(c -> nextAreaDiff(true))
				.build();

		previousDiffAction = new ActionBuilder("Dual Listing Go To Previous Area Marker", owner)
				.description("Go to the previous highlighted area.")
				.helpLocation(
					new HelpLocation(HELP_TOPIC, "Dual Listing Go To Previous Highlighted Area"))
				.popupMenuPath("Go To Previous Highlighted Area")
				.popupMenuIcon(PREVIOUS_DIFF_ICON)
				.popupMenuGroup(DIFF_NAVIGATE_GROUP)
				.toolBarIcon(PREVIOUS_DIFF_ICON)
				.toolBarGroup(DIFF_NAVIGATE_GROUP)
				.keyBinding("ctrl alt P")
				.validContextWhen(c -> isValidPanelContext(c))
				.enabledWhen(c -> isShowing() && listingDiff.hasCorrelation())
				.onAction(c -> nextAreaDiff(false))
				.build();

		toggleHeaderAction = new ToggleActionBuilder("Dual Listing Toggle Header", owner)
				.description("Toggle Format Header")
				.menuPath("Show Listing Format Header")
				.menuGroup("Listing Group")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Dual Listing Toggle Format Header"))
				.onAction(c -> displays.get(LEFT).showHeader(toggleHeaderAction.isSelected()))
				.build();

		toggleHoverAction = new ToggleActionBuilder("Dual Listing Toggle Mouse Hover Popups", owner)
				.description("Toggles Mouse Hover Popups")
				.toolBarIcon(HOVER_ON_ICON)
				.helpLocation(
					new HelpLocation(HELP_TOPIC, "Dual Listing Toggle Mouse Hover Popups"))
				.enabledWhen(c -> isShowing())
				.selected(true)
				.onAction(c -> setHover(toggleHoverAction.isSelected()))
				.build();
		nextPreviousAreaTypeAction =
			new MultiStateActionBuilder<NavigateType>("Dual Listing Next/Previous Area Marker",
				owner)
						.description("Set Navigate Next/Previous Area Marker options")
						.helpLocation(
							new HelpLocation(HELP_TOPIC, "Dual Listing Next/Previous Area Marker"))
						.toolBarIcon(DIFF_ICON)
						.toolBarGroup(DIFF_NAVIGATE_GROUP)
						.addState("All Area Markers", BOTH_VIEWS_ICON, NavigateType.ALL)
						.addState("Unmatched Area Markers", UNMATCHED_ICON, NavigateType.UNMATCHED)
						.addState("Diff AreaMarkers", DIFF_ICON, NavigateType.DIFF)
						.enabledWhen(c -> isShowing() && listingDiff.hasCorrelation())
						.onActionStateChanged((s, t) -> adjustNextPreviousAreaType(s.getUserData()))
						.build();

		optionsAction = new ActionBuilder("Listing Code Comparison Options", owner)
				.description("Show the tool options for the Listing Code Comparison.")
				.popupMenuPath("Properties")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Listing_Code_Comparison_Options"))
				.validContextWhen(c -> isValidPanelContext(c))
				.enabledWhen(c -> isShowing() && listingDiff.hasCorrelation())
				.onAction(c -> showOptionsDialog())
				.build();

		applyFunctionNameAction = new FunctionNameApplyAction(owner);
		applyEmptySignatureAction = new EmptySignatureApplyAction(owner);
		applySignatureAction = new SignatureWithDatatypesApplyAction(owner);

	}

	private void showOptionsDialog() {
		OptionsService service = tool.getService(OptionsService.class);
		service.showOptionsDialog(ListingCodeComparisonOptions.OPTIONS_CATEGORY_NAME,
			"Listing Code Comparison");
	}

	private void adjustNextPreviousAreaType(NavigateType type) {
		String typeString = getTypeName(type);
		nextDiffAction.getPopupMenuData()
				.setMenuPath(new String[] { "Go to Next " + typeString + " Area" });
		nextDiffAction.setDescription("Go to the next " + typeString + " area");
		previousDiffAction.getPopupMenuData()
				.setMenuPath(new String[] { "Go to Previous " + typeString + " Area" });
		previousDiffAction.setDescription("Go to the previous " + typeString + " area");

	}

	private String getTypeName(NavigateType type) {
		switch (type) {
			case DIFF:
				return "Difference";
			case UNMATCHED:
				return "Unmatched";
			case ALL:
				return "Highlighted";
			default:
				throw new AssertException("Unexpected navigate type" + type);
		}
	}

	private void setHover(boolean enabled) {
		toggleHoverAction.getToolBarData().setIcon(enabled ? HOVER_ON_ICON : HOVER_OFF_ICON);
		displays.each(d -> d.setHoverMode(enabled));
	}

	private boolean isValidPanelContext(ActionContext context) {
		if (!(context instanceof CodeComparisonPanelActionContext comparisonContext)) {
			return false;
		}
		CodeComparisonPanel comparisonPanel = comparisonContext.getCodeComparisonPanel();
		return comparisonPanel == this;
	}

	@Override
	protected void comparisonDataChanged() {
		addressCorrelator = createCorrelator();
		updateProgramViews();
		updateCoordinator();
		updateListingDiff();
		initializeCursorMarkers();
		updateActionEnablement();
		validate();
	}

	private void updateCoordinator() {
		if (coordinator != null) {
			coordinator.dispose();
			coordinator = null;
		}
		if (listingsLocked) {
			coordinator = new ListingCoordinator(displays, addressCorrelator);
			coordinator.sync(activeSide);
		}
	}

	private ListingAddressCorrelation createCorrelator() {
		Function f1 = getFunction(LEFT);
		Function f2 = getFunction(RIGHT);
		if (f1 != null && f2 != null) {
			try {
				return new HashedFunctionAddressCorrelation(f1, f2, TaskMonitor.DUMMY);
			}
			catch (CancelledException | MemoryAccessException e) {
				// fall back to linear address correlation
			}
		}
		if (comparisonData.get(LEFT).isEmpty() || comparisonData.get(RIGHT).isEmpty()) {
			return null;
		}
		return new LinearAddressCorrelation(comparisonData);
	}

	private void updateListingDiff() {
		try {
			listingDiff.setCorrelation(addressCorrelator);
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Failed to load correlator", e);
		}
	}

	/**
	 * Establishes the location and display of the arrow cursor. This method should be called after
	 * the function comparison window is loaded with functions, data, etc.
	 */
	private void initializeCursorMarkers() {
		ProgramLocation activeProgramLocation = displays.get(activeSide).getProgramLocation();
		programLocationChanged(activeSide, activeProgramLocation, null);
	}

	private Object getContextForMarginPanels(ListingPanel lp, MouseEvent event) {
		Object source = event.getSource();
		List<MarginProvider> marginProvidersForLP = lp.getMarginProviders();
		for (MarginProvider marginProvider : marginProvidersForLP) {
			JComponent c = marginProvider.getComponent();
			if (c == source) {
				MarkerLocation loc = marginProvider.getMarkerLocation(event.getX(), event.getY());
				if (loc != null) {
					return loc;
				}
				return source;
			}
		}
		List<OverviewProvider> overviewProvidersForLP = lp.getOverviewProviders();
		for (OverviewProvider overviewProvider : overviewProvidersForLP) {
			JComponent c = overviewProvider.getComponent();
			if (c == source) {
				return source;
			}
		}
		return null;
	}

	private void initializeOptions() {
		comparisonOptions = new ListingCodeComparisonOptions();
		ToolOptions options = tool.getOptions(ListingCodeComparisonOptions.OPTIONS_CATEGORY_NAME);
		options.addOptionsChangeListener(this);
		comparisonOptions.initializeOptions(options);
		comparisonOptions.loadOptions(options);
	}

	private void changeRightToMatchLeftFormat(FieldFormatModel model) {
		SaveState saveState = new SaveState();
		displays.get(LEFT).getFormatManager().saveState(saveState);
		displays.get(RIGHT).getFormatManager().readState(saveState);
	}

	private void updateProgramViews() {
		displays.get(LEFT).setProgramView(getProgram(LEFT), getAddresses(LEFT), "listing1");
		displays.get(RIGHT).setProgramView(getProgram(RIGHT), getAddresses(RIGHT), "listing2");
	}

	private void nextAreaDiff(boolean forward) {
		NavigateType type = nextPreviousAreaTypeAction.getCurrentState().getUserData();
		ListingPanel activeListingPanel = getActiveListingPanel();
		ProgramLocation activePanelLocation = activeListingPanel.getProgramLocation();
		if (activePanelLocation == null) {
			tool.setStatusInfo(
				"The " + (activeSide == LEFT ? "first" : "second") + " listing is empty.");
			return;
		}
		Address activeAddress = activePanelLocation.getAddress();

		ArrayList<AddressRangeIterator> iteratorList = new ArrayList<>();

		if (type == NavigateType.ALL || type == NavigateType.DIFF) {
			AddressSetView activeDiffs = listingDiff.getDiffs(activeSide);
			iteratorList.add(activeDiffs.getAddressRanges(activeAddress, forward));
		}
		if (type == NavigateType.ALL || type == NavigateType.UNMATCHED) {
			AddressSetView unmatchedCode = listingDiff.getUnmatchedCode(activeSide);
			iteratorList.add(unmatchedCode.getAddressRanges(activeAddress, forward));
		}

		MultiAddressRangeIterator multiIterator = new MultiAddressRangeIterator(
			iteratorList.toArray(new AddressRangeIterator[iteratorList.size()]), forward);

		if (multiIterator.hasNext()) {
			AddressRange nextRange = multiIterator.next();
			Address minAddress = nextRange.getMinAddress();
			if ((forward ? nextRange.contains(activeAddress) : minAddress.equals(activeAddress)) &&
				multiIterator.hasNext()) {
				nextRange = multiIterator.next();
				minAddress = nextRange.getMinAddress();
			}
			if (minAddress.equals(activeAddress)) {
				outputNoNextPreviousMessage(forward, activeSide);
				return;
			}
			tool.clearStatusInfo();
			activeListingPanel.goTo(minAddress);
		}
		else {
			outputNoNextPreviousMessage(forward, activeSide);
		}
	}

	private void outputNoNextPreviousMessage(boolean forward, Side side) {
		NavigateType type = nextPreviousAreaTypeAction.getCurrentState().getUserData();
		String typeName = getTypeName(type).toLowerCase();
		tool.setStatusInfo("There isn't another " + (forward ? "next " : "previous ") +
			typeName + " area in the " +
			(side == LEFT ? "first" : "second") + " listing.");
	}
}
