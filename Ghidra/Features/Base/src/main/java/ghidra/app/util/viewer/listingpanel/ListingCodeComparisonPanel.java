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
package ghidra.app.util.viewer.listingpanel;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.*;
import docking.action.*;
import docking.help.Help;
import docking.help.HelpService;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.fieldpanel.listener.FieldLocationListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.codebrowser.hover.*;
import ghidra.app.plugin.core.marker.MarkerManager;
import ghidra.app.services.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.util.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProviderDecorator;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.*;
import ghidra.program.model.correlate.HashedFunctionAddressCorrelation;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;

/**
 * Panel that displays two listings for comparison.
 */

public class ListingCodeComparisonPanel
		extends CodeComparisonPanel<ListingComparisonFieldPanelCoordinator> implements
		FormatModelListener, CodeFormatService, ListingDiffChangeListener, OptionsChangeListener {

	private static final String DUAL_LISTING_HEADER_SHOWING = "DUAL_LISTING_HEADER_SHOWING";
	private static final String DUAL_LISTING_SIDE_BY_SIDE = "DUAL_LISTING_SIDE_BY_SIDE";
	public static final String NAME = "DualListing";
	public static final String TITLE = "Listing View";

	protected static final HelpService help = Help.getHelpService();

	private static final String DUAL_LISTING_HELP_TOPIC = "FunctionComparison";
	private static final String DUAL_LISTING_ACTION_GROUP = NAME;

	private static final String DIFF_NAVIGATE_GROUP = "A2_DiffNavigate";
	private static final String HOVER_GROUP = "A5_Hovers";
	private static final String PROPERTIES_GROUP = "B1_Properties";
	private static final Icon NEXT_DIFF_ICON =
		ResourceManager.loadImage("images/view-sort-ascending.png");
	private static final Icon PREVIOUS_DIFF_ICON =
		ResourceManager.loadImage("images/view-sort-descending.png");
	private static final Icon bothIcon = ResourceManager.loadImage("images/text_list_bullets.png");
	private static final Icon unmatchedIcon = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
	private static final Icon diffsIcon =
		ResourceManager.loadImage("images/table_relationship.png");
	private static final String ALL_AREA_MARKERS = "All Area Markers";
	private static final String UNMATCHED_AREA_MARKERS = "Unmatched Area Markers";
	private static final String DIFF_AREA_MARKERS = "Diff Area Markers";
	private String nextPreviousAreaType;

	private static final Icon HOVER_ON_ICON = ResourceManager.loadImage("images/hoverOn.gif");
	private static final Icon HOVER_OFF_ICON = ResourceManager.loadImage("images/hoverOff.gif");

	private ListingPanel[] listingPanels = new ListingPanel[2];
	private ListingDiff listingDiff;
	private ListingDiffActionManager diffActionManager;
	private DualListingServiceProvider[] dualListingServiceProviders =
		new DualListingServiceProvider[2];
	private DualListingNavigator[] navigatables = new DualListingNavigator[2];
	private FieldNavigator[] fieldNavigators = new FieldNavigator[2];
	private AddressIndexMap[] indexMaps = new AddressIndexMap[2];
	private AddressSetView[] addressSets =
		new AddressSetView[] { EMPTY_ADDRESS_SET, EMPTY_ADDRESS_SET };
	private MarkerManager[] markerManagers = new MarkerManager[2];
	private MarkerSet[] unmatchedCodeMarkers = new MarkerSet[2];
	private MarkerSet[] diffMarkers = new MarkerSet[2];
	private MarkerSet[] currentCursorMarkers = new MarkerSet[2];
	private static final Color CURSOR_LINE_COLOR = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;
	private ImageIcon CURSOR_LOC_ICON =
		ResourceManager.loadImage("images/cursor_arrow_flipped.gif");
	private Color cursorHighlightColor;
	private boolean isShowingEntireListing;
	private boolean isSideBySide = true;
	private boolean fieldLocationChanging = false;
	private LeftLocationListener leftLocationListener;
	private RightLocationListener rightLocationListener;
	private ToggleHeaderAction toggleHeaderAction;
	private ToggleOrientationAction toggleOrientationAction;
	private ToggleHoverAction toggleHoverAction;
	private NextPreviousAreaMarkerAction nextPreviousAreaMarkerAction;
	private NextDiffAction nextDiffAction;
	private PreviousDiffAction previousDiffAction;
	private ListingCodeComparisonOptionsAction optionsAction;
	private DockingAction[] diffActions;
	private ApplyFunctionSignatureAction applyFunctionSignatureAction;
	private JSplitPane splitPane;

	private ListingDiffHighlightProvider leftDiffHighlightProvider;
	private ListingDiffHighlightProvider rightDiffHighlightProvider;

	private FunctionAddressCorrelation correlator;

	private boolean adjustingLeftLocation = false;
	private boolean adjustingRightLocation = false;

	ReferenceListingHover referenceHoverService;
	DataTypeListingHover dataTypeHoverService;
	TruncatedTextListingHover truncatedTextHoverService;
	FunctionNameListingHover functionNameHoverService;
	private String leftTitle;
	private String rightTitle;
	private ListingCodeComparisonOptions comparisonOptions = new ListingCodeComparisonOptions();
	private Address[] coordinatorLockedAddresses;

	/**
	 * Creates a comparison panel with two listings.
	 * @param owner the owner of this panel
	 * @param tool the tool displaying this panel
	 */
	public ListingCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);
		initialize();
	}

	private void initialize() {
		listingDiff = new ListingDiff();
		diffActionManager = new ListingDiffActionManager(listingDiff);
		initializeGoToServiceProviders(); // Must be before other buildPanel() and initialize methods.
		buildPanel();
		initializeListingFieldPanels();
		initializeListingFieldNavigation();
		initializeListingHoverService();
		setupMarkerManagers();
		createActions();
		listingDiff.addListingDiffChangeListener(this);
		setScrollingSyncState(true);
		help.registerHelp(this, new HelpLocation(DUAL_LISTING_HELP_TOPIC, "Dual Listing"));

		comparisonOptions = new ListingCodeComparisonOptions();
		initializeOptions();
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(ListingCodeComparisonOptions.OPTIONS_CATEGORY_NAME);
		options.addOptionsChangeListener(this);
		comparisonOptions.initializeOptions(options);
		comparisonOptions.loadOptions(options);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		comparisonOptions.loadOptions(options);

		repaint(); // Refresh the highlights. (byte, mnemonic, & operand)

		if (programs[LEFT] == null) {
			// not data is showing; no widgets to update
			return;
		}

		// Refresh the area markers for Diff Code Units and Unmatched Code Units.
		Color unmatchedCodeUnitsBackgroundColor =
			comparisonOptions.getUnmatchedCodeUnitsBackgroundColor();
		unmatchedCodeMarkers[LEFT].setMarkerColor(unmatchedCodeUnitsBackgroundColor);
		unmatchedCodeMarkers[RIGHT].setMarkerColor(unmatchedCodeUnitsBackgroundColor);
		Color diffCodeUnitsBackgroundColor = comparisonOptions.getDiffCodeUnitsBackgroundColor();
		diffMarkers[LEFT].setMarkerColor(diffCodeUnitsBackgroundColor);
		diffMarkers[RIGHT].setMarkerColor(diffCodeUnitsBackgroundColor);
		// Force a refresh by setting the program. This updates the colors in the navigation popup.
		markerManagers[LEFT].setProgram(getLeftProgram());
		markerManagers[RIGHT].setProgram(getRightProgram());
	}

	@Override
	public JComponent getComponent() {
		return this;
	}

	@Override
	public String getTitle() {
		return TITLE;
	}

	@Override
	public void setVisible(boolean aFlag) {
		super.setVisible(aFlag);
		updateActionEnablement();
	}

	private FormatManager createFormatManager(int leftOrRight) {
		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		FormatManager formatManager = new FormatManager(displayOptions, fieldOptions);

		ServiceProviderDecorator sp = ServiceProviderDecorator.createEmptyDecorator();
		sp.overrideService(GoToService.class,
			dualListingServiceProviders[leftOrRight].getService(GoToService.class));
		formatManager.setServiceProvider(sp);

		//
		// 							Unusual Code Alert!
		// In a normal tool, this option is registered by the Code Browse Plugin.  In the VT
		// tool, nobody registers this option.   Our system logs a warning if an option is used
		// but not registered.  So, when in a real tool, use the registered/managed option.
		// Otherwise, just use the default.
		//
		if (fieldOptions.isRegistered(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)) {
			cursorHighlightColor =
				fieldOptions.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR, CURSOR_LINE_COLOR);
		}
		else {
			cursorHighlightColor = CURSOR_LINE_COLOR;
		}

		return formatManager;
	}

	private void initializeGoToServiceProviders() {
		dualListingServiceProviders[LEFT] = new DualListingServiceProvider(tool, this, true);
		dualListingServiceProviders[RIGHT] = new DualListingServiceProvider(tool, this, false);
	}

	private void initializeListingFieldPanels() {
		FieldPanel[] fieldPanels = new FieldPanel[2];
		for (int i = 0; i < 2; i++) {
			fieldPanels[i] = listingPanels[i].getFieldPanel();
			fieldPanels[i].addFocusListener(this);
			fieldPanels[i].addMouseListener(new DualListingMouseListener(fieldPanels[i], i));
		}

		leftLocationListener = new LeftLocationListener();
		rightLocationListener = new RightLocationListener();
		fieldPanels[LEFT].addFieldLocationListener(leftLocationListener);
		fieldPanels[RIGHT].addFieldLocationListener(rightLocationListener);
	}

	/**
	 * Sets the coordinator for the two listings within this code comparison panel. It coordinates
	 * their scrolling and location synchronization.
	 * @param listingFieldPanelCoordinator the coordinator for the two listings
	 */
	@Override
	public void setFieldPanelCoordinator(
			ListingComparisonFieldPanelCoordinator listingFieldPanelCoordinator) {
		ListingComparisonFieldPanelCoordinator fieldPanelCoordinator = getFieldPanelCoordinator();
		if (fieldPanelCoordinator == listingFieldPanelCoordinator) {
			return;
		}

		super.setFieldPanelCoordinator(listingFieldPanelCoordinator);

		if (listingFieldPanelCoordinator != null) {
			ListingPanel focusedListingPanel = getFocusedListingPanel();
			ProgramLocation programLocation = focusedListingPanel.getProgramLocation();
			if (programLocation != null) {
				focusedListingPanel.goTo(programLocation);
			}
		}
	}

	/**
	 * Adds the indicated highlight providers for the left and right listing panels.
	 * @param leftHighlightProvider the highlight provider for the left side's listing.
	 * @param rightHighlightProvider the highlight provider for the right side's listing.
	 */
	public void addHighlightProviders(HighlightProvider leftHighlightProvider,
			HighlightProvider rightHighlightProvider) {
		addLeftHighlightProvider(leftHighlightProvider);
		addRightHighlightProvider(rightHighlightProvider);
	}

	private void addLeftHighlightProvider(HighlightProvider leftHighlightProvider) {
		listingPanels[LEFT].getFormatManager().addHighlightProvider(leftHighlightProvider);
	}

	private void addRightHighlightProvider(HighlightProvider rightHighlightProvider) {
		listingPanels[RIGHT].getFormatManager().addHighlightProvider(rightHighlightProvider);
	}

	/**
	 * Removes the indicated highlight providers from the left and right listing panels.
	 * @param leftHighlightProvider the highlight provider for the left side's listing.
	 * @param rightHighlightProvider the highlight provider for the right side's listing.
	 */
	public void removeHighlightProviders(HighlightProvider leftHighlightProvider,
			HighlightProvider rightHighlightProvider) {
		removeLeftHighlightProvider(leftHighlightProvider);
		removeRightHighlightProvider(rightHighlightProvider);
	}

	private void removeLeftHighlightProvider(HighlightProvider leftHighlightProvider) {
		listingPanels[LEFT].getFormatManager().removeHighlightProvider(leftHighlightProvider);
	}

	private void removeRightHighlightProvider(HighlightProvider rightHighlightProvider) {
		listingPanels[RIGHT].getFormatManager().removeHighlightProvider(rightHighlightProvider);
	}

	@Override
	protected void setPrograms(Program leftProgram, Program rightProgram) {
		boolean programChanged = false;
		if (leftProgram != programs[LEFT]) {
			programs[LEFT] = leftProgram;
			listingPanels[LEFT].setProgram(leftProgram);
			addressSets[LEFT] = EMPTY_ADDRESS_SET;
			indexMaps[LEFT] = new AddressIndexMap(addressSets[LEFT]);
			updateLeftListingTitle();
			programChanged = true;
		}
		if (rightProgram != programs[RIGHT]) {
			programs[RIGHT] = rightProgram;
			listingPanels[RIGHT].setProgram(rightProgram);
			addressSets[RIGHT] = EMPTY_ADDRESS_SET;
			indexMaps[RIGHT] = new AddressIndexMap(addressSets[RIGHT]);
			updateRightListingTitle();
			programChanged = true;
		}
		setupAreaMarkerSets();
		setupCursorMarkerSets();
		if (programChanged) {
			showEntireListing(isShowingEntireListing);
		}
	}

	private void updateLeftListingTitle() {
		titlePanels[LEFT].setTitleName(getLeftProgramName());
	}

	private String getLeftProgramName() {
		String leftProgramName =
			(programs[LEFT] != null) ? programs[LEFT].getDomainFile().toString() : "none";
		return leftProgramName;
	}

	private void updateRightListingTitle() {
		titlePanels[RIGHT].setTitleName(getRightProgramName());
	}

	private String getRightProgramName() {
		String rightProgramName =
			(programs[RIGHT] != null) ? programs[RIGHT].getDomainFile().toString() : "none";
		return rightProgramName;
	}

	private void initializeListingFieldNavigation() {
		initializeListingFieldNavigation(LEFT);
		initializeListingFieldNavigation(RIGHT);
	}

	private void initializeListingFieldNavigation(int leftOrRight) {
		boolean isLeftSide = (leftOrRight == LEFT);
		navigatables[leftOrRight] = new DualListingNavigator(this, isLeftSide);
		fieldNavigators[leftOrRight] =
			new FieldNavigator(dualListingServiceProviders[leftOrRight], navigatables[leftOrRight]);
		listingPanels[leftOrRight].addButtonPressedListener(fieldNavigators[leftOrRight]);
	}

	private Navigatable getFocusedNavigatable() {
		return navigatables[currProgramIndex];
	}

	private void initializeListingHoverService() {

		// The CodeFormatService is needed by the ReferenceHover.
		referenceHoverService = new ReferenceListingHover(tool, this);
		dataTypeHoverService = new DataTypeListingHover(tool);
		truncatedTextHoverService = new TruncatedTextListingHover(tool);
		functionNameHoverService = new FunctionNameListingHover(tool);

		initializeListingHoverService(LEFT);
		initializeListingHoverService(RIGHT);
	}

	private void initializeListingHoverService(int leftOrRight) {
		ListingPanel listingPanel = listingPanels[leftOrRight];
		listingPanel.addHoverService(referenceHoverService);
		listingPanel.addHoverService(dataTypeHoverService);
		listingPanel.addHoverService(truncatedTextHoverService);
		listingPanel.addHoverService(functionNameHoverService);
		listingPanel.setHoverMode(true);
	}

	/**
	 * Sets a listener for program location changes for the left side's listing panel.
	 * @param programLocationListener the listener
	 */
	public void setLeftProgramLocationListener(ProgramLocationListener programLocationListener) {
		listingPanels[LEFT].setProgramLocationListener(programLocationListener);
	}

	/**
	 * Sets a listener for program location changes for the right side's listing panel.
	 * @param programLocationListener the listener
	 */
	public void setRightProgramLocationListener(ProgramLocationListener programLocationListener) {
		listingPanels[RIGHT].setProgramLocationListener(programLocationListener);
	}

	private void createActions() {
		toggleHeaderAction = new ToggleHeaderAction();
		toggleOrientationAction = new ToggleOrientationAction();
		toggleHoverAction = new ToggleHoverAction();
		applyFunctionSignatureAction = new ApplyFunctionSignatureAction(owner);
		nextDiffAction = new NextDiffAction();
		previousDiffAction = new PreviousDiffAction();
		optionsAction = new ListingCodeComparisonOptionsAction();
		// NextDiff and PreviousDiff must be created before the area marker action.
		nextPreviousAreaMarkerAction = new NextPreviousAreaMarkerAction(owner);
		diffActions = getListingDiffActions();
	}

	private DockingAction[] getListingDiffActions() {
		return diffActionManager.getActions();
	}

	@Override
	public DockingAction[] getActions() {
		DockingAction[] codeCompActions = super.getActions();
		DockingAction[] otherActions = new DockingAction[] { toggleHeaderAction,
			toggleOrientationAction, toggleHoverAction, applyFunctionSignatureAction,
			nextPreviousAreaMarkerAction, nextDiffAction, previousDiffAction, optionsAction };
		int compCount = codeCompActions.length;
		int otherCount = otherActions.length;
		int diffCount = diffActions.length;
		DockingAction[] actions = new DockingAction[compCount + otherCount + diffCount];
		System.arraycopy(codeCompActions, 0, actions, 0, compCount);
		System.arraycopy(otherActions, 0, actions, compCount, otherCount);
		System.arraycopy(diffActions, 0, actions, compCount + otherCount, diffCount);
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

	class ToggleHeaderAction extends ToggleDockingAction {
		ToggleHeaderAction() {
			super("Dual Listing Toggle Header", owner);
			setDescription("Toggle Format Header");
			setEnabled(true);
			MenuData menuData = new MenuData(new String[] { "Show Listing Format Header" },
				DUAL_LISTING_ACTION_GROUP);
			setMenuBarData(menuData);

			setHelpLocation(
				new HelpLocation(DUAL_LISTING_HELP_TOPIC, "Dual Listing Toggle Format Header"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ListingPanel listingPanel = getLeftPanel();
			boolean show = !listingPanel.isHeaderShowing();
			listingPanel.showHeader(show);
			listingPanel.validate();
			listingPanel.invalidate();
		}
	}

	class ToggleOrientationAction extends ToggleDockingAction {
		ToggleOrientationAction() {
			super("Dual Listing Toggle Orientation", owner);
			setDescription("<HTML>Toggle the layout of the listings " +
				"<BR>between side-by-side and one above the other.</HTML>");
			setEnabled(true);
			setSelected(isSideBySide);
			MenuData menuData = new MenuData(new String[] { "Show Listings Side-by-Side" },
				DUAL_LISTING_ACTION_GROUP);
			setMenuBarData(menuData);

			setHelpLocation(
				new HelpLocation(DUAL_LISTING_HELP_TOPIC, "Dual Listing Toggle Orientation"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			boolean sideBySide = !isSideBySide();
			showSideBySide(sideBySide);
		}
	}

	class ToggleHoverAction extends ToggleDockingAction {
		ToggleHoverAction() {
			super("Dual Listing Toggle Mouse Hover Popups", owner);
			setEnabled(true);
			setToolBarData(new ToolBarData(HOVER_ON_ICON, HOVER_GROUP));
			setSelected(true);

			setHelpLocation(new HelpLocation(DUAL_LISTING_HELP_TOPIC,
				"Dual Listing Toggle Mouse Hover Popups"));
			setHover(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isShowing();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setHover(isSelected());
		}

		void setHover(boolean enabled) {
			getToolBarData().setIcon(enabled ? HOVER_ON_ICON : HOVER_OFF_ICON);
			setHoverEnabled(enabled);
		}
	}

	private void setHoverEnabled(boolean enabled) {
		listingPanels[LEFT].setHoverMode(enabled);
		listingPanels[RIGHT].setHoverMode(enabled);
	}

	private boolean isValidPanelContext(ActionContext context) {
		CodeComparisonPanel<? extends FieldPanelCoordinator> displayedPanel = null;
		if (context instanceof CodeComparisonPanelActionContext) {
			CodeComparisonPanelActionContext compareContext =
				(CodeComparisonPanelActionContext) context;
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel =
				compareContext.getCodeComparisonPanel();
			if (codeComparisonPanel == this) {
				displayedPanel = codeComparisonPanel;
			}
		}
		if (displayedPanel != ListingCodeComparisonPanel.this) {
			return false;
		}
		ListingCodeComparisonPanel dualListingPanel = (ListingCodeComparisonPanel) displayedPanel;
		ListingPanel leftPanel = dualListingPanel.getLeftPanel();
		ListingPanel rightPanel = dualListingPanel.getRightPanel();

		Object sourceObject = context.getSourceObject();
		if (sourceObject instanceof ListingPanel) {
			ListingPanel listingPanel = (ListingPanel) sourceObject;
			return listingPanel == leftPanel || listingPanel == rightPanel;
		}
		return true;
	}

	private void nextAreaDiff(String currentUserData, boolean forward) {
		boolean leftHasFocus = (currProgramIndex == LEFT);
		ListingPanel focusPanel = getFocusedListingPanel();
		ProgramLocation focusLocation = focusPanel.getProgramLocation();
		if (focusLocation == null) {
			tool.setStatusInfo("The " + (leftHasFocus ? "first" : "second") + " listing is empty.");
			return;
		}
		Address focusAddress = focusLocation.getAddress();

		ArrayList<AddressRangeIterator> iteratorList = new ArrayList<>();

		if (currentUserData.equals(ALL_AREA_MARKERS) || currentUserData.equals(DIFF_AREA_MARKERS)) {
			// DIFF Area Markers
			AddressSetView focusDiffs =
				leftHasFocus ? listingDiff.getListing1Diffs() : listingDiff.getListing2Diffs();
			iteratorList.add(focusDiffs.getAddressRanges(focusAddress, forward));
		}
		if (currentUserData.equals(ALL_AREA_MARKERS) ||
			currentUserData.equals(UNMATCHED_AREA_MARKERS)) {
			// UNMATCHED CODE Area Markers
			AddressSetView unmatchedCode = leftHasFocus ? listingDiff.getListing1UnmatchedCode()
					: listingDiff.getListing2UnmatchedCode();
			iteratorList.add(unmatchedCode.getAddressRanges(focusAddress, forward));
		}

		MultiAddressRangeIterator multiIterator = new MultiAddressRangeIterator(
			iteratorList.toArray(new AddressRangeIterator[iteratorList.size()]), forward);

		if (multiIterator.hasNext()) {
			AddressRange nextRange = multiIterator.next();
			Address minAddress = nextRange.getMinAddress();
			if ((forward ? nextRange.contains(focusAddress) : minAddress.equals(focusAddress)) &&
				multiIterator.hasNext()) {
				nextRange = multiIterator.next();
				minAddress = nextRange.getMinAddress();
			}
			if (minAddress.equals(focusAddress)) {
				outputNoNextPreviousMessage(forward, leftHasFocus);
				return;
			}
			tool.clearStatusInfo();
			focusPanel.goTo(minAddress);
		}
		else {
			outputNoNextPreviousMessage(forward, leftHasFocus);
		}
	}

	private void outputNoNextPreviousMessage(boolean forward, boolean isFirstListing) {
		tool.setStatusInfo("There isn't another " + (forward ? "next " : "previous ") +
			getCurrentAreaMarkerType().toLowerCase() + " area in the " +
			(isFirstListing ? "first" : "second") + " listing.");
	}

	private String getCurrentAreaMarkerType() {
		String type = "Highlighted";
		if (nextPreviousAreaType.equals(UNMATCHED_AREA_MARKERS)) {
			type = "Unmatched";
		}
		else if (nextPreviousAreaType.equals(DIFF_AREA_MARKERS)) {
			type = "Difference";
		}
		return type;
	}

	class NextPreviousAreaMarkerAction extends MultiStateDockingAction<String> {

		public NextPreviousAreaMarkerAction(String owner) {
			super("Dual Listing Next/Previous Area Marker", owner);

			ToolBarData toolBarData = new ToolBarData(diffsIcon, DIFF_NAVIGATE_GROUP);
			setToolBarData(toolBarData);

			HelpLocation helpLocation =
				new HelpLocation(DUAL_LISTING_HELP_TOPIC, "Dual Listing Next/Previous Area Marker");
			setHelpLocation(helpLocation);
			setDescription("Set Navigate Next/Previous Area Marker options");

			setPerformActionOnPrimaryButtonClick(false);

			ActionState<String> allAreaMarkers =
				new ActionState<>(ALL_AREA_MARKERS, bothIcon, ALL_AREA_MARKERS);
			allAreaMarkers.setHelpLocation(helpLocation);
			ActionState<String> unmatchedAreaMarkers =
				new ActionState<>(UNMATCHED_AREA_MARKERS, unmatchedIcon, UNMATCHED_AREA_MARKERS);
			unmatchedAreaMarkers.setHelpLocation(helpLocation);
			ActionState<String> diffAreaMarkers =
				new ActionState<>(DIFF_AREA_MARKERS, diffsIcon, DIFF_AREA_MARKERS);
			diffAreaMarkers.setHelpLocation(helpLocation);

			addActionState(allAreaMarkers);
			addActionState(unmatchedAreaMarkers);
			addActionState(diffAreaMarkers);

			setCurrentActionState(allAreaMarkers); // default
			adjustNextPreviousAreaType();
		}

		private void adjustNextPreviousAreaType() {
			nextPreviousAreaType = getCurrentUserData();
			nextDiffAction.setMenuString();
			previousDiffAction.setMenuString();
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isShowing() && listingDiff.hasCorrelation();
		}

		@Override
		public void actionStateChanged(ActionState<String> newActionState, EventTrigger trigger) {
			adjustNextPreviousAreaType();
		}

		public void refresh() {
			actionStateChanged(getCurrentState(), (EventTrigger) null);
		}
	}

	class NextDiffAction extends DockingAction {

		NextDiffAction() {
			super("Dual Listing Go To Next Area Marker", owner);
			setEnabled(true);
			setKeyBindingData(new KeyBindingData('N',
				DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.ALT_DOWN_MASK));
			setDescription("Go to the next highlighted area.");
			setPopupMenuData(new MenuData(new String[] { "Go To Next Highlighted Area" },
				NEXT_DIFF_ICON, DIFF_NAVIGATE_GROUP));
			ToolBarData newToolBarData = new ToolBarData(NEXT_DIFF_ICON, DIFF_NAVIGATE_GROUP);
			setToolBarData(newToolBarData);

			HelpLocation helpLocation = new HelpLocation(DUAL_LISTING_HELP_TOPIC,
				"Dual Listing Go To Next Highlighted Area");
			setHelpLocation(helpLocation);
			setEnabled(true);
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			return isValidPanelContext(context);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isShowing() && listingDiff.hasCorrelation();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isValidContext(context)) {
				nextAreaDiff(nextPreviousAreaType, true);
			}
		}

		void setMenuString() {
			String type = getCurrentAreaMarkerType();
			setPopupMenuData(new MenuData(new String[] { "Go To Next " + type + " Area" },
				NEXT_DIFF_ICON, DIFF_NAVIGATE_GROUP));
			setDescription("Go to the next " + type.toLowerCase() + " area.");
		}
	}

	class PreviousDiffAction extends DockingAction {

		PreviousDiffAction() {
			super("Dual Listing Go To Previous Area Marker", owner);
			setEnabled(true);
			setKeyBindingData(new KeyBindingData('P',
				DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.ALT_DOWN_MASK));
			setDescription("Go to the previous highlighted area.");
			setPopupMenuData(new MenuData(new String[] { "Go To Previous Highlighted Area" },
				PREVIOUS_DIFF_ICON, DIFF_NAVIGATE_GROUP));
			ToolBarData newToolBarData = new ToolBarData(PREVIOUS_DIFF_ICON, DIFF_NAVIGATE_GROUP);
			setToolBarData(newToolBarData);

			HelpLocation helpLocation = new HelpLocation(DUAL_LISTING_HELP_TOPIC,
				"Dual Listing Go To Previous Highlighted Area");
			setHelpLocation(helpLocation);
			setEnabled(true);
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			return isValidPanelContext(context);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isShowing() && listingDiff.hasCorrelation();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isValidContext(context)) {
				nextAreaDiff(nextPreviousAreaType, false);
			}
		}

		void setMenuString() {
			String type = getCurrentAreaMarkerType();
			setPopupMenuData(new MenuData(new String[] { "Go To Previous " + type + " Area" },
				PREVIOUS_DIFF_ICON, DIFF_NAVIGATE_GROUP));
			setDescription("Go to the previous " + type.toLowerCase() + " area.");
		}
	}

	class ListingCodeComparisonOptionsAction extends DockingAction {

		ListingCodeComparisonOptionsAction() {
			super("Listing Code Comparison Options", owner);
			setEnabled(true);
			setDescription("Show the tool options for the Listing Code Comparison.");
			setPopupMenuData(new MenuData(new String[] { "Properties" }, null, PROPERTIES_GROUP));
			setHelpLocation(
				new HelpLocation(DUAL_LISTING_HELP_TOPIC, "Listing_Code_Comparison_Options"));
			setEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isShowing() && listingDiff.hasCorrelation();
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			return isValidPanelContext(context);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			OptionsService service = tool.getService(OptionsService.class);
			service.showOptionsDialog(ListingCodeComparisonOptions.OPTIONS_CATEGORY_NAME,
				"Listing Code Comparison");
		}
	}

	public boolean isEntireListingShowing() {
		return isShowingEntireListing;
	}

	/**
	 * Sets whether or not the entire programs are displayed in the listings or only
	 * the addresses in the limited set.
	 * @param show if true, the entire program will be shown. Otherwise the listings will only
	 * show the limited addresses.
	 */
	public void showEntireListing(boolean show) {
		try {
			fieldLocationChanging = true;

			isShowingEntireListing = show;

			ProgramLocation leftLocation = listingPanels[LEFT].getProgramLocation();
			ProgramLocation rightLocation = listingPanels[RIGHT].getProgramLocation();
			if (show) {
				loadEntirePrograms();
			}
			else {
				loadLimitedAddresses();
			}
			if (leftLocation != null) {
				listingPanels[LEFT].goTo(leftLocation);
			}
			if (rightLocation != null) {
				listingPanels[RIGHT].goTo(rightLocation);
			}
		}
		finally {
			fieldLocationChanging = false;
		}
	}

	/**
	 * Determines if the listing's layout field header is currently showing.
	 * @return true if the header is showing.
	 */
	public boolean isHeaderShowing() {
		return getLeftPanel().isHeaderShowing();
	}

	/**
	 * Shows or hides the listing's layout field header.
	 * @param show true means show the field header. false means hide the header.
	 */
	public void setHeaderShowing(boolean show) {
		ListingPanel listingPanel = getLeftPanel();
		boolean isShowing = listingPanel.isHeaderShowing();
		if (show == isShowing) {
			return;
		}
		listingPanel.showHeader(show);
		toggleHeaderAction.setSelected(show);
	}

	public boolean isSideBySide() {
		return isSideBySide;
	}

	/**
	 * Sets whether or not the listings are displayed side by side.
	 * @param sideBySide if true, the listings are side by side, otherwise one is above the other.
	 */
	public void showSideBySide(boolean sideBySide) {
		isSideBySide = sideBySide;
		splitPane.setOrientation(
			isSideBySide ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT);
		splitPane.setDividerLocation(0.5);
		toggleOrientationAction.setSelected(sideBySide);
	}

	private void loadEntirePrograms() {
		AddressSetView leftSet =
			(programs[LEFT] != null) ? programs[LEFT].getMemory() : EMPTY_ADDRESS_SET;
		AddressSetView rightSet =
			(programs[RIGHT] != null) ? programs[RIGHT].getMemory() : EMPTY_ADDRESS_SET;
		ListingComparisonFieldPanelCoordinator fieldPanelCoordinator = getFieldPanelCoordinator();
		if (fieldPanelCoordinator != null) {
			fieldPanelCoordinator.resetLockedLines();
		}
		listingPanels[LEFT].setView(leftSet);
		listingPanels[RIGHT].setView(rightSet);
	}

	private void loadLimitedAddresses() {
		AddressSetView leftSet =
			(addressSets[LEFT] != null) ? addressSets[LEFT] : EMPTY_ADDRESS_SET;
		AddressSetView rightSet =
			(addressSets[RIGHT] != null) ? addressSets[RIGHT] : EMPTY_ADDRESS_SET;
		ListingComparisonFieldPanelCoordinator fieldPanelCoordinator = getFieldPanelCoordinator();
		if (fieldPanelCoordinator != null) {
			fieldPanelCoordinator.resetLockedLines();
		}
		listingPanels[LEFT].setView(leftSet);
		listingPanels[RIGHT].setView(rightSet);
	}

	@Override
	public void loadFunctions(Function leftFunction, Function rightFunction) {
		setFunctions(leftFunction, rightFunction);
	}

	/**
	 * Gets the function loaded in the left listing panel.
	 * @return the function or null
	 */
	@Override
	public Function getLeftFunction() {
		return functions[LEFT];
	}

	/**
	 * Gets the function loaded in the right listing panel.
	 * @return the function or null
	 */
	@Override
	public Function getRightFunction() {
		return functions[RIGHT];
	}

	private void setFunctions(Function leftFunction, Function rightFunction) {

		if (leftFunction != functions[LEFT] || rightFunction != functions[RIGHT]) {
			clearMarkers();

			Program leftProgram =
				((leftFunction != null) ? leftFunction.getProgram() : programs[LEFT]);
			Program rightProgram =
				((rightFunction != null) ? rightFunction.getProgram() : programs[RIGHT]);
			setPrograms(leftProgram, rightProgram);
			// Adjust the data and functions only after the correct programs are set.
			data[LEFT] = null;
			data[RIGHT] = null;
			functions[LEFT] = leftFunction;
			functions[RIGHT] = rightFunction;
			setFunctionTitles();
		}
		doLoadFunctions(leftFunction, rightFunction, TaskMonitor.DUMMY);
		if (leftFunction == null || rightFunction == null) {
			correlator = null; // Clear the correlation. Need 2 functions for a correlation.
		}
		try {
			listingDiff.setCorrelation(correlator);
			// Setting the correlation will also reset the locked line numbers.
			ListingComparisonFieldPanelCoordinator fieldPanelCoordinator =
				getFieldPanelCoordinator();
			if (fieldPanelCoordinator != null) {
				fieldPanelCoordinator.setCorrelation(correlator);
			}
		}
		catch (MemoryAccessException e) {
			String leftName = (leftFunction != null) ? leftFunction.getName() : "No Function";
			String rightName = (rightFunction != null) ? rightFunction.getName() : "No Function";
			Msg.error(this, "Failed to load functions, " + leftName + " and " + rightName +
				" , into dual listing panel. " + e.getMessage(), e);
		}
		loadCursorArrow();
		updateActionEnablement();
	}

	/**
	 * Establishes the location and display of the arrow cursor. This method should be called
	 * after the function comparison window is loaded with functions, data, etc.
	 */
	private void loadCursorArrow() {
		int focusedSide = currProgramIndex;
		boolean leftHasFocus = (focusedSide == LEFT);
		int nonFocusedSide = leftHasFocus ? RIGHT : LEFT;
		ProgramLocation focusedProgramLocation = listingPanels[focusedSide].getProgramLocation();
		ProgramLocation nonFocusedProgramLocation = null;
		if (focusedProgramLocation != null) {
			nonFocusedProgramLocation =
				getProgramLocation((leftHasFocus ? RIGHT : LEFT), focusedProgramLocation);
		}

		if (focusedProgramLocation != null) {
			setCursorMarkers(focusedSide, focusedProgramLocation);
		}
		else {
			//remove obsolete cursor background highlight for cursor on focused side
			listingPanels[focusedSide].getFieldPanel().repaint();
		}

		if (nonFocusedProgramLocation != null) {
			setCursorMarkers(nonFocusedSide, nonFocusedProgramLocation);
		}
		else {
			//remove obsolete cursor background highlight for cursor on non-focused side
			listingPanels[nonFocusedSide].getFieldPanel().repaint();
		}
	}

	/**
	 * Gets an equivalent left side program location when given a right side program location or
	 * vice versa. The intent of this method is to translate a location from one side of the
	 * dual listing to an equivalent location for the other side if possible.
	 * @param leftOrRight LEFT or RIGHT indicating which side's program location is needed.
	 * @param programLocation the program location for the other side.
	 * @return a program location for the desired side. Otherwise, null.
	 */
	private ProgramLocation getProgramLocation(int leftOrRight, ProgramLocation programLocation) {
		if (programLocation == null) {
			return null;
		}
		if (programLocation instanceof VariableLocation) {
			return getVariableLocation(leftOrRight, (VariableLocation) programLocation);
		}

		SaveState saveState = new SaveState();
		programLocation.saveState(saveState);
		Address address = programLocation.getAddress();

		// Try to get the indicated side's address using one of the address correlators.
		Address desiredAddress = getAddress(leftOrRight, address);
		if (desiredAddress == null || desiredAddress == Address.NO_ADDRESS) {
			return null; // Couldn't determine the indicated side's address.
		}

		saveState.remove("_ADDRESS");
		saveState.putString("_ADDRESS", desiredAddress.toString());

		Address byteAddress = programLocation.getByteAddress();
		saveState.remove("_BYTE_ADDR");
		Address desiredByteAddress = null;
		if (byteAddress != null) {
			// Try to get the indicated side's byte address using one of the address 
			// correlators or by inferring it.
			desiredByteAddress = inferDesiredByteAddress(address, desiredAddress, byteAddress,
				programLocation.getProgram(), programs[leftOrRight]);
			if (desiredByteAddress != null) {
				saveState.putString("_BYTE_ADDR", desiredByteAddress.toString());
			}
		}

		// Adjust symbol path for labels if it is part of the location.
		adjustSymbolPath(saveState, address, desiredAddress, byteAddress, desiredByteAddress,
			programLocation.getProgram(), programs[leftOrRight]);

		// ref address can't be used with indicated side so remove it.
		saveState.remove("_REF_ADDRESS");
		// Don't know how to find equivalent referenced address for the indicated side,
		// so don't put any _REF_ADDRESS back.

		return ProgramLocation.getLocation(programs[leftOrRight], saveState);
	}

	private void adjustSymbolPath(SaveState saveState, Address address, Address desiredAddress,
			Address byteAddress, Address desiredByteAddress, Program program,
			Program desiredProgram) {

		String[] symbolPathArray = saveState.getStrings("_SYMBOL_PATH", new String[0]);
		saveState.remove("_SYMBOL_PATH");
		if (symbolPathArray.length == 0) {
			return; // save state has no labels for program location.
		}
		Address symbolAddress = (byteAddress != null) ? byteAddress : address;
		Address desiredSymbolAddress =
			(desiredByteAddress != null) ? desiredByteAddress : desiredAddress;
		if (symbolAddress == null || desiredSymbolAddress == null) {
			return; // no address match.
		}
		Symbol[] symbols = program.getSymbolTable().getSymbols(symbolAddress);
		if (symbols.length == 0) {
			return; // no symbols in program for matching.
		}
		Symbol[] desiredSymbols = desiredProgram.getSymbolTable().getSymbols(desiredSymbolAddress);
		if (desiredSymbols.length == 0) {
			return; // no symbols in desiredProgram for matching.
		}

		int desiredRow = adjustSymbolRow(saveState, symbols, desiredSymbols);

		int desiredIndex = getDesiredSymbolIndex(desiredSymbols, desiredRow);

		// Now get the desired symbol.
		Symbol desiredSymbol = desiredSymbols[desiredIndex];
		SymbolPath symbolPath = getSymbolPath(desiredSymbol);
		// Set symbol path for desiredProgram in the save state.
		saveState.putStrings("_SYMBOL_PATH", symbolPath.asArray());
	}

	private int adjustSymbolRow(SaveState saveState, Symbol[] symbols, Symbol[] desiredSymbols) {
		// For now just try to choose the same label index if more than one.
		int row = saveState.getInt("_ROW", 0);
		int desiredRow = row;
		if ((desiredRow >= desiredSymbols.length) || // desiredRow is beyond last one so set to last row.
			(isFunctionCompare() && (row == (symbols.length - 1)))) { // row is function so set to last row.

			desiredRow = desiredSymbols.length - 1;
		}
		saveState.remove("_ROW");
		saveState.putInt("_ROW", desiredRow);
		return desiredRow;
	}

	private int getDesiredSymbolIndex(Symbol[] desiredSymbols, int desiredRow) {

		boolean hasFunction = desiredSymbols[0].getSymbolType().equals(SymbolType.FUNCTION);

		// Get the array index of the desired symbol.
		int desiredIndex = 0; // Default to first entry in array.
		if (desiredRow >= 0 && desiredRow < desiredSymbols.length) {
			desiredIndex = desiredRow;
		}
		if (hasFunction) {
			// Last row in GUI is also first entry in array.
			if (desiredIndex == desiredSymbols.length - 1) {
				desiredIndex = 0; // Set to function element.
			}
			else {
				desiredIndex++; // Adjust for function element at start of array.
			}
		}
		return desiredIndex;
	}

	private SymbolPath getSymbolPath(Symbol desiredSymbol) {
		String label = desiredSymbol.getName();
		Namespace namespace = desiredSymbol.getParentNamespace();
		SymbolPath symbolPath;
		if (namespace == null || namespace.isGlobal()) {
			symbolPath = new SymbolPath(label);
		}
		else {
			symbolPath = new SymbolPath(new SymbolPath(namespace.getSymbol()), label);
		}
		return symbolPath;
	}

	/**
	 * Infers a desired byte address based on the specified <code>byteAddress</code> as well 
	 * as the <code>address</code> and <code>desiredAddress</code> that were matched.
	 * @param address matches up with the <code>desiredAddress</code> from the other function/data.
	 * @param desiredAddress matches up with the <code>address</code> from the other function/data.
	 * @param byteAddress the byte address that is associated with <code>address</code>
	 * @param program the program for the <code>address</code> and <code>byteAddress</code>.
	 * @param desiredProgram the program for the <code>desiredAddress</code> and 
	 * <code>desiredByteAddress</code>.
	 * @return the desired byte address that matches up with the indicated <code>byteAddress</code>
	 * or null if it can't be determined.
	 */
	private Address inferDesiredByteAddress(Address address, Address desiredAddress,
			Address byteAddress, Program program, Program desiredProgram) {

		// Functions and Data have their addresses inferred differently.
		// Functions can use the address correlator for code units, while internal addresses
		// may get matched for Data.
		if (isFunctionCompare()) {
			return inferDesiredFunctionAddress(address, desiredAddress, byteAddress, program,
				desiredProgram);
		}
		if (isDataCompare()) {
			return inferDesiredDataAddress(address, desiredAddress, byteAddress, program,
				desiredProgram);
		}
		return null;
	}

	/**
	 * This infers the desired byte address within Data based on the code units at 
	 * <code>codeUnitAddress</code> and <code>desiredCodeUnitAddress</code>.
	 * The inferred address will be at an offset from the <code>desiredCodeUnitAddress</code> 
	 * that is the same distance the <code>byteAddress</code> is from the <code>codeUnitAddress</code>.
	 * 
	 * @param codeUnitAddress matches up with the <code>desiredCodeUnitAddress</code> from 
	 * the other data.
	 * @param desiredCodeUnitAddress matches up with the <code>codeUnitAddress</code> from 
	 * the other data.
	 * @param byteAddress the byte address that is associated with <code>codeUnitAddress</code>
	 * @param program the program for the <code>codeUnitAddress</code> and <code>byteAddress</code>.
	 * @param desiredProgram the program for the <code>desiredCodeUnitAddress</code> and 
	 * <code>desiredByteAddress</code>.
	 * @return the desired byte address within the data that matches up with the indicated 
	 * <code>byteAddress</code> or null if it can't be determined.
	 */
	private Address inferDesiredDataAddress(Address codeUnitAddress, Address desiredCodeUnitAddress,
			Address byteAddress, Program program, Program desiredProgram) {

		long offset = byteAddress.subtract(codeUnitAddress);
		if (offset == 0) {
			return desiredCodeUnitAddress;
		}
		if (offset > 0) {
			CodeUnit codeUnit = program.getListing().getCodeUnitContaining(codeUnitAddress);
			CodeUnit desiredCodeUnit =
				desiredProgram.getListing().getCodeUnitContaining(desiredCodeUnitAddress);
			if (codeUnit != null && desiredCodeUnit != null) {
				try {
					return desiredCodeUnitAddress.add(offset);
				}
				catch (AddressOutOfBoundsException e) {
					return null; // No matching address.
				}
			}
		}
		return null; // No matching address.
	}

	/**
	 * This infers the desired byte address within a function based on the code units at 
	 * <code>address</code> and <code>desiredAddress</code>.
	 * If the inferred address would be beyond the last byte of the code unit then it 
	 * will get set to the last byte of the code unit at the <code>desiredAddress</code>.
	 * 
	 * @param address matches up with the <code>desiredAddress</code> from the other function.
	 * @param desiredAddress matches up with the <code>address</code> from the other function.
	 * @param byteAddress the byte address that is associated with <code>address</code>
	 * @param program the program for the <code>address</code> and <code>byteAddress</code>.
	 * @param desiredProgram the program for the <code>desiredAddress</code> and 
	 * <code>desiredByteAddress</code>.
	 * @return the desired byte address within the data that matches up with the indicated 
	 * <code>byteAddress</code> or null if it can't be determined.
	 */
	private Address inferDesiredFunctionAddress(Address address, Address desiredAddress,
			Address byteAddress, Program program, Program desiredProgram) {

		long numBytesIntoCodeUnit = byteAddress.subtract(address);
		if (numBytesIntoCodeUnit == 0) {
			return desiredAddress;
		}
		if (numBytesIntoCodeUnit > 0) {
			CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
			CodeUnit desiredCodeUnit = desiredProgram.getListing().getCodeUnitAt(desiredAddress);
			if (codeUnit != null && desiredCodeUnit != null) {
				int desiredCodeUnitLength = desiredCodeUnit.getLength();
				if (numBytesIntoCodeUnit < desiredCodeUnitLength) {
					// Position at byte within code unit.
					return desiredAddress.add(numBytesIntoCodeUnit);
				}
				// Otherwise position at last byte of code unit.
				return desiredAddress.add(desiredCodeUnitLength - 1);
			}
		}
		return null;
	}

	/**
	 * Gets an equivalent left side variable location when given a right side variable location or
	 * vice versa. The intent of this method is to translate a variable location from one side of
	 * the dual listing to an equivalent variable location for the other side if possible.
	 * @param leftOrRight LEFT or RIGHT indicating which side's variable location is needed.
	 * @param variableLocation the variable location for the other side.
	 * @return a variable location for the desired side. Otherwise, null.
	 */
	private ProgramLocation getVariableLocation(int leftOrRight,
			VariableLocation variableLocation) {
		if (variableLocation == null) {
			return null;
		}
		SaveState saveState = new SaveState();
		variableLocation.saveState(saveState);
		Address address = variableLocation.getAddress();
		Address byteAddress = variableLocation.getByteAddress();
		Address functionAddress = variableLocation.getFunctionAddress();

		// Try to get the indicated side's address using one of the address correlators.
		Address desiredAddress = getAddress(leftOrRight, address);
		if (desiredAddress == null || desiredAddress == Address.NO_ADDRESS) {
			return null; // Couldn't determine the indicated side's address.
		}

		// Try to use a byte address.
		Address desiredByteAddress = null;
		if (byteAddress != null) {
			desiredByteAddress = getAddress(leftOrRight, byteAddress);
		}

		Address desiredFunctionAddress = null;
		if (functionAddress != null) {
			desiredFunctionAddress = getAddress(leftOrRight, functionAddress);
		}
		if ((desiredFunctionAddress == null) && (functions[leftOrRight] != null)) {
			// If this is a thunk function get the thunked address.
			Function thunkedFunction = functions[leftOrRight].getThunkedFunction(true);
			if (thunkedFunction != null) {
				desiredFunctionAddress = thunkedFunction.getEntryPoint();
			}
		}

		saveState.remove("_ADDRESS");
		saveState.putString("_ADDRESS", desiredAddress.toString());

		saveState.remove("_BYTE_ADDR");
		if (desiredByteAddress != null) {
			saveState.putString("_BYTE_ADDR", desiredByteAddress.toString());
		}

		saveState.remove("_FUNC_ADDRESS");
		if (desiredFunctionAddress != null) {
			saveState.putString("_FUNC_ADDRESS", desiredFunctionAddress.toString());
		}

		// ref address can't be used with indicated side so remove it.
		saveState.remove("_REF_ADDRESS");
		// Don't know how to find equivalent referenced address for the indicated side,
		// so don't put any _REF_ADDRESS back.

		return ProgramLocation.getLocation(programs[leftOrRight], saveState);
	}

	private void clearMarkers() {
		clearUnmatchedCodeMarkers();
		clearDiffMarkers();
		clearCursorMarkers();
	}

	private void clearUnmatchedCodeMarkers() {
		if (unmatchedCodeMarkers[LEFT] != null) {
			unmatchedCodeMarkers[LEFT].clearAll();
		}
		if (unmatchedCodeMarkers[RIGHT] != null) {
			unmatchedCodeMarkers[RIGHT].clearAll();
		}
	}

	private void clearDiffMarkers() {
		if (diffMarkers[LEFT] != null) {
			diffMarkers[LEFT].clearAll();
		}
		if (diffMarkers[RIGHT] != null) {
			diffMarkers[RIGHT].clearAll();
		}
	}

	private void setCursorMarkers(int leftOrRight, ProgramLocation location) {
		if (currentCursorMarkers[leftOrRight] != null) {
			currentCursorMarkers[leftOrRight].clearAll();
			if (location != null) {
				currentCursorMarkers[leftOrRight].add(location.getAddress());
			}
		}
	}

	private void clearCursorMarkers() {
		if (currentCursorMarkers[LEFT] != null) {
			currentCursorMarkers[LEFT].clearAll();

		}
		if (currentCursorMarkers[RIGHT] != null) {
			currentCursorMarkers[RIGHT].clearAll();
		}
	}

	private void setFunctionTitles() {
		setLeftTitle(getFunctionTitle(functions[LEFT]));
		setRightTitle(getFunctionTitle(functions[RIGHT]));
	}

	private String getFunctionTitle(Function function) {
		if (function == null) {
			return "none";
		}
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);

		String functionStr = HTMLUtilities.friendlyEncodeHTML(function.getName(true) + "()");
		String specialFunctionStr = HTMLUtilities.bold(functionStr);
		buf.append(specialFunctionStr);

		Program program = function.getProgram();
		if (program != null) {
			buf.append(" in ");

			String programStr =
				HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
			String specialProgramStr = HTMLUtilities.colorString(Color.DARK_GRAY, programStr);
			buf.append(specialProgramStr);
			buf.append(padStr);
		}
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	private void setDataTitles() {
		setLeftTitle(getDataTitle(data[LEFT]));
		setRightTitle(getDataTitle(data[RIGHT]));
	}

	private String getDataTitle(Data currentData) {
		if (currentData == null) {
			return "none";
		}
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);

		String dataLabel = currentData.getLabel();
		if (dataLabel == null) { // If we can't get a label for the data then use the address .
			Address address = currentData.getAddress();
			dataLabel = address.toString();
		}
		String dataStr = HTMLUtilities.friendlyEncodeHTML(dataLabel);
		String specialDataStr = HTMLUtilities.bold(dataStr);
		buf.append(specialDataStr);

		Program program = currentData.getProgram();
		if (program != null) {
			buf.append(" in ");

			String programStr =
				HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
			String specialProgramStr = HTMLUtilities.colorString(Color.DARK_GRAY, programStr);
			buf.append(specialProgramStr);
			buf.append(padStr);
		}
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	private void setAddressesTitles() {
		setLeftTitle(getAddressesTitle(programs[LEFT], addressSets[LEFT]));
		setRightTitle(getAddressesTitle(programs[RIGHT], addressSets[RIGHT]));
	}

	private String getAddressesTitle(Program program, AddressSetView addresses) {
		if (program == null) {
			return "none";
		}
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);
		String programStr = HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
		String specialProgramStr = HTMLUtilities.colorString(Color.DARK_GRAY, programStr);
		buf.append(specialProgramStr);
		buf.append(padStr);
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	private void setDiffHighlights() {
		setFunctionComparisonDiffHighlights();
		setUnmatchedCodeUnitAreaMarkers();
		setDiffAreaMarkers();
	}

	private void setFunctionComparisonDiffHighlights() {
		// Remove old highlight providers if they exist.
		removeHighlightProviders(leftDiffHighlightProvider, rightDiffHighlightProvider);

		leftDiffHighlightProvider =
			new ListingDiffHighlightProvider(listingDiff, true, comparisonOptions);
		rightDiffHighlightProvider =
			new ListingDiffHighlightProvider(listingDiff, false, comparisonOptions);
		addHighlightProviders(leftDiffHighlightProvider, rightDiffHighlightProvider);
	}

	private void setDiffAreaMarkers() {
		Color codeUnitDiffsBackgroundColor = comparisonOptions.getDiffCodeUnitsBackgroundColor();
		AddressSetView listing1Diffs = listingDiff.getListing1Diffs();
		AddressSetView listing2Diffs = listingDiff.getListing2Diffs();
		if (diffMarkers[LEFT] != null) {
			diffMarkers[LEFT].setMarkerColor(codeUnitDiffsBackgroundColor);
			diffMarkers[LEFT].clearAll();
			diffMarkers[LEFT].add(listing1Diffs);
			listingPanels[LEFT].getFieldPanel().repaint();
		}
		if (diffMarkers[RIGHT] != null) {
			diffMarkers[RIGHT].setMarkerColor(codeUnitDiffsBackgroundColor);
			diffMarkers[RIGHT].clearAll();
			diffMarkers[RIGHT].add(listing2Diffs);
			listingPanels[RIGHT].getFieldPanel().repaint();
		}
	}

	private void setUnmatchedCodeUnitAreaMarkers() {
		Color unmatchedCodeUnitsBackgroundColor =
			comparisonOptions.getUnmatchedCodeUnitsBackgroundColor();
		AddressSetView listing1UnmatchedCode = listingDiff.getListing1UnmatchedCode();
		AddressSetView listing2UnmatchedCode = listingDiff.getListing2UnmatchedCode();
		if (unmatchedCodeMarkers[LEFT] != null) {
			unmatchedCodeMarkers[LEFT].setMarkerColor(unmatchedCodeUnitsBackgroundColor);
			unmatchedCodeMarkers[LEFT].clearAll();
			unmatchedCodeMarkers[LEFT].add(listing1UnmatchedCode);
			listingPanels[LEFT].getFieldPanel().repaint();
		}
		if (unmatchedCodeMarkers[RIGHT] != null) {
			unmatchedCodeMarkers[RIGHT].setMarkerColor(unmatchedCodeUnitsBackgroundColor);
			unmatchedCodeMarkers[RIGHT].clearAll();
			unmatchedCodeMarkers[RIGHT].add(listing2UnmatchedCode);
			listingPanels[RIGHT].getFieldPanel().repaint();
		}
	}

	private void setupMarkerManagers() {
		setupMarkerManager(LEFT);
		setupMarkerManager(RIGHT);
	}

	private void setupMarkerManager(int leftOrRight) {
		if (markerManagers[leftOrRight] == null) {
			markerManagers[leftOrRight] =
				new DualListingMarkerManager(owner, tool, dualListingServiceProviders[leftOrRight]);

			// setup a marker change listener that can repaint the listing as markers are enabled/disabled.
			markerManagers[leftOrRight].addChangeListener(new MarkerChangeListener(leftOrRight));

			// Set up the marker margin that is on the left side of the listing.
			MarginProvider marginProvider = markerManagers[leftOrRight].getMarginProvider();
			JComponent providerComp = marginProvider.getComponent();
			DualListingMouseListener providerMouseListener =
				new DualListingMouseListener(providerComp, leftOrRight);
			providerComp.addMouseListener(providerMouseListener);
			listingPanels[leftOrRight].addMarginProvider(marginProvider);

			// Set up the overview margin that is on the right side of the listing.
			OverviewProvider overviewProvider = markerManagers[leftOrRight].getOverviewProvider();
			JComponent overviewComp = overviewProvider.getComponent();
			DualListingMouseListener overviewMouseListener =
				new DualListingMouseListener(overviewComp, leftOrRight);
			overviewComp.addMouseListener(overviewMouseListener);
			listingPanels[leftOrRight].addOverviewProvider(overviewProvider);
		}
	}

	private void setupAreaMarkerSets() {
		Color diffCodeUnitsBackgroundColor = comparisonOptions.getDiffCodeUnitsBackgroundColor();
		Color unmatchedCodeUnitsBackgroundColor =
			comparisonOptions.getUnmatchedCodeUnitsBackgroundColor();
		if (programs[LEFT] != null) {
			AddressIndexMap indexMap = listingPanels[LEFT].getAddressIndexMap();
			listingPanels[LEFT].getFieldPanel()
					.setBackgroundColorModel(
						new MarkerServiceBackgroundColorModel(markerManagers[LEFT], indexMap));
			markerManagers[LEFT].setProgram(programs[LEFT]);
			unmatchedCodeMarkers[LEFT] =
				markerManagers[LEFT].createAreaMarker("Listing1 Unmatched Code",
					"Instructions that are not matched to an instruction in the other function.",
					programs[LEFT], MarkerService.DIFF_PRIORITY, true, true, true,
					unmatchedCodeUnitsBackgroundColor);
			diffMarkers[LEFT] = markerManagers[LEFT].createAreaMarker("Listing1 Diffs",
				"Instructions that have a difference.", programs[LEFT], MarkerService.DIFF_PRIORITY,
				true, true, true, diffCodeUnitsBackgroundColor);
		}
		if (programs[RIGHT] != null) {
			AddressIndexMap rightIndexMap = listingPanels[RIGHT].getAddressIndexMap();
			listingPanels[RIGHT].getFieldPanel()
					.setBackgroundColorModel(
						new MarkerServiceBackgroundColorModel(markerManagers[RIGHT],
							rightIndexMap));
			markerManagers[RIGHT].setProgram(programs[RIGHT]);
			unmatchedCodeMarkers[RIGHT] =
				markerManagers[RIGHT].createAreaMarker("Listing2 Unmatched Code",
					"Instructions that are not matched to an instruction in the other function.",
					programs[RIGHT], MarkerService.DIFF_PRIORITY, true, true, true,
					unmatchedCodeUnitsBackgroundColor);
			diffMarkers[RIGHT] = markerManagers[RIGHT].createAreaMarker("Listing2 Diffs",
				"Instructions that have a difference.", programs[RIGHT],
				MarkerService.DIFF_PRIORITY, true, true, true, diffCodeUnitsBackgroundColor);

		}
	}

	private void setupCursorMarkerSets() {
		if (programs[LEFT] != null) {
			currentCursorMarkers[LEFT] = markerManagers[LEFT].createPointMarker("Cursor",
				"Cursor Location", programs[LEFT], MarkerService.FUNCTION_COMPARE_CURSOR_PRIORITY,
				true, true, true, cursorHighlightColor, CURSOR_LOC_ICON, false);
		}
		if (programs[RIGHT] != null) {
			currentCursorMarkers[RIGHT] = markerManagers[RIGHT].createPointMarker("Cursor",
				"Cursor Location", programs[RIGHT], MarkerService.FUNCTION_COMPARE_CURSOR_PRIORITY,
				true, true, true, cursorHighlightColor, CURSOR_LOC_ICON, false);
		}
	}

	private void doLoadFunctions(Function leftFunction, Function rightFunction,
			TaskMonitor monitor) {
		try {
			fieldLocationChanging = true;
			updateLeftAddressSet(leftFunction);
			updateRightAddressSet(rightFunction);
			try {
				correlator =
					new HashedFunctionAddressCorrelation(leftFunction, rightFunction, monitor);
			}
			catch (CancelledException e) {
				correlator = null;
			}
			catch (MemoryAccessException e) {
				correlator = null;
			}
			if (isShowingEntireListing) {
				loadEntirePrograms();
			}
			else {
				loadLimitedAddresses();
			}
			goToLeftFunction(leftFunction);
			goToRightFunction(rightFunction);
			validate();
		}
		finally {
			fieldLocationChanging = false;
		}
	}

	private void goToLeftFunction(Function leftFunction) {
		if (leftFunction != null && !adjustingLeftLocation) {
			try {
				adjustingLeftLocation = true;

				listingPanels[LEFT].goTo(new FunctionSignatureFieldLocation(
					leftFunction.getProgram(), leftFunction.getEntryPoint(), null, 0,
					leftFunction.getPrototypeString(false, false)));
			}
			finally {
				adjustingLeftLocation = false;
			}
		}
	}

	private void goToRightFunction(Function rightFunction) {
		if (rightFunction != null && !adjustingRightLocation) {
			try {
				adjustingRightLocation = true;

				listingPanels[RIGHT].goTo(new FunctionSignatureFieldLocation(
					rightFunction.getProgram(), rightFunction.getEntryPoint(), null, 0,
					rightFunction.getPrototypeString(false, false)));
			}
			finally {
				adjustingRightLocation = false;
			}
		}
	}

	private void updateLeftAddressSet(Function leftFunction) {
		addressSets[LEFT] = (leftFunction != null) ? leftFunction.getBody() : EMPTY_ADDRESS_SET;

		// If we have a function and no addresses, then set the entry point as the address set.
		// This allows external functions to be displayed.
		if (leftFunction != null && addressSets[LEFT].isEmpty()) {
			Address entryPoint = leftFunction.getEntryPoint();
			addressSets[LEFT] = new AddressSet(leftFunction.getProgram(), entryPoint, entryPoint);
		}

		indexMaps[LEFT] = new AddressIndexMap(addressSets[LEFT]);
		markerManagers[LEFT].getOverviewProvider().setAddressIndexMap(indexMaps[LEFT]);
		listingPanels[LEFT].getFieldPanel()
				.setBackgroundColorModel(
					new MarkerServiceBackgroundColorModel(markerManagers[LEFT], indexMaps[LEFT]));
	}

	private void updateRightAddressSet(Function rightFunction) {
		addressSets[RIGHT] = (rightFunction != null) ? rightFunction.getBody() : EMPTY_ADDRESS_SET;

		// If we have a function and no addresses, then set the entry point as the address set.
		// This allows external functions to be displayed.
		if (rightFunction != null && addressSets[RIGHT].isEmpty()) {
			Address entryPoint = rightFunction.getEntryPoint();
			addressSets[RIGHT] = new AddressSet(rightFunction.getProgram(), entryPoint, entryPoint);
		}

		indexMaps[RIGHT] = new AddressIndexMap(addressSets[RIGHT]);
		markerManagers[RIGHT].getOverviewProvider().setAddressIndexMap(indexMaps[RIGHT]);
		listingPanels[RIGHT].getFieldPanel()
				.setBackgroundColorModel(
					new MarkerServiceBackgroundColorModel(markerManagers[RIGHT], indexMaps[RIGHT]));
	}

	@Override
	public void loadAddresses(Program leftProgram, Program rightProgram,
			AddressSetView leftAddresses, AddressSetView rightAddresses) {

		setPrograms(leftProgram, rightProgram);
		try {
			fieldLocationChanging = true;
			addressSets[LEFT] =
				(leftProgram != null && leftAddresses != null) ? leftAddresses : EMPTY_ADDRESS_SET;
			addressSets[RIGHT] = (rightProgram != null && rightAddresses != null) ? rightAddresses
					: EMPTY_ADDRESS_SET;
			clearCorrelation();
			if (isShowingEntireListing) {
				loadEntirePrograms();
			}
			else {
				loadLimitedAddresses();
			}
			setAddressesTitles();
			if (programs[LEFT] != null && !addressSets[LEFT].isEmpty()) {
				listingPanels[LEFT].goTo(
					new ProgramLocation(programs[LEFT], addressSets[LEFT].getMinAddress()));
			}
			if (programs[RIGHT] != null && !addressSets[RIGHT].isEmpty()) {
				listingPanels[RIGHT].goTo(
					new ProgramLocation(programs[RIGHT], addressSets[RIGHT].getMinAddress()));
			}
		}
		finally {
			loadCursorArrow();
			updateActionEnablement();
			fieldLocationChanging = false;
		}
	}

	/**
	 * Sets the cursor location in the left and right listing at the specified functions.
	 * @param leftFunction the function in the left listing panel.
	 * @param rightFunction the function in the right listing panel.
	 */
	public void setLocation(Function leftFunction, Function rightFunction) {
		goToLeftFunction(leftFunction);
		goToRightFunction(rightFunction);
	}

	/**
	 * Sets the cursor in the left side's listing to the specified location.
	 * @param program the left side's program
	 * @param location the location
	 */
	public void setLeftLocation(Program program, ProgramLocation location) {
		if (isShowing()) {
			goToLeftLocation(location);
		}
	}

	/**
	 * Sets the cursor in the right side's listing to the specified location.
	 * @param program the right side's program
	 * @param location the location
	 */
	public void setRightLocation(Program program, ProgramLocation location) {
		if (isShowing()) {
			goToRightLocation(location);
		}
	}

	private void goToLeftLocation(ProgramLocation location) {
		if (adjustingLeftLocation || location == null) {
			return;
		}
		try {
			adjustingLeftLocation = true;

			Address address = location.getAddress();
			if (location instanceof CodeUnitLocation) {
				CodeUnit leftCodeUnit = programs[LEFT].getListing().getCodeUnitContaining(address);
				if (leftCodeUnit == null) {
					return;
				}
			}

			// Now that we have the correct addresses, position the cursor location.
			listingPanels[LEFT].goTo(location, false);
		}
		finally {
			adjustingLeftLocation = false;
		}
	}

	private void goToRightLocation(ProgramLocation location) {
		if (adjustingRightLocation || location == null) {
			return;
		}
		try {
			adjustingRightLocation = true;

			Address address = location.getAddress();
			if (location instanceof CodeUnitLocation) {
				CodeUnit rightCodeUnit =
					programs[RIGHT].getListing().getCodeUnitContaining(address);
				if (rightCodeUnit == null) {
					return;
				}
			}

			// Now that we have the correct addresses, position the cursor location.
			listingPanels[RIGHT].goTo(location, false);
		}
		finally {
			adjustingRightLocation = false;
		}
	}

	private void buildPanel() {
		setName(DUAL_LISTING_ACTION_GROUP);
		setLayout(new BorderLayout());
		// cleanup remnants
		if (splitPane != null) {
			remove(splitPane);
			listingPanels[LEFT].dispose();
			listingPanels[RIGHT].dispose();
		}

		FormatManager leftFormatManager = createFormatManager(LEFT);
		leftFormatManager.addFormatModelListener(this);
		listingPanels[LEFT] = new ListingPanel(leftFormatManager, programs[LEFT]);

		FormatManager rightFormatManager = createFormatManager(RIGHT);
		listingPanels[RIGHT] = new ListingPanel(rightFormatManager, programs[RIGHT]);

		listingPanels[LEFT].setBorder(FOCUS_BORDER);
		listingPanels[RIGHT].setBorder(NON_FOCUS_BORDER);

		// Turn off selection in the listings so it can be set up s desired elsewhere.
		listingPanels[LEFT].getFieldPanel().enableSelection(false);
		listingPanels[RIGHT].getFieldPanel().enableSelection(false);

		String leftProgramName =
			(programs[LEFT] != null) ? programs[LEFT].getDomainFile().toString() : "none";
		String rightProgramName =
			(programs[RIGHT] != null) ? programs[RIGHT].getDomainFile().toString() : "none";

		titlePanels[LEFT] = new TitledPanel(leftProgramName, listingPanels[LEFT], 5);
		titlePanels[RIGHT] = new TitledPanel(rightProgramName, listingPanels[RIGHT], 5);

		// Set the MINIMUM_PANEL_WIDTH for the left and right panel to prevent the split pane's 
		// divider from becoming locked (can't be moved) due to extra long title names.
		titlePanels[LEFT].setMinimumSize(
			new Dimension(MINIMUM_PANEL_WIDTH, titlePanels[LEFT].getMinimumSize().height));
		titlePanels[RIGHT].setMinimumSize(
			new Dimension(MINIMUM_PANEL_WIDTH, titlePanels[RIGHT].getMinimumSize().height));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, titlePanels[LEFT],
			titlePanels[RIGHT]);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		add(splitPane, BorderLayout.CENTER);
	}

	private void setTitle(TitledPanel titlePanel, String titlePrefix, String title) {
		if (!titlePrefix.isEmpty()) {
			titlePrefix += " "; // Add a space between prefix and title.
		}
		String htmlPrefix = "<HTML>";
		if (title.startsWith(htmlPrefix)) {
			titlePanel.setTitleName(htmlPrefix + HTMLUtilities.friendlyEncodeHTML(titlePrefix) +
				title.substring(htmlPrefix.length()));
		}
		else {
			titlePanel.setTitleName(titlePrefix + title);
		}
	}

	/**
	 * Sets the title for the left side's listing.
	 * @param leftTitle the title
	 */
	public void setLeftTitle(String leftTitle) {
		this.leftTitle = leftTitle;
		setTitle(titlePanels[LEFT], leftTitlePrefix, leftTitle);
	}

	/**
	 * Sets the title for the right side's listing.
	 * @param rightTitle the title
	 */
	public void setRightTitle(String rightTitle) {
		this.rightTitle = rightTitle;
		setTitle(titlePanels[RIGHT], rightTitlePrefix, rightTitle);
	}

	/**
	 * Sets the component displayed in the top of this panel.
	 * @param comp the component.
	 */
	public void setTopComponent(JComponent comp) {
		if (topComp == comp) {
			return;
		}
		if (topComp != null) {
			remove(topComp);
		}
		topComp = comp;
		if (topComp != null) {
			add(topComp, BorderLayout.NORTH);
		}
		validate();
	}

	/**
	 * Sets the component displayed in the bottom of this panel.
	 * @param comp the component.
	 */
	public void setBottomComponent(JComponent comp) {
		if (bottomComp == comp) {
			return;
		}
		if (bottomComp != null) {
			remove(bottomComp);
		}
		validate(); // Since we are removing this while the panel is on the screen.
		bottomComp = comp;
		if (bottomComp != null) {
			add(bottomComp, BorderLayout.SOUTH);
		}
		validate(); // Since we are adding this while the panel is on the screen.
	}

	/**
	 * Gets the program from the left or right side that has or last had focus.
	 * @return the program from the side of this panel with focus or null
	 */
	public Program getFocusedProgram() {
		return programs[currProgramIndex];
	}

	/**
	 * Gets the program in the left listing panel.
	 * @return the left program or null
	 */
	@Override
	public Program getLeftProgram() {
		return programs[LEFT];
	}

	/**
	 * Gets the program in the right listing panel.
	 * @return the right program or null
	 */
	@Override
	public Program getRightProgram() {
		return programs[RIGHT];
	}

	/**
	 * Gets the addresses in the left listing panel.
	 * @return the addresses
	 */
	@Override
	public AddressSetView getLeftAddresses() {
		return addressSets[LEFT];
	}

	/**
	 * Gets the addresses in the right listing panel.
	 * @return the addresses
	 */
	@Override
	public AddressSetView getRightAddresses() {
		return addressSets[RIGHT];
	}

	/**
	 * Get the left or right listing panel that has or last had focus.
	 * @return the listing panel with focus.
	 */
	public ListingPanel getFocusedListingPanel() {
		return listingPanels[currProgramIndex];
	}

	/**
	 * Get the left side's listing panel.
	 * @return the left panel
	 */
	public ListingPanel getLeftPanel() {
		return listingPanels[LEFT];
	}

	/**
	 * Get the right side's listing panel.
	 * @return the right panel
	 */
	public ListingPanel getRightPanel() {
		return listingPanels[RIGHT];
	}

	/**
	 * Go to the indicated address in the listing that last had focus.
	 * @param addr the cursor should go to this address
	 * @return true if the location changed
	 */
	public boolean goTo(Address addr) {
		return listingPanels[currProgramIndex].goTo(addr);
	}

	/**
	 * Go to the indicated location in the listing that last had focus.
	 * @param loc the cursor should go to this location.
	 * @param centerOnScreen true indicates that the location should be centered in the listing's
	 * viewport.
	 * @return true if the location changed
	 */
	public boolean goTo(ProgramLocation loc, boolean centerOnScreen) {
		return listingPanels[currProgramIndex].goTo(loc, centerOnScreen);
	}

	@Override
	public void dispose() {
		setFieldPanelCoordinator(null);
		listingDiff.removeListingDiffChangeListener(this);
		markerManagers[LEFT].dispose();
		markerManagers[RIGHT].dispose();
		listingPanels[LEFT].getFieldPanel().removeFieldLocationListener(leftLocationListener);
		listingPanels[RIGHT].getFieldPanel().removeFieldLocationListener(rightLocationListener);
		for (int i = 0; i < 2; i++) {
			listingPanels[i].dispose();
		}
	}

	@Override
	public void focusGained(FocusEvent e) {
		Component comp = e.getComponent();
		for (int i = 0; i < listingPanels.length; i++) {
			if (listingPanels[i].getFieldPanel() == comp) {
				setDualPanelFocus(i);
			}
		}

		// Kick the tool so action buttons will be updated
		if (tool.getActiveComponentProvider() != null) {
			tool.getActiveComponentProvider().contextChanged();
		}
	}

	private void setDualPanelFocus(int leftOrRight) {
		currProgramIndex = leftOrRight;
		listingPanels[leftOrRight].setBorder(FOCUS_BORDER);
		listingPanels[((leftOrRight == LEFT) ? RIGHT : LEFT)].setBorder(NON_FOCUS_BORDER);
	}

	@Override
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {

		ListingCodeComparisonPanel dualListingPanel = this;

		if (event == null) {
			Navigatable focusedNavigatable = dualListingPanel.getFocusedNavigatable();
			DualListingActionContext myActionContext =
				new DualListingActionContext(provider, focusedNavigatable);
			myActionContext.setContextObject(this);
			myActionContext.setCodeComparisonPanel(this);
			return myActionContext;
		}

		ListingPanel leftPanel = dualListingPanel.getLeftPanel();
		ListingPanel rightPanel = dualListingPanel.getRightPanel();

		Object leftMarginContext = getContextForMarginPanels(leftPanel, event);
		if (leftMarginContext != null) {
			return new ActionContext(provider).setContextObject(leftMarginContext);
		}
		Object rightMarginContext = getContextForMarginPanels(rightPanel, event);
		if (rightMarginContext != null) {
			return new ActionContext(provider).setContextObject(rightMarginContext);
		}

		Object source = event.getSource();
		if (source instanceof FieldHeaderComp) {
			FieldHeaderLocation fieldHeaderLocation =
				leftPanel.getFieldHeader().getFieldHeaderLocation(event.getPoint());
			return new ActionContext(provider).setContextObject(fieldHeaderLocation);
		}

		Navigatable focusedNavigatable = dualListingPanel.getFocusedNavigatable();
		DualListingActionContext myActionContext =
			new DualListingActionContext(provider, focusedNavigatable);
		myActionContext.setContextObject(this);
		myActionContext.setCodeComparisonPanel(this);
		myActionContext.setSourceObject(source);
		return myActionContext;
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

	/**
	 * Adds the indicated button press listener to both listing panels in this code comparison panel.
	 * @param listener the listener
	 */
	public void addButtonPressedListener(ButtonPressedListener listener) {
		for (ListingPanel listingPanel : listingPanels) {
			listingPanel.addButtonPressedListener(listener);
		}
	}

	/**
	 * Repaints both the left and right listing panels if they are visible.
	 */
	public void updateListings() {
		if (!isVisible()) {
			return;
		}
		listingPanels[LEFT].repaint();
		listingPanels[RIGHT].repaint();
	}

	/**
	 * Gets the indicated (LEFT or RIGHT) side's address that is equivalent to the other side's
	 * address.
	 * @param leftOrRight LEFT or RIGHT indicating which side's address is needed.
	 * @param otherSidesAddress the address for the other side. If leftOrRight = LEFT, then this
	 * should be a right side address. If leftOrRight = RIGHT, then this should be a left side address.
	 * @return an address for the indicated side (LEFT or RIGHT) that is equivalent to the other
	 * side's address that is specified. Otherwise, null.
	 */
	private Address getAddress(int leftOrRight, Address otherSidesAddress) {
		if (isFunctionCompare()) {
			return getFunctionAddress(leftOrRight, otherSidesAddress);
		}
		if (isDataCompare()) {
			return getDataAddress(leftOrRight, otherSidesAddress);
		}
		return null;
	}

	/**
	 * Gets an address in the program indicated by <code>leftOrRight</code> that matches the 
	 * <code>otherSidesAddress</code> that is an address in a function in the other program.
	 * @param leftOrRight indicates whether to get the address from the LEFT or RIGHT program.
	 * @param otherSidesAddress address in the other program that is equivalent to the 
	 * desired address.
	 * @return the matching address in the indicated program or null.
	 */
	private Address getFunctionAddress(int leftOrRight, Address otherSidesAddress) {
		// Try to get the address using the correlator. 
		// If the correlator couldn't determine it, then try to infer it.
		int otherSide = (leftOrRight == RIGHT) ? LEFT : RIGHT;
		// Finding desired side's address.
		Address desiredSidesAddress =
			(leftOrRight == RIGHT) ? getRightCorrelatedAddress(otherSidesAddress)
					: getLeftCorrelatedAddress(otherSidesAddress);
		if (desiredSidesAddress != null) {
			return desiredSidesAddress;
		}
		// Couldn't directly correlate the address.
		CodeUnit otherCodeUnit =
			programs[otherSide].getListing().getCodeUnitContaining(otherSidesAddress);
		if (otherCodeUnit == null) {
			return null; // Can't get the code unit's address.
		}
		Address otherCodeUnitAddress = otherCodeUnit.getMinAddress();
		Address desiredCodeUnitAddress =
			(leftOrRight == RIGHT) ? getRightCorrelatedAddress(otherCodeUnitAddress)
					: getLeftCorrelatedAddress(otherCodeUnitAddress);
		if (desiredCodeUnitAddress == null) {
			return null; // Can't match the code unit address either.
		}
		return inferDesiredFunctionAddress(otherCodeUnitAddress, desiredCodeUnitAddress,
			otherSidesAddress, programs[otherSide], programs[leftOrRight]);
	}

	private Address getDataAddress(int leftOrRight, Address otherSidesAddress) {
		// Correlator doesn't handle data compare, so associate beginning of data and 
		// infer the others based on relative position.
		Address leftDataAddress = getLeftDataAddress();
		Address rightDataAddress = getRightDataAddress();
		if (leftOrRight == RIGHT) {
			// Finding right side address.
			return inferDesiredDataAddress(leftDataAddress, rightDataAddress, otherSidesAddress,
				programs[LEFT], programs[RIGHT]);
		}
		// Finding left side address.
		return inferDesiredDataAddress(rightDataAddress, leftDataAddress, otherSidesAddress,
			programs[RIGHT], programs[LEFT]);
	}

	/**
	 * Is this panel currently comparing a function match?
	 * @return true if comparing functions.
	 */
	private boolean isFunctionCompare() {
		Address leftFunctionAddress = getLeftFunctionAddress();
		Address rightFunctionAddress = getRightFunctionAddress();
		return (leftFunctionAddress != null && rightFunctionAddress != null);
	}

	/**
	 * Is this panel currently comparing a data match?
	 * @return true if comparing data.
	 */
	private boolean isDataCompare() {
		Address leftDataAddress = getLeftDataAddress();
		Address rightDataAddress = getRightDataAddress();
		return (leftDataAddress != null && rightDataAddress != null);
	}

	/**
	 * Gets the left side address that is equivalent to the indicated right side address.
	 * @param rightByteAddress the right side address
	 * @return the left side address or null.
	 */
	private Address getLeftCorrelatedAddress(Address rightByteAddress) {
		if (correlator != null) {
			return correlator.getAddressInFirst(rightByteAddress);
		}
		return null;
	}

	/**
	 * Gets the right side address that is equivalent to the indicated left side address.
	 * @param leftByteAddress the left side address
	 * @return the right side address or null.
	 */
	private Address getRightCorrelatedAddress(Address leftByteAddress) {
		if (correlator != null) {
			return correlator.getAddressInSecond(leftByteAddress);
		}
		return null;
	}

	/**
	 * Gets the left side function's entry point address.
	 * @return the left side function's entry point address or null.
	 */
	private Address getLeftFunctionAddress() {
		if (functions[LEFT] != null) {
			return functions[LEFT].getEntryPoint();
		}
		return null;
	}

	/**
	 * Gets the right side function's entry point address.
	 * @return the right side function's entry point address or null.
	 */
	private Address getRightFunctionAddress() {
		if (functions[RIGHT] != null) {
			return functions[RIGHT].getEntryPoint();
		}
		return null;
	}

	/**
	 * Gets the left side data's minimum address.
	 * @return the left side data's minimum address or null.
	 */
	private Address getLeftDataAddress() {
		if (data[LEFT] != null) {
			return data[LEFT].getMinAddress();
		}
		return null;
	}

	/**
	 * Gets the right side data's minimum address.
	 * @return the right side data's minimum address or null.
	 */
	private Address getRightDataAddress() {
		if (data[RIGHT] != null) {
			return data[RIGHT].getMinAddress();
		}
		return null;
	}

	private class LeftLocationListener implements FieldLocationListener {

		@Override
		public void fieldLocationChanged(FieldLocation location, Field field,
				EventTrigger trigger) {
			if (fieldLocationChanging) {
				return;
			}
			try {
				fieldLocationChanging = true;

				ProgramLocation leftProgramLocation = listingPanels[LEFT].getProgramLocation();
				ListingComparisonFieldPanelCoordinator fieldPanelCoordinator =
					getFieldPanelCoordinator();
				// Only set other side's cursor if we are coordinating right now.
				ProgramLocation rightProgramLocation =
					(fieldPanelCoordinator != null) ? getProgramLocation(RIGHT, leftProgramLocation)
							: null;

				setCursorMarkers(LEFT, leftProgramLocation);
				setCursorMarkers(RIGHT, rightProgramLocation);
				if (rightProgramLocation == null) {
					//remove obsolete cursor background highlight for right-hand cursor
					listingPanels[RIGHT].getFieldPanel().repaint();
					return;
				}

				if (fieldPanelCoordinator != null) {
					fieldPanelCoordinator.leftLocationChanged(leftProgramLocation);
					setRightLocation(getRightProgram(), rightProgramLocation);
				}
			}
			finally {
				fieldLocationChanging = false;
			}
		}
	}

	private class RightLocationListener implements FieldLocationListener {

		@Override
		public void fieldLocationChanged(FieldLocation location, Field field,
				EventTrigger trigger) {
			if (fieldLocationChanging) {
				return;
			}
			try {
				fieldLocationChanging = true;

				ProgramLocation rightProgramLocation = listingPanels[RIGHT].getProgramLocation();
				ListingComparisonFieldPanelCoordinator fieldPanelCoordinator =
					getFieldPanelCoordinator();
				// Only set other side's cursor if we are coordinating right now.
				ProgramLocation leftProgramLocation =
					(fieldPanelCoordinator != null) ? getProgramLocation(LEFT, rightProgramLocation)
							: null;

				setCursorMarkers(RIGHT, rightProgramLocation);
				setCursorMarkers(LEFT, leftProgramLocation);
				if (leftProgramLocation == null) {
					//remove obsolete cursor background highlight for left-hand cursor
					listingPanels[LEFT].getFieldPanel().repaint();
					return;
				}

				if (fieldPanelCoordinator != null) {
					fieldPanelCoordinator.rightLocationChanged(rightProgramLocation);
					setLeftLocation(getLeftProgram(), leftProgramLocation);
				}
			}
			finally {
				fieldLocationChanging = false;
			}
		}
	}

	@Override
	public void formatModelAdded(FieldFormatModel model) {
		changeRightToMatchLeftFormat(model);
	}

	@Override
	public void formatModelChanged(FieldFormatModel model) {
		changeRightToMatchLeftFormat(model);
	}

	@Override
	public void formatModelRemoved(FieldFormatModel model) {
		changeRightToMatchLeftFormat(model);
	}

	private void changeRightToMatchLeftFormat(FieldFormatModel model) {
		SaveState saveState = new SaveState();
		listingPanels[LEFT].getFormatManager().saveState(saveState);
		listingPanels[RIGHT].getFormatManager().readState(saveState);
	}

	/**
	 * Gets the left or right listing panel that contains the indicated field panel.
	 * @param fieldPanel the field panel
	 * @return the listing panel or null.
	 */
	public ListingPanel getListingPanel(FieldPanel fieldPanel) {
		if (listingPanels[LEFT].getFieldPanel() == fieldPanel) {
			return listingPanels[LEFT];
		}
		if (listingPanels[RIGHT].getFieldPanel() == fieldPanel) {
			return listingPanels[RIGHT];
		}
		return null;
	}

	@Override
	public FormatManager getFormatManager() {
		return listingPanels[LEFT].getFormatManager();
	}

	/**
	 * Disable mouse navigation from within this dual listing panel.
	 * @param enabled false disables navigation
	 */
	@Override
	public void setMouseNavigationEnabled(boolean enabled) {
		// always remove before adding to avoid double adding
		listingPanels[LEFT].removeButtonPressedListener(fieldNavigators[LEFT]);
		listingPanels[RIGHT].removeButtonPressedListener(fieldNavigators[RIGHT]);

		if (enabled) {
			listingPanels[LEFT].addButtonPressedListener(fieldNavigators[LEFT]);
			listingPanels[RIGHT].addButtonPressedListener(fieldNavigators[RIGHT]);
		}
	}

	@Override
	public void loadData(Data leftData, Data rightData) {
		clearCorrelation();
		Program leftProgram = (leftData != null) ? leftData.getProgram() : null;
		Program rightProgram = (rightData != null) ? rightData.getProgram() : null;
		// Try to show matching code units based on the size of the larger data item.
		long maxOffset = getMaxOffset(leftData, rightData);
		AddressSetView leftAddressSet = EMPTY_ADDRESS_SET;
		if (leftData != null) {
			Address leftMinAddress = leftData.getMinAddress();
			Address leftEndAddress = getEndAddress(leftProgram, maxOffset, leftMinAddress);
			leftAddressSet = new AddressSet(leftMinAddress, leftEndAddress);
		}
		AddressSetView rightAddressSet = EMPTY_ADDRESS_SET;
		if (rightData != null) {
			Address rightMinAddress = rightData.getMinAddress();
			Address rightEndAddress = getEndAddress(rightProgram, maxOffset, rightMinAddress);
			rightAddressSet = new AddressSet(rightMinAddress, rightEndAddress);
		}
		setPrograms(leftProgram, rightProgram);
		// Adjust the data and functions only after the correct programs are set.
		functions[LEFT] = null;
		functions[RIGHT] = null;
		data[LEFT] = leftData;
		data[RIGHT] = rightData;
		// Adjust the addresses only after the Data is set.
		loadAddresses(leftProgram, rightProgram, leftAddressSet, rightAddressSet);
		setDataTitles();
		updateActionEnablement();
	}

	/**
	 * Gets the maximum offset based on the larger data that is passed to this method.
	 * @param leftData the left view's data
	 * @param rightData the right view's data
	 * @return the maximum offset (one less than the larger data item's size).
	 */
	private long getMaxOffset(Data leftData, Data rightData) {
		long leftOffset = 0;
		if (leftData != null) {
			leftOffset = leftData.getMaxAddress().subtract(leftData.getMinAddress());
		}
		long rightOffset = 0;
		if (rightData != null) {
			rightOffset = rightData.getMaxAddress().subtract(rightData.getMinAddress());
		}
		long maxOffset = Math.max(leftOffset, rightOffset);
		return maxOffset;
	}

	/**
	 * Gets the ending address to be displayed. It tries to get an ending address that is
	 * maxOffset number of bytes beyond the minAddress without leaving the memory block
	 * that contains the minAddress. If the maxOffset is beyond the end of the block then
	 * the end of the block is returned. For an externalAddress the minAddress is returned.
	 * @param program the program containing the data
	 * @param maxOffset the max offset
	 * @param minAddress the minimum address of the data
	 * @return the end address to display
	 */
	private Address getEndAddress(Program program, long maxOffset, Address minAddress) {
		if (minAddress.isExternalAddress()) {
			return minAddress; // Begin and end address are same for external data.
		}
		MemoryBlock block = program.getMemory().getBlock(minAddress);
		Address blockEnd = block.getEnd();
		Address endAddress;
		try {
			endAddress = minAddress.add(maxOffset);
			if (endAddress.compareTo(blockEnd) > 0) {
				endAddress = blockEnd;
			}
		}
		catch (AddressOutOfBoundsException e) {
			endAddress = blockEnd;
		}
		return endAddress;
	}

	/**
	 * Clears the address correlation being used with the ListingDiff and the dual listing
	 * field panel coordinator.
	 */
	private void clearCorrelation() {
		correlator = null;
		try {
			listingDiff.setCorrelation(correlator);
			// Setting the correlation will also reset the locked line numbers.
			ListingComparisonFieldPanelCoordinator fieldPanelCoordinator =
				getFieldPanelCoordinator();
			if (fieldPanelCoordinator != null) {
				fieldPanelCoordinator.setCorrelation(correlator);
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Couldn't clear the address correlator for the dual listing.", e);
		}
	}

	/**
	 * Gets the data loaded in the left listing panel.
	 * @return the data or null
	 */
	@Override
	public Data getLeftData() {
		return data[LEFT];
	}

	/**
	 * Gets the data loaded in the right listing panel.
	 * @return the data or null
	 */
	@Override
	public Data getRightData() {
		return data[RIGHT];
	}

	@Override
	public Class<? extends CodeComparisonPanel<ListingComparisonFieldPanelCoordinator>> getPanelThisSupersedes() {
		return null; // Doesn't supersede any other panel.
	}

	private class DualListingMarkerManager extends MarkerManager {

		private DualListingServiceProvider serviceProvider;

		private DualListingMarkerManager(String Owner, PluginTool tool,
				DualListingServiceProvider serviceProvider) {
			super(owner, tool);
			this.serviceProvider = serviceProvider;
		}

		@Override
		public GoToService getGoToService() {
			return serviceProvider.getService(GoToService.class);
		}
	}

	@Override
	public void listingDiffChanged() {
		setDiffHighlights();
	}

	/**
	 * Displays the indicated text int the tool's status area.
	 * @param text the message to display
	 */
	void setStatusInfo(String text) {
		tool.setStatusInfo(text);
	}

	@Override
	public void refreshLeftPanel() {
		// Listing will update automatically, so just update title.
		setLeftTitle(getFunctionTitle(functions[LEFT]));
	}

	@Override
	public void refreshRightPanel() {
		// Listing will update automatically, so just update title.
		setRightTitle(getFunctionTitle(functions[RIGHT]));
	}

	@Override
	public void programRestored(Program program) {
		if (getLeftProgram() == program) {
			setLeftTitle(getFunctionTitle(functions[LEFT]));
		}
		if (getRightProgram() == program) {
			setRightTitle(getFunctionTitle(functions[RIGHT]));
		}
	}

	@Override
	public boolean leftPanelHasFocus() {
		return currProgramIndex == LEFT;
	}

	@Override
	public void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix) {
		this.leftTitlePrefix = leftTitlePrefix;
		this.rightTitlePrefix = rightTitlePrefix;
		setLeftTitle(leftTitle);
		setRightTitle(rightTitle);
	}

	private class DualListingMouseListener extends MouseAdapter {

		private int leftOrRight;

		@SuppressWarnings("unused")
		private Component leftOrRightComponent;

		DualListingMouseListener(Component leftOrRightComponent, int leftOrRight) {
			this.leftOrRightComponent = leftOrRightComponent;
			this.leftOrRight = leftOrRight;
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			setDualPanelFocus(leftOrRight);
		}
	}

	/**
	 * Gets the GoToService that is used for either the left listing or the right listing.
	 * @param isLeftSide true means get the GoToService for the left side listing.
	 * false means get it for the right side listing.
	 * @return the goToService
	 */
	GoToService getGoToService(boolean isLeftSide) {
		return dualListingServiceProviders[isLeftSide ? LEFT : RIGHT].getService(GoToService.class);
	}

	public ActionContext getActionContext(MouseEvent event, ComponentProvider provider) {
		Object source = (event != null) ? event.getSource() : null;
		Component sourceComponent = (source instanceof Component) ? (Component) source : null;
		// Is the action being taken on the dual listing.
		if (this.isAncestorOf(sourceComponent)) {
			ListingPanel sourcePanel = getLeftPanel();
			ListingPanel destinationPanel = getRightPanel();

			// Are we on a marker margin of the left listing? Return that margin's context.
			Object sourceMarginContextObject = getContextObjectForMarginPanels(sourcePanel, event);
			if (sourceMarginContextObject != null) {
				return new ActionContext(provider).setContextObject(sourceMarginContextObject);
			}
			// Are we on a marker margin of the right listing? Return that margin's context.
			Object destinationMarginContextObject =
				getContextObjectForMarginPanels(destinationPanel, event);
			if (destinationMarginContextObject != null) {
				return new ActionContext(provider).setContextObject(destinationMarginContextObject);
			}

			// If the action is on the Field Header of the left listing panel return an
			// appropriate context for the field actions.
			if (sourceComponent instanceof FieldHeaderComp) {
				FieldHeaderLocation fieldHeaderLocation =
					sourcePanel.getFieldHeader().getFieldHeaderLocation(event.getPoint());
				return new ActionContext(provider).setContextObject(fieldHeaderLocation);
			}
		}
		return null;
	}

	/**
	 * Gets a marker margin or overview margin context object if the mouse event occurred on one
	 * of the GUI components for the indicated listing panel's marker margin (left edge of listing)
	 * or overview margin (right edge of listing).
	 * @param lp The listing panel to check
	 * @param event the mouse event
	 * @return a marker margin context object if the event was on a margin.
	 */
	public Object getContextObjectForMarginPanels(ListingPanel lp, MouseEvent event) {
		Object source = event.getSource();
		// Is event source a marker margin provider on the left side of the listing?
		List<MarginProvider> marginProviders = lp.getMarginProviders();
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
		List<OverviewProvider> overviewProviders = lp.getOverviewProviders();
		for (OverviewProvider overviewProvider : overviewProviders) {
			JComponent c = overviewProvider.getComponent();
			if (c == source) {
				return source; // Return the overview provider that was clicked.
			}
		}
		return null; // Not one of the listing panel's margin panels.
	}

	/**
	 * Change listener that performs a repaint when a marker changes between enabled and disabled.
	 */
	private class MarkerChangeListener implements ChangeListener {

		private int leftOrRight;

		private MarkerChangeListener(int leftOrRight) {
			this.leftOrRight = leftOrRight;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			listingPanels[leftOrRight].getFieldPanel().repaint();
		}
	}

	@Override
	public FieldPanel getLeftFieldPanel() {
		return getLeftPanel().getFieldPanel();
	}

	@Override
	public FieldPanel getRightFieldPanel() {
		return getRightPanel().getFieldPanel();
	}

	@Override
	protected ListingComparisonFieldPanelCoordinator createFieldPanelCoordinator() {
		ListingComparisonFieldPanelCoordinator coordinator =
			new ListingComparisonFieldPanelCoordinator(this);
		// If we already have an address correlator established then use it.
		if (correlator != null) {
			coordinator.setCorrelation(correlator);
		}
		return coordinator;
	}

	/**
	 * Restores this panel to the indicated saved configuration state.
	 * @param prefix identifier to prepend to any save state names to make them unique.
	 * @param saveState the configuration state to restore
	 */
	public void readConfigState(String prefix, SaveState saveState) {
		showSideBySide(saveState.getBoolean(prefix + DUAL_LISTING_SIDE_BY_SIDE, true));
		setHeaderShowing(saveState.getBoolean(prefix + DUAL_LISTING_HEADER_SHOWING, false));
	}

	/**
	 * Saves the current configuration state of this panel.
	 * @param prefix identifier to prepend to any save state names to make them unique.
	 * @param saveState the new configuration state
	 */
	public void writeConfigState(String prefix, SaveState saveState) {
		saveState.putBoolean(prefix + DUAL_LISTING_SIDE_BY_SIDE, isSideBySide());
		saveState.putBoolean(prefix + DUAL_LISTING_HEADER_SHOWING, isHeaderShowing());
	}

	@Override
	public void setScrollingSyncState(boolean syncScrolling) {
		// Overrides the base method so it can save and restore the coordinator sync state.
		if (isScrollingSynced() == syncScrolling) {
			return;
		}
		FieldPanel currentFieldPanel = listingPanels[currProgramIndex].getFieldPanel();
		ViewerPosition viewerPosition = currentFieldPanel.getViewerPosition(); // Save focused side's viewer position.
		saveCoordinatorState(); // Saves sync state when disabling synchronized scrolling.
		super.setScrollingSyncState(syncScrolling);
		// Need to restore sync point if current location can't determine matching one.
		if (!hasMatchingLocation()) {
			restoreCoordinatorState(); // Restores sync state when enabling synchronized scrolling.
		}
		currentFieldPanel.setViewerPosition(viewerPosition.getIndex(), viewerPosition.getXOffset(),
			viewerPosition.getYOffset()); // Restore the focused side's viewer position.
	}

	private boolean hasMatchingLocation() {
		ProgramLocation cursorLocation = listingPanels[currProgramIndex].getCursorLocation();
		if (cursorLocation != null) {
			Address address = cursorLocation.getAddress();
			Address otherAddress;
			if (currProgramIndex == LEFT) {
				otherAddress = getRightCorrelatedAddress(address);
			}
			else {
				otherAddress = getLeftCorrelatedAddress(address);
			}
			return (otherAddress != null);
		}
		return false;
	}

	private void saveCoordinatorState() {
		// If we can get the field panel coordinator, save its state.
		ListingComparisonFieldPanelCoordinator fieldPanelCoordinator = getFieldPanelCoordinator();
		if (fieldPanelCoordinator != null) {
			// Save the coordinator state.
			coordinatorLockedAddresses = fieldPanelCoordinator.getLockedAddresses();
		}
	}

	private void restoreCoordinatorState() {
		// If we can get the field panel coordinator, restore its state.
		ListingComparisonFieldPanelCoordinator fieldPanelCoordinator = getFieldPanelCoordinator();
		if (fieldPanelCoordinator != null && coordinatorLockedAddresses != null &&
			coordinatorLockedAddresses.length == 2) {
			// Restore the coordinator state.
			fieldPanelCoordinator.setLockedAddresses(coordinatorLockedAddresses[LEFT],
				coordinatorLockedAddresses[RIGHT]);
		}
	}
}
