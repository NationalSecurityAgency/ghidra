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
package ghidra.app.plugin.core.diff;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.tree.TreeSelectionModel;

import docking.DockingUtils;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.FieldMouseListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.bookmark.BookmarkNavigator;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.marker.MarkerManager;
import ghidra.app.services.*;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Plugin that shows the differences between two programs, and allows the
 * user to apply differences to the currently open program. This allows only one
 * tabbed program to display a second program (possibly with an active Diff).
 * It allows the active program to change without losing the current Diff or
 * second program that is opened. De-activation of the first program for the Diff
 * will result in termination of the Diff or the Diff can be closed directly by the user.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays Program differences",
	description = "Extends the CodeBrowser plugin to show a second program side-by-side with " +
			"the current program.  This plugin also computes differences between the two " +
			"programs and allows the user to apply differences from the second program onto" +
			"the first.",
	servicesRequired = { GoToService.class, CodeViewerService.class, MarkerService.class },
	servicesProvided = { DiffService.class },
	eventsProduced = { ProgramSelectionPluginEvent.class, ViewChangedPluginEvent.class },
	eventsConsumed = { ProgramClosedPluginEvent.class, ViewChangedPluginEvent.class }
)
//@formatter:on
public class ProgramDiffPlugin extends ProgramPlugin
		implements ProgramLocationListener, ProgramSelectionListener, DiffControllerListener,
		DiffService, OptionsChangeListener, DomainObjectListener {

	private ImageIcon CURSOR_LOC_ICON = ResourceManager.loadImage("images/cursor_arrow.gif");
	private static final String SELECTION_GROUP = "Selection Colors";
	private static final String DIFF_HIGHLIGHT_COLOR_NAME =
		SELECTION_GROUP + Options.DELIMITER + "Difference Color";
	private Color diffHighlightColor = new Color(255, 230, 180); // light orange
	private Color cursorHighlightColor;
	protected static final HelpService help = Help.getHelpService();

	private GoToService goToService;
	private CodeViewerService codeViewerService;
	private MarkerManager markerManager;
	private MarkerSet p2SelectionMarkers;
	private MarkerSet p2DiffMarkers;
	private MarkerSet p1DiffMarkers;
	private MarkerSet p2CursorMarkers;
	private Map<BookmarkType, BookmarkNavigator> bookmarkMap; // map BookmarkType to BookmarkNavigator

	private boolean isLimitedToSelection;
	private ProgramDiffFilter execDiffFilter;
	private ProgramMergeFilter applyFilter;

	private boolean showDetails = false;
	private boolean showApplySettings = false;
	private boolean showingSecondProgram = false;
	private boolean sameProgramContext = false;
	private DiffActionManager actionManager;
	private ListingPanel diffListingPanel;
	private Navigatable diffNavigatable;
	private FieldNavigator diffFieldNavigator;
	private volatile boolean taskInProgress;
	private ExecuteDiffDialog executeDiffDialog;
	private AddressSetView p1ViewAddrSet;
	private AddressSetView addressesOnlyInP1;
	private AddressSetView compatibleOnlyInP2;
	private DiffController diffControl;
	private Program primaryProgram;
	private Program secondaryDiffProgram;
	private AddressFactory p2AddressFactory;
	private ProgramDiffDetails diffDetails;

	private ProgramSelection p2DiffHighlight;
	private ProgramSelection p2Selection;
	private DiffApplySettingsProvider diffApplySettingsProvider;
	private DiffDetailsProvider diffDetailsProvider;
	private boolean settingLocation;

	private ActionListener okListener;
	private DiffTaskListener diffTaskListener = DiffTaskListener.NULL_LISTENER;
	private ProgramLocation previousP1Location;

	private ApplySettingsActionListener applySettingsListener;
	private DiffDetailsActionListener diffDetailsListener;
	DiffApplySettingsOptionManager applySettingsMgr;
	private boolean isHighlightCursorLine;
	private Program activeProgram;
	private OpenVersionedFileDialog openProgramDialog;

	/**
	 * Creates the plugin for indicating program differences to the user.
	 * @param tool the tool that owns this plugin.
	 */
	public ProgramDiffPlugin(PluginTool tool) {
		super(tool, true, true);

		markerManager = new MarkerManager(this);

		actionManager = new DiffActionManager(this);
		p2Selection = new ProgramSelection();
		p2DiffHighlight = new ProgramSelection();
		bookmarkMap = new HashMap<>();
		addressesOnlyInP1 = new AddressSet();
		compatibleOnlyInP2 = new AddressSet();
	}

	@Override
	public void programLocationChanged(ProgramLocation p2Loc, EventTrigger trigger) {
		if (trigger == EventTrigger.MODEL_CHANGE) {
			return; // don't trigger left-side when model on right side changes.
		}
		if ((primaryProgram == null) || (primaryProgram != currentProgram) ||
			!showingSecondProgram) {
			return;
		}
		Address p2LocationAddress = p2Loc.getAddress();
		////////////////////////////////////
		// NOTE: Need to fix this, so we really get an equivalent p1Loc (primary Program location).
		// The following use of the p2Loc as a p1Loc is NOT good, but seems to work for non-overlay
		// locations. If the location is for an overlay, we will convert to a simple address
		// ProgramLocation whenever the overlay spaces are not equal (which would be
		// due to one overlay space being longer than the other.) In the non-equal overlay case,
		// using a p2Loc as a p1Loc would result in an exception.
		// Instead this really should convert any location (p2Loc) to the equivalent location in
		// the other program (p1Loc). [i.e. a MnemonicFieldLocation, etc. isn't dumbed down to a
		// ProgramLocation.]
		////////////////////////////////////
		ProgramLocation p1Loc = p2Loc;
		if (p2LocationAddress.getAddressSpace().isOverlaySpace()) {
			ProgramLocation equivalentP1Loc = DiffUtility
					.getCompatibleProgramLocation(secondaryDiffProgram, p2Loc, primaryProgram);
			if (equivalentP1Loc != null) {
				AddressSpace p2Space = p2LocationAddress.getAddressSpace();
				AddressSpace p1Space = equivalentP1Loc.getAddress().getAddressSpace();
				if (!(p2Space.equals(p1Space))) {
					p1Loc = equivalentP1Loc;
				}
			}
		}
		if (!settingLocation && !p1Loc.equals(currentLocation)) {
			MarkerSet cursorMarkers = getCursorMarkers();
			Address p1LocationAddress = p1Loc.getAddress();
			cursorMarkers.setAddressSet(new AddressSet(p2LocationAddress));

			previousP1Location = currentLocation;
			currentLocation = p1Loc;
			if (diffControl != null) {
				try {
					settingLocation = true;
					diffControl.setLocation(p1LocationAddress);
				}
				finally {
					settingLocation = false;
				}
			}
			if (secondaryDiffProgram != null) {
				try {
					settingLocation = true;
					codeViewerServiceGoTo(p1Loc);
				}
				finally {
					settingLocation = false;
				}
			}
			if (diffDetailsProvider != null && diffDetails != null) {
				diffDetailsProvider.locationChanged(p1Loc);
			}
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			programClosed(((ProgramClosedPluginEvent) event).getProgram());
		}
		else if (event instanceof ViewChangedPluginEvent) {
			AddressSet set = ((ViewChangedPluginEvent) event).getView();
			// If we are doing a Diff on the entire program then use the combined addresses for both programs.
			if (primaryProgram != null && showingSecondProgram) {
				addressesOnlyInP1 = new AddressSet();
				compatibleOnlyInP2 = new AddressSet();
				AddressSet addressSet = new AddressSet(primaryProgram.getMemory());
				if (set.equals(addressSet)) {
					if (secondaryDiffProgram != null) {
						try {
							ProgramMemoryComparator programMemoryComparator =
								new ProgramMemoryComparator(primaryProgram, secondaryDiffProgram);
							set = ProgramMemoryComparator.getCombinedAddresses(primaryProgram,
								secondaryDiffProgram);
							addressesOnlyInP1 = programMemoryComparator.getAddressesOnlyInOne();
							compatibleOnlyInP2 =
								programMemoryComparator.getCompatibleAddressesOnlyInTwo();
						}
						catch (ProgramConflictException e) {
							Msg.error(this, "Diff encountered a problem while changing the view. " +
								e.getMessage(), e);
						}
					}
				}
			}
			viewChanged(set);
		}
		else {
			super.processEvent(event);
		}
	}

	private void viewChanged(AddressSetView p1AddressSet) {
		if (primaryProgram != null && !showingSecondProgram) {
			return;
		}
		p1ViewAddrSet = p1AddressSet;

		if (showingSecondProgram) {
			ProgramSelection previousP1Selection = currentSelection;
			ProgramSelection previousP2DiffHighlight = p2DiffHighlight;
			ProgramSelection previousP2Selection = p2Selection;

			FieldPanel fp = diffListingPanel.getFieldPanel();
			AddressSet p1AddressSetAsP2 =
				DiffUtility.getCompatibleAddressSet(p1AddressSet, secondaryDiffProgram);
			AddressIndexMap p2IndexMap = new AddressIndexMap(p1AddressSetAsP2);
			markerManager.getOverviewProvider().setAddressIndexMap(p2IndexMap);
			fp.setBackgroundColorModel(
				new MarkerServiceBackgroundColorModel(markerManager, p2IndexMap));

			currentSelection = previousP1Selection;
			p2DiffHighlight = previousP2DiffHighlight;

			p2Selection = previousP2Selection;
			setProgram2Selection(p2Selection);
			if (p2DiffHighlight != null) {
				setDiffHighlight(p2DiffHighlight);
			}
		}
	}

	@Override
	public void differencesChanged(DiffController diffController) {
		setDiffHighlight();
		updatePgm2Enablement();
		if (diffDetailsProvider != null) {
			diffDetailsProvider.refreshDetails(currentLocation);
		}
	}

	@Override
	public void diffLocationChanged(DiffController diffController, Address program1Location) {
		if (!settingLocation) {
			goToServiceGoTo(new ProgramLocation(primaryProgram, program1Location)); // GoToService.goTo()
		}
		updatePgm2Enablement();
	}

	@Override
	public boolean inProgress() {
		return taskInProgress;
	}

	private boolean launchDiffOnOpenProgram() {
		try {
			if (diffControl != null) { // There is currently a Diff already so clear it.
				clearDiff();
			}
			diff(p1ViewAddrSet);
			return true;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return false;
		}
	}

	@Override
	public boolean launchDiff(DomainFile otherProgram) {
		if (openSecondProgram(otherProgram)) {
			return launchDiffOnOpenProgram();
		}
		return false;
	}

	@Override
	public boolean launchDiff(Program otherProgram) {
		try {
			if (diffControl != null) { // There is currently a Diff already so clear it.
				clearDiff();
			}
			if (openSecondProgram(otherProgram, null)) {
				secondaryDiffProgram.addConsumer(this);
				diff(p1ViewAddrSet);
			}
			return true;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return false;
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionsName, Object oldValue,
			Object newValue) {
		boolean diffHighlightChanged = false;
		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionsName.equals(DIFF_HIGHLIGHT_COLOR_NAME)) {
				diffHighlightColor = ((Color) newValue);
				diffHighlightChanged = true;
			}
			else if (optionsName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)) {
				cursorHighlightColor = (Color) newValue;
				if (p2CursorMarkers != null) {
					p2CursorMarkers.setMarkerColor(cursorHighlightColor);
				}
			}
			else if (optionsName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE)) {
				isHighlightCursorLine = (Boolean) newValue;
				if (p2CursorMarkers != null) {
					p2CursorMarkers.setColoringBackground(isHighlightCursorLine);
				}
			}
		}
		if (secondaryDiffProgram == null) {
			return;
		}

		if (diffHighlightChanged) {
			diffHighlightColor = ((Color) newValue);

			MarkerSet diffMarkers = getDiffMarkers();
			diffMarkers.setMarkerColor(diffHighlightColor);

			MarkerSet codeViewerDiffMarkers = getCodeViewerMarkers();
			codeViewerDiffMarkers.setMarkerColor(diffHighlightColor);

			adjustDiffDisplay();
		}

		// See if the browser selection color changed.
		// The browser will change the panel, but we need to change the markers.
		MarkerSet selectionMarkers = getSelectionMarkers();
		Color markColor = selectionMarkers.getMarkerColor();
		Color panelColor = diffListingPanel.getFieldPanel().getSelectionColor();
		if (!markColor.equals(panelColor)) {
			selectionMarkers.setMarkerColor(panelColor);
		}
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (!showingSecondProgram) {
			return;
		}

		if (location == null) {
			return;
		}

		if (settingLocation) {
			return;
		}

		if (location.equals(previousP1Location)) {
			return;
		}

		// Is location from primary program?
		if (location.isValid(primaryProgram)) {
			previousP1Location = location;
		}
		else { // Otherwise location is from Diff program.
			Address addr = location.getAddress();
			Address byteAddr = location.getByteAddress();
			Address refAddr = location.getRefAddress();
			Address primaryAddr =
				SimpleDiffUtility.getCompatibleAddress(secondaryDiffProgram, addr, primaryProgram);
			if (primaryAddr == null) {
				return;
			}

			Address primaryByteAddr = SimpleDiffUtility.getCompatibleAddress(secondaryDiffProgram,
				byteAddr, primaryProgram);
			if (primaryByteAddr == null) {
				primaryByteAddr = primaryAddr; // Make sure the byte address isn't null.
			}
			Address primaryRefAddr = SimpleDiffUtility.getCompatibleAddress(secondaryDiffProgram,
				refAddr, primaryProgram);
			ProgramLocation newP1Location = new ProgramLocation(primaryProgram, primaryAddr,
				primaryByteAddr, location.getComponentPath(), primaryRefAddr, 0, 0, 0);
			previousP1Location = newP1Location;
		}

		Address p1LocationAddress = previousP1Location.getAddress();
		Address p2LocationAddress = SimpleDiffUtility.getCompatibleAddress(primaryProgram,
			p1LocationAddress, secondaryDiffProgram);
		if (p2LocationAddress != null) {
			MarkerSet cursorMarkers = getCursorMarkers();
			cursorMarkers.setAddressSet(new AddressSet(p2LocationAddress));
		}

		try {
			settingLocation = true;
			if (diffControl != null) {
				diffControl.setLocation(previousP1Location.getAddress());
			}
			ProgramLocation previousP1LocationAsP2 = DiffUtility
					.getCompatibleProgramLocation(primaryProgram, location, secondaryDiffProgram);
			if (previousP1LocationAsP2 != null) {
				diffListingPanel.setCursorPosition(previousP1LocationAsP2);
			}
			if (diffDetailsProvider != null && diffDetails != null) {
				diffDetailsProvider.locationChanged(previousP1Location);
			}
		}
		finally {
			settingLocation = false;
		}
	}

	/**
	 * Called when a program gets closed.
	 * If the closed program is the first program of the Diff then we need to close the second program.
	 * @param program
	 */
	@Override
	protected void programClosed(Program program) {
		if (primaryProgram == program) {
			primaryProgram.removeListener(this);
			if (secondaryDiffProgram != null) {
				closeProgram2();
			}
			actionManager.programClosed(program);
		}
	}

	void setOpenDiffProgramDialog(OpenVersionedFileDialog dialog) {
		this.openProgramDialog = dialog;
	}

	private void setActiveProgram(Program newActiveProgram) {
		if (primaryProgram == null && newActiveProgram != null) {
			p1ViewAddrSet = newActiveProgram.getMemory();
		}
		actionManager.setActiveProgram(newActiveProgram);
		if (activeProgram == primaryProgram) {
			hideDiff();
		}
		else if (newActiveProgram == primaryProgram && newActiveProgram != null) {
			showDiff(newActiveProgram);
		}
		activeProgram = newActiveProgram;
	}

	protected void hideDiff() {
		actionManager.removeActions();
		removeSecondView();
		boolean isShowingDiffDetails =
			((diffDetailsProvider != null) && tool.isVisible(diffDetailsProvider));
		if (isShowingDiffDetails) {
			hideDiffDetails();
		}
		showDetails = isShowingDiffDetails;
		boolean isShowingApplySettings =
			((diffApplySettingsProvider != null) && tool.isVisible(diffApplySettingsProvider));
		if (isShowingApplySettings) {
			hideDiffApplySettings();
		}
		showApplySettings = isShowingApplySettings;
		clearMarkers();
	}

	protected void showDiff(Program program) {
		actionManager.addActions();
		showSecondView();
		if (showDetails) {
			showDiffDetails();
		}
		if (showApplySettings) {
			showDiffApplySettings();
		}
	}

	@Override
	protected void selectionChanged(ProgramSelection p1Selection) {
		if (!showingSecondProgram) {
			return;
		}
		if (currentSelection == null) {
			AddressFactory p1AddressFactory =
				(primaryProgram != null) ? primaryProgram.getAddressFactory() : null;
			currentSelection = new ProgramSelection(p1AddressFactory);
		}
		actionManager.setP1SelectToP2ActionEnabled(
			secondaryDiffProgram != null && !currentSelection.isEmpty());
	}

	@Override
	protected void dispose() {
		if (secondaryDiffProgram != null) {
			closeProgram2();
		}
		if (diffListingPanel != null) {
			diffListingPanel.removeButtonPressedListener(diffFieldNavigator);
			diffFieldNavigator = null;
			diffNavigatable = null;
			diffListingPanel = null;
		}
		if (diffApplySettingsProvider != null) {
			diffApplySettingsProvider.removeActionListener(applySettingsListener);
		}
		if (diffDetailsProvider != null) {
			diffDetailsProvider.removeActionListener(diffDetailsListener);
		}
		actionManager.dispose();
		applySettingsMgr.dispose();
		markerManager.dispose();
		codeViewerService.setCoordinatedListingPanelListener(null);
	}

	@Override
	protected void init() {
		codeViewerService = tool.getService(CodeViewerService.class);
		goToService = tool.getService(GoToService.class);

		FormatManager formatManager = codeViewerService.getFormatManager();
		ServiceProvider diffServiceProvider =
			new DiffServiceProvider(formatManager.getServiceProvider(), this);
		diffListingPanel = new ListingPanel(formatManager);
		diffListingPanel.setProgramLocationListener(this);
		diffListingPanel.setProgramSelectionListener(this);
		diffListingPanel.getFieldPanel().addFieldMouseListener(new MyFieldMouseListener());
		diffListingPanel.addMarginProvider(markerManager.getMarginProvider());
		diffListingPanel.addOverviewProvider(markerManager.getOverviewProvider());
		diffNavigatable = new DiffNavigatable(this, codeViewerService.getNavigatable());
		diffFieldNavigator = new FieldNavigator(diffServiceProvider, diffNavigatable);
		diffListingPanel.addButtonPressedListener(diffFieldNavigator);
		help.registerHelp(diffListingPanel, new HelpLocation("Diff", "Program_Differences"));
		GoToService diffMarkerGoToService = diffServiceProvider.getService(GoToService.class);
		markerManager.setGoToService(diffMarkerGoToService);

		actionManager.setCodeViewerService(codeViewerService);
		setupOptions();

		execDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS);
		isLimitedToSelection = false;

		applySettingsMgr = new DiffApplySettingsOptionManager(this);
		applyFilter = applySettingsMgr.getDefaultApplyFilter();

		codeViewerService.setCoordinatedListingPanelListener(new CoordinatedListingPanelListener() {
			@Override
			public void activeProgramChanged(Program newActiveProgram) {
				setActiveProgram(newActiveProgram);
			}

			@Override
			public boolean listingClosed() {
				if (primaryProgram != null) {
					closeProgram2();
					return true;
				}
				return false;
			}
		});

	}

	synchronized boolean isTaskInProgress() {
		return taskInProgress;
	}

	synchronized void setTaskInProgress(boolean inProgress) {
		taskInProgress = inProgress;
		updatePgm2Enablement();
		diffTaskListener.taskInProgress(inProgress);
	}

	void setDiffTaskListener(DiffTaskListener listener) {
		diffTaskListener = listener;
	}

	Address getCurrentAddress() {
		if (currentLocation != null) {
			return currentLocation.getAddress();
		}
		return null;
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	DiffController getDiffController() {
		return diffControl;
	}

	void setDiffController(DiffController dc) {
		diffControl = dc;
		execDiffFilter = diffControl.getDiffFilter();
		diffControl.addDiffControllerListener(this);
	}

	ProgramSelection getCurrentSelection() {
		if (currentSelection == null) {
			AddressFactory p1AddressFactory =
				(primaryProgram != null) ? primaryProgram.getAddressFactory() : null;
			currentSelection = new ProgramSelection(p1AddressFactory);
		}
		return currentSelection;
	}

	DiffApplySettingsProvider getDiffApplySettingsProvider() {
		if (diffApplySettingsProvider == null) {
			diffApplySettingsProvider = new DiffApplySettingsProvider(this);
		}
		if (secondaryDiffProgram != null && applySettingsListener == null) {
			addApplySettingsProviderComponent();
		}
		return diffApplySettingsProvider;
	}

	void addApplySettingsProviderComponent() {
		tool.addComponentProvider(diffApplySettingsProvider, false);
		applySettingsListener = new ApplySettingsActionListener();
		diffApplySettingsProvider.addActionListener(applySettingsListener);
		diffApplySettingsProvider.addActions();
	}

	void removeApplySettingsProviderComponent() {
		diffApplySettingsProvider.removeActionListener(applySettingsListener);
		applySettingsListener = null;
		tool.removeComponentProvider(diffApplySettingsProvider);
	}

	DiffDetailsProvider getDiffDetailsProvider() {
		if (diffDetailsProvider == null) {
			diffDetailsProvider = new DiffDetailsProvider(this);
		}
		if (secondaryDiffProgram != null && diffDetailsListener == null) {
			addDiffDetailsProviderComponent();
		}
		return diffDetailsProvider;
	}

	void addDiffDetailsProviderComponent() {
		tool.addComponentProvider(diffDetailsProvider, false);
		diffDetailsListener = new DiffDetailsActionListener();
		diffDetailsProvider.addActionListener(diffDetailsListener);
		diffDetailsProvider.addActions();
	}

	void removeDiffDetailsProviderComponent() {
		diffDetailsProvider.removeActionListener(diffDetailsListener);
		diffDetailsListener = null;
		tool.removeComponentProvider(diffDetailsProvider);
	}

	/**
	 * Callback when user changes selection in the program2 diff panel.
	 *
	 * Note: A P2 selection is handed to this method when a selection is made in the diff
	 * listing which displays P2.
	 */
	@Override
	public void programSelectionChanged(ProgramSelection newP2Selection) {
		setProgram2Selection(newP2Selection);
	}

	void setProgram2Selection(ProgramSelection newP2Selection) {
		if (primaryProgram == null || primaryProgram != currentProgram || !showingSecondProgram) {
			return;
		}

		// Make sure that the Diff selection is to the code unit boundary.
		ProgramSelection p2CodeUnitSelection =
			new ProgramSelection(DiffUtility.getCodeUnitSet(newP2Selection, secondaryDiffProgram));
		AddressFactory p1AddressFactory =
			(primaryProgram != null) ? primaryProgram.getAddressFactory() : null;
		ProgramSelection intersection =
			new ProgramSelection(p2AddressFactory, p2CodeUnitSelection.intersect(p2DiffHighlight));

		p2Selection = intersection;
		AddressSet p2SelectionAsP1Set =
			DiffUtility.getCompatibleAddressSet(p2Selection, primaryProgram);

		///////////////////////////////////////////
		// Note: the AddressIndexMap in the diff listing wants a P1 selection, because
		// of the MultiListing Layout being used.
		///////////////////////////////////////////

		ProgramSelection p2SelectionAsP1 =
			new ProgramSelection(p1AddressFactory, p2SelectionAsP1Set);
		runSwing(() -> {
			MarkerSet selectionMarkers = getSelectionMarkers();
			selectionMarkers.clearAll();
			selectionMarkers.add(p2Selection);
		});

		diffListingPanel.setSelection(p2SelectionAsP1);
		updatePgm2Enablement();

		if (!SystemUtilities.isEqual(p2SelectionAsP1, currentSelection)) {
			currentSelection = p2SelectionAsP1;
			actionManager.setP1SelectToP2ActionEnabled(
				(secondaryDiffProgram != null) && !currentSelection.isEmpty());
			firePluginEvent(new ProgramSelectionPluginEvent(this.getName(),
				new ProgramSelection(p1AddressFactory, currentSelection), primaryProgram));
		}
	}

	ProgramSelection getProgram2Selection() {
		return p2Selection;
	}

	boolean isShowingDiff() {
		return showingSecondProgram;
	}

	void applyDiffAndGoNext() {
		applyDiff();
		NextDiffCommand nextCmd = new NextDiffCommand(this);
		tool.executeBackgroundCommand(nextCmd, primaryProgram);
	}

	void applyDiff() {
		if (!applyIsSet()) {
			tool.setStatusInfo(
				"At least one difference type must be set to \'Replace\' or \'Merge\' in the " +
					diffApplySettingsProvider.getName() + ".",
				true);
			return;
		}

		if (primaryProgram.getCurrentTransaction() != null) {
			String msg = "Cannot apply differences while another task is modifying \"" +
				primaryProgram.getName() + "\"." +
				"\nTry again when the currently executing task has completed.";
			Msg.showError(getClass(), tool.getToolFrame(), "Apply Differences", msg);
			return;
		}

		// Limit the apply to the selection in the view.
		AddressSet p2SelectionAsP1 =
			DiffUtility.getCompatibleAddressSet(p2Selection, primaryProgram);
		AddressSet p1ApplySet = p2SelectionAsP1.intersect(p1ViewAddrSet)
				.subtract(addressesOnlyInP1)
				.subtract(compatibleOnlyInP2);
		if (p1ApplySet.isEmpty()) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "Apply Differences",
				(p2Selection.isEmpty()) ? "No diff selection in the current view."
						: "Nothing can be applied from the current selection.");
			return;
		}
		ApplyDiffCommand applyCmd = new ApplyDiffCommand(this, p1ApplySet, diffControl);
		tool.executeBackgroundCommand(applyCmd, primaryProgram);
	}

	private boolean applyIsSet() {
		if (diffControl == null) {
			return false;
		}
		ProgramMergeFilter filter = diffControl.getMergeFilter();
		// Want to know if something other than the primary symbol filter is set.
		filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.IGNORE);
		return filter.isSet();
	}

	void adjustDiffDisplay() {
		tool.getToolFrame().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		setDiffHighlight();

		MarkerSet diffMarkers = getDiffMarkers();
		diffMarkers.setMarkerColor(diffHighlightColor);

		setProgram2Selection(p2Selection);
		updatePgm2Enablement();
	}

	/**
	 * Set the highlight based on the current program differences, but
	 * do not set the highlight for set of addresses to be ignored.
	 * @param ignoreAddressSet the set of addresses to ignore.
	 */
	private void setDiffHighlight() {
		if (diffControl == null) {
			return;
		}

		AddressSetView p1DiffSet = null;
		try {
			p1DiffSet = diffControl.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// Shouldn't get this, since using a DUMMY_MONITOR.
		}

		AddressSet p2DiffSet = DiffUtility.getCompatibleAddressSet(p1DiffSet, secondaryDiffProgram);
		ProgramSelection p2DiffSelection = new ProgramSelection(p2AddressFactory, p2DiffSet);
		p2DiffHighlight = p2DiffSelection;
		AddressSet p2DiffSetAsP1 = DiffUtility.getCompatibleAddressSet(p2DiffSet, primaryProgram);

		// Must be on the Swing thread to modify MarkerSets
		runSwing(() -> {
			// Right side markers need p1 addresses since they use p1 indexMap.
			MarkerSet diffMarkers = getDiffMarkers(); // Get right side markers for program 2.
			diffMarkers.clearAll();
			diffMarkers.add(p2DiffSet);

			MarkerSet codeViewerDiffMarkers = getCodeViewerMarkers(); // Get left side markers for program 1.
			codeViewerDiffMarkers.clearAll();
			codeViewerDiffMarkers.add(p2DiffSetAsP1);
			diffListingPanel.getFieldPanel().repaint();
		});
	}

	private void setDiffHighlight(final ProgramSelection p2Highlight) {
		if (diffControl == null) {
			return;
		}

		MarkerSet diffMarkers = getDiffMarkers();
		MarkerSet codeViewerDiffMarkers = getCodeViewerMarkers();

		diffMarkers.clearAll();
		codeViewerDiffMarkers.clearAll();

		if (p2Highlight != null && secondaryDiffProgram != null && diffControl != null) {
			AddressSet p1DiffHighlightSet =
				DiffUtility.getCompatibleAddressSet(p2Highlight, primaryProgram);
			p2DiffHighlight = p2Highlight;
			diffMarkers.add(p2Highlight);
			codeViewerDiffMarkers.add(p1DiffHighlightSet);
		}

		updatePgm2Enablement();
	}

	void nextDiff() {
		tool.clearStatusInfo();
		if (diffControl.hasNext()) {
			diffControl.next();
		}
		setProgram2Selection(new ProgramSelection(p2AddressFactory, getDiffHighlightBlock()));
	}

	void previousDiff() {
		tool.clearStatusInfo();
		if (diffControl.hasPrevious()) {
			diffControl.previous();
		}
		setProgram2Selection(new ProgramSelection(p2AddressFactory, getDiffHighlightBlock()));
	}

	private void clearDiff() {
		if (diffApplySettingsProvider != null) {
			removeApplySettingsProviderComponent();
		}
		if (diffDetailsProvider != null) {
			removeDiffDetailsProviderComponent();
		}
		if (executeDiffDialog != null) {
			executeDiffDialog.close();
		}
		if (diffControl != null) {

			clearDiffMarkers();

			p2DiffHighlight = new ProgramSelection();

			clearCodeViewerDiffMarkers();

			setProgram2Selection(new ProgramSelection());
			firePluginEvent(new ProgramSelectionPluginEvent(this.getName(), new ProgramSelection(),
				primaryProgram));
			diffControl.removeDiffControllerListener(this);
			diffControl = null;
		}
		updatePgm2Enablement();
	}

	/**
	 * Computes the differences between program1 and program2 that are displayed
	 * in the browser using the current Limiting set. It allows the user to specify the Diff settings to use.
	 */
	void diff() {
		diff(createLimitingSet());
	}

	/**
	 * Computes the differences between program1 and program2 that are displayed
	 * in the browser. It allows the user to specify the Diff settings to use.
	 * @param p1LimitSet an address set to use to limit the extent of the Diff.
	 */
	void diff(AddressSetView p1LimitSet) {
		if (taskInProgress) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "Can't Start Another Diff",
				"A Diff or Apply is already in progress.");
			return;
		}
		boolean reload = diffControl != null;
		if (reload) {
			reloadDiff(p1LimitSet);
		}
		else {
			createDiff(p1LimitSet);
		}
	}

	void ignoreDiff() {
		JFrame frame = tool.getToolFrame();
		try {
			frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			tool.clearStatusInfo();
			// Limit the apply to the selection in the view.
			AddressSet p2ViewAddrSet =
				DiffUtility.getCompatibleAddressSet(p1ViewAddrSet, secondaryDiffProgram);
			AddressSet p2IgnoreSet = p2Selection.intersect(p2ViewAddrSet);
			if (p2IgnoreSet.isEmpty()) {
				Msg.showError(getClass(), frame, "Ignore Selection and Goto Next Difference",
					"No diff selection in the current view.");
				return;
			}
			AddressSet p1IgnoreSet =
				DiffUtility.getCompatibleAddressSet(p2IgnoreSet, primaryProgram);
			diffControl.ignore(p1IgnoreSet, null);
			p2DiffHighlight =
				new ProgramSelection(p2AddressFactory, p2DiffHighlight.subtract(p2IgnoreSet));

			adjustDiffDisplay();

		}
		finally {
			diffListingPanel.getFieldPanel().requestFocus();
			frame.setCursor(Cursor.getDefaultCursor());
			NextDiffCommand nextCmd = new NextDiffCommand(this);
			tool.executeBackgroundCommand(nextCmd, primaryProgram);
		}
	}

	void hideDiffApplySettings() {
		tool.showComponentProvider(diffApplySettingsProvider, false);
	}

	void showDiffApplySettings() {
		if (!tool.isVisible(diffApplySettingsProvider)) {
			tool.showComponentProvider(diffApplySettingsProvider, true);
		}
	}

	void hideDiffDetails() {
		if (diffDetailsProvider != null) {
			tool.showComponentProvider(diffDetailsProvider, false);
		}
	}

	void showDiffDetails() {
		DiffDetailsProvider detailsProvider = getDiffDetailsProvider();
		if (tool.isVisible(detailsProvider)) {
			detailsProvider.refreshDetails(currentLocation);
		}
		else {
			tool.showComponentProvider(detailsProvider, true);
		}
	}

	void selectAllDiffs() {
		JFrame frame = tool.getToolFrame();
		try {
			frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			tool.clearStatusInfo();
			AddressSetView adjustedView = p1ViewAddrSet;
			if (secondaryDiffProgram != null) {
				if ((primaryProgram != null) &&
					p1ViewAddrSet.contains(new AddressSet(primaryProgram.getMemory()))) {
					adjustedView = ProgramMemoryComparator.getCombinedAddresses(primaryProgram,
						secondaryDiffProgram);
				}
			}
			AddressSetView p2ViewAddrSet =
				DiffUtility.getCompatibleAddressSet(adjustedView, secondaryDiffProgram);
			setProgram2Selection(new ProgramSelection(p2AddressFactory, p2ViewAddrSet));
		}
		finally {
			diffListingPanel.getFieldPanel().requestFocus();
			frame.setCursor(Cursor.getDefaultCursor());
		}
	}

	void closeProgram2() {
		codeViewerService.removeListingPanel(diffListingPanel);
		showingSecondProgram = false;
		diffListingPanel.setProgram(null);
		p2Selection = new ProgramSelection();
		setProgram2Selection(p2Selection);
		clearDiff();
		if (secondaryDiffProgram != null) {
			markerManager.setProgram(null);
			Iterator<BookmarkNavigator> iter = bookmarkMap.values().iterator();
			while (iter.hasNext()) {
				BookmarkNavigator nav = iter.next();
				nav.dispose();
			}
			bookmarkMap.clear();

			actionManager.secondProgramClosed();
			secondaryDiffProgram.release(this);
			diffDetails = null;

			clearMarkers();
			addressesOnlyInP1 = new AddressSet();
			compatibleOnlyInP2 = new AddressSet();
			primaryProgram.removeListener(this);
			primaryProgram = null;
			secondaryDiffProgram = null;
			p2AddressFactory = null;
		}
		sameProgramContext = false;
		updatePgm2Enablement();
	}

	CodeViewerService getCodeViewerService() {
		return codeViewerService;
	}

	void selectProgram2() {
		if (primaryProgram != null) {
			String msg = primaryProgram.getDomainFile().getName() +
				" already has a Diff view. Only one is allowed at a time.";
			tool.setStatusInfo(msg, true);
			Msg.showWarn(this, diffListingPanel, "Diff Already In Progress", msg);
			return;
		}

		final OpenVersionedFileDialog dialog = getOpenProgramDialog();
		okListener = e -> {
			tool.clearStatusInfo();
			JComponent component = dialog.getComponent();

			DomainObject dobj = dialog.getVersionedDomainObject(ProgramDiffPlugin.this, false);
			if (dobj != null) {
				if (openSecondProgram((Program) dobj, component)) {
					dialog.close();
					launchDiffOnOpenProgram();
				}
				return;
			}

			DomainFile df = dialog.getDomainFile();
			if (df != null) {
				if (openSecondProgram(df)) {
					dialog.close();
					launchDiffOnOpenProgram();
				}
				return;
			}

			displayStatus(component, "Can't Open Selected Program",
				"Please select a file, not a folder.", OptionDialog.INFORMATION_MESSAGE);
		};
		dialog.addOkActionListener(okListener);

		dialog.showComponent();
		actionManager.setOpenCloseActionSelected(secondaryDiffProgram != null);
		getDiffDetailsProvider();
	}

	private OpenVersionedFileDialog getOpenProgramDialog() {

		if (openProgramDialog != null) {
			return openProgramDialog;
		}

		OpenVersionedFileDialog dialog =
			new OpenVersionedFileDialog(tool, "Select Other Program", f -> {
				Class<?> c = f.getDomainObjectClass();
				return Program.class.isAssignableFrom(c);
			});
		dialog.setTreeSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		dialog.setHelpLocation(new HelpLocation("Diff", "Open_Close_Program_View"));
		return dialog;
	}

	/**
	 * Displays the execute diff dialog.
	 */
	void displayExecuteDiff() {
		if (executeDiffDialog == null) {
			executeDiffDialog = new ExecuteDiffDialog();
			executeDiffDialog.addActionListener(new DiffActionListener());
		}
		if (executeDiffDialog != null) {
			executeDiffDialog.configure(primaryProgram, secondaryDiffProgram, currentSelection,
				execDiffFilter);
			executeDiffDialog.setPgmContextEnabled(sameProgramContext);
			tool.showDialog(executeDiffDialog);
		}
	}

	void setP1SelectionOnP2() {
		if (!currentSelection.isEmpty()) {
			AddressSet p2SelectionSet =
				DiffUtility.getCompatibleAddressSet(currentSelection, secondaryDiffProgram);
			setProgram2Selection(new ProgramSelection(p2AddressFactory,
				DiffUtility.getCodeUnitSet(p2SelectionSet, secondaryDiffProgram)));
		}
		if (p2Selection.isEmpty()) {
			tool.setStatusInfo("No highlights in second program for the selection.", true);
		}

	}

	/**
	 * Get the first program for the current Diff.
	 * <br><b>Note</b>: This may not be the currently active program.
	 * @return the Diff's first program or null if don't currently have a
	 * second program associated for a Diff.
	 */
	Program getFirstProgram() {
		return primaryProgram;
	}

	/**
	 * Get the second program for the current Diff.
	 * @return the Diff's second program or null if don't currently have a
	 * second program associated for a Diff.
	 */
	Program getSecondProgram() {
		return secondaryDiffProgram;
	}

	void activeProgram(Program program) {
		ProgramManager programManager = tool.getService(ProgramManager.class);
		programManager.setCurrentProgram(program);
	}

	void addDiffDetails(Address p1Address, StyledDocument doc) {
		// FUTURE This may need to be changed to a background task.
		if (diffDetails != null) {
			diffDetails.getAllDetails(p1Address, doc, getDiffCountInfo(p1Address));
		}
		else {
			try {
				doc.insertString(doc.getLength(), "Don't have a second program open.",
					new SimpleAttributeSet());
			}
			catch (BadLocationException e) {
				// Shouldn't happen, since adding at end of doc.
			}
		}
	}

	void addFilteredDiffDetails(Address p1Address, ProgramDiffFilter filter, StyledDocument doc) {
		// FUTURE This may need to be changed to a background task.
		if (diffDetails != null) {
			diffDetails.getDetails(p1Address, filter, doc, getDiffCountInfo(p1Address));
		}
		else {
			try {
				doc.insertString(doc.getLength(), "Don't have a second program open.",
					new SimpleAttributeSet());
			}
			catch (BadLocationException e) {
				// Shouldn't happen, since adding at end of doc.
			}
		}
	}

	ListingPanel getListingPanel() {
		return diffListingPanel;
	}

	ProgramSelection getDiffHighlightSelection() {
		return p2DiffHighlight;
	}

	/**
	 * Gets the address set where detailed differences will be determined for details at the
	 * indicated address. An address set is returned since the indicated address may be in different
	 * sized code units in each of the two programs.
	 * @param p1Address the current address from program1 where details are desired.
	 * @return the address set for code units containing that address within the programs being
	 * compared to determine differences.
	 * Otherwise null if a diff of two programs isn't being performed.
	 */
	AddressSetView getDetailsAddressSet(Address p1Address) {
		if (diffDetails != null) {
			return diffDetails.getDetailsAddressSet(p1Address);
		}
		return null;
	}

	private AddressSetView createLimitingSet() {
		if (primaryProgram == null) {
			return null;
		}
		if (executeDiffDialog != null) {
			return executeDiffDialog.getAddressSet();
		}
		AddressSet limitSet = new AddressSet(primaryProgram.getMemory());
		limitSet = limitSet.union(compatibleOnlyInP2);
		if (currentSelection != null && !currentSelection.isEmpty()) {
			limitSet = limitSet.intersect(currentSelection);
		}
		return limitSet;
	}

	/**
	 * Reload the marked differences in the diff panel.
	 */
	private void reloadDiff(AddressSetView p1LimitSet) {
		if (diffControl == null) {
			createDiff(p1LimitSet);
		}
		else {
			tool.clearStatusInfo();
			if (p1LimitSet == null) {
				p1LimitSet = createLimitingSet();
			}
			displayExecuteDiff();
		}
	}

	private void createDiff(AddressSetView p1LimitSet) {
		Frame frame = tool.getToolFrame();
		try {
			frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			tool.clearStatusInfo();

			if (secondaryDiffProgram == null) {
				selectProgram2();
				if (secondaryDiffProgram == null) {
					return;
				}
			}
			if (executeDiffDialog != null) {
				executeDiffDialog.close();
				executeDiffDialog = null;
			}
			if (p1LimitSet == null) {
				p1LimitSet = createLimitingSet();
			}
			displayExecuteDiff();
		}
		finally {
			frame.setCursor(Cursor.getDefaultCursor());
		}
	}

	private void updatePgm2Enablement() {
		boolean hasProgram2 = (secondaryDiffProgram != null);
		boolean inDiff = (diffControl != null);
		boolean hasHighlights = (p2DiffHighlight != null) && !p2DiffHighlight.isEmpty();
		AddressSet possibleAddresses = new AddressSet(p1ViewAddrSet);
		// If the left side of Diff isn't a limited view then include the compatible addresses
		// for those that are only in program2.
		if (p1ViewAddrSet != null && primaryProgram != null &&
			p1ViewAddrSet.equals(primaryProgram.getMemory())) {
			possibleAddresses.add(compatibleOnlyInP2);
		}
		boolean hasSelectionInView = false;
		if (hasProgram2) {
			AddressSet possibleP2Addresses =
				DiffUtility.getCompatibleAddressSet(possibleAddresses, secondaryDiffProgram);
			hasSelectionInView = !(p2Selection.intersect(possibleP2Addresses).isEmpty());
		}
		actionManager.updateActions(taskInProgress, inDiff, hasSelectionInView, applyIsSet(),
			hasProgram2, hasHighlights);
	}

	private void codeViewerServiceGoTo(final ProgramLocation loc) {

		// we have to be careful to make sure the goTo() call is on the
		// swing thread, since some of the calls to this method are triggered
		// by background tasks
		if (SwingUtilities.isEventDispatchThread()) {
			codeViewerService.goTo(loc, false);
		}
		else {
			Runnable runner = () -> codeViewerService.goTo(loc, false);

			try {
				SwingUtilities.invokeAndWait(runner);
			}
			catch (InterruptedException e) {
				// if we were interrupted, then just try to run the command
				// later
				SwingUtilities.invokeLater(runner);
			}
			catch (InvocationTargetException e) {
				// if the runner threw an exception, then show an error
				Msg.showError(this, null, "Unexpected Exception",
					"Encountered an unexpected exception calling " +
						"codeViewerService.goTo(ProgramLocation,boolean).",
					e);
			}
		}
	}

	private void goToServiceGoTo(final ProgramLocation loc) {

		previousP1Location = currentLocation;

		// we have to be careful to make sure the goTo() call is on the
		// swing thread, since some of the calls to this method are triggered
		// by background tasks
		if (SwingUtilities.isEventDispatchThread()) {
			if (currentProgram.getMemory().contains(loc.getAddress())) {
				// Address is in left panel's program.
				goToService.goTo(loc);
			}
			else {
				// Address wasn't in left program so must be in right program only.
				diffListingPanel.goTo(loc, true);
			}
		}
		else {
			Runnable runner = () -> goToService.goTo(loc);

			try {
				SwingUtilities.invokeAndWait(runner);
			}
			catch (InterruptedException e) {
				// if we were interrupted, then just try to run the command
				// later
				SwingUtilities.invokeLater(runner);
			}
			catch (InvocationTargetException e) {
				// if the runner threw an exception, then show an error
				Msg.showError(this, null, "Unexpected Exception",
					"Encountered an unexpected exception calling " +
						"goToService.goTo(ProgramLocation,boolean).",
					e);
			}
		}
	}

	private void setupOptions() {
		String OPTIONS_TITLE = GhidraOptions.CATEGORY_BROWSER_FIELDS;
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.registerOption(DIFF_HIGHLIGHT_COLOR_NAME, diffHighlightColor,
			new HelpLocation("CodeBrowserPlugin", "Browser_Fields"),
			"Color used to highlight differences between two programs.");
		Color c = opt.getColor(DIFF_HIGHLIGHT_COLOR_NAME, diffHighlightColor);
		diffHighlightColor = c;
		opt.addOptionsChangeListener(this);

		cursorHighlightColor = opt.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR, null);
		isHighlightCursorLine = opt.getBoolean(GhidraOptions.HIGHLIGHT_CURSOR_LINE, false);
	}

	private MarkerSet getSelectionMarkers() {
		// already created
		if (p2SelectionMarkers != null) {
			return p2SelectionMarkers;
		}

		FieldPanel fp = diffListingPanel.getFieldPanel();
		p2SelectionMarkers =
			markerManager.createAreaMarker("Selection", "Selection Display", secondaryDiffProgram,
				MarkerService.SELECTION_PRIORITY, false, true, false, fp.getSelectionColor());
		return p2SelectionMarkers;
	}

	private MarkerSet getDiffMarkers() {
		// already created
		if (p2DiffMarkers != null) {
			return p2DiffMarkers;
		}

		p2DiffMarkers =
			markerManager.createAreaMarker("Difference", "Diff Display", secondaryDiffProgram,
				MarkerService.DIFF_PRIORITY, false, true, true, diffHighlightColor);
		return p2DiffMarkers;
	}

	private MarkerSet getCursorMarkers() {
		// already created
		if (p2CursorMarkers != null) {
			return p2CursorMarkers;
		}

		p2CursorMarkers = markerManager.createPointMarker("Cursor", "Cursor Location",
			secondaryDiffProgram, MarkerService.CURSOR_PRIORITY, true, true, isHighlightCursorLine,
			cursorHighlightColor, CURSOR_LOC_ICON);

		return p2CursorMarkers;
	}

	private MarkerSet getCodeViewerMarkers() {
		MarkerService markerService = tool.getService(MarkerService.class);
		if (markerService == null) {
			return null;
		}

		// already created
		if (p1DiffMarkers != null) {
			return p1DiffMarkers;
		}

		p1DiffMarkers = markerService.createAreaMarker("Difference", "Diff Display", primaryProgram,
			MarkerService.DIFF_PRIORITY, false, true, true, diffHighlightColor);
		return p1DiffMarkers;
	}

	private void clearMarkers() {
		clearSelectionMarkers();
		clearDiffMarkers();
		clearCursorMarkers();
		clearCodeViewerDiffMarkers();
	}

	private void clearSelectionMarkers() {
		if (p2SelectionMarkers == null) {
			return;
		}

		markerManager.removeMarker(p2SelectionMarkers, secondaryDiffProgram);
		p2SelectionMarkers = null;
	}

	private void clearDiffMarkers() {
		if (p2DiffMarkers == null) {
			return;
		}

		markerManager.removeMarker(p2DiffMarkers, secondaryDiffProgram);
		p2DiffMarkers = null;
	}

	private void clearCursorMarkers() {
		if (p2CursorMarkers == null) {
			return;
		}

		markerManager.removeMarker(p2CursorMarkers, secondaryDiffProgram);
		p2CursorMarkers = null;
	}

	private void clearCodeViewerDiffMarkers() {
		if (p1DiffMarkers == null) {
			return;
		}

		MarkerService markerService = tool.getService(MarkerService.class);
		if (markerService == null) {
			return;
		}

		markerService.removeMarker(p1DiffMarkers, primaryProgram);
		p1DiffMarkers = null;
	}

	private boolean openSecondProgram(DomainFile df) {

		OpenSecondProgramTask task = new OpenSecondProgramTask(df);
		new TaskLauncher(task, tool.getToolFrame(), 500);
		// block until the task completes

		if (!task.wasCanceled()) {
			Program newProgram = task.getDiffProgram();
			if (newProgram != null) {
				return openSecondProgram(newProgram, null);
			}
		}
		return false;
	}

	private boolean openSecondProgram(Program newProgram, JComponent selectDialog) {
		if (newProgram == null) {
			displayStatus(selectDialog, "Can't Open Selected Program",
				"Couldn't open second program.", OptionDialog.ERROR_MESSAGE);
			return false;
		}

		if (!ProgramMemoryComparator.similarPrograms(currentProgram, newProgram)) {
			newProgram.release(this);
			String message = "Programs languages don't match.\n" + currentProgram.getName() + " (" +
				currentProgram.getLanguageID() + ")\n" + newProgram.getName() + " (" +
				newProgram.getLanguageID() + ")";
			displayStatus(selectDialog, "Can't Open Selected Program", message,
				OptionDialog.ERROR_MESSAGE);
			return false;
		}
		ProgramMemoryComparator programMemoryComparator = null;
		try {

			programMemoryComparator = new ProgramMemoryComparator(currentProgram, newProgram);
		}
		catch (ProgramConflictException e) {
			Msg.error(this, "Unexpected exception creating memory comparator", e);
			return false;
		}
		addressesOnlyInP1 = programMemoryComparator.getAddressesOnlyInOne();
		compatibleOnlyInP2 = programMemoryComparator.getCompatibleAddressesOnlyInTwo();
		AddressSet addressesInCommon = programMemoryComparator.getAddressesInCommon();
		AddressSet combinedAddresses =
			ProgramMemoryComparator.getCombinedAddresses(currentProgram, newProgram);
		if (addressesInCommon.isEmpty()) {
			int selectedOption = OptionDialog.showYesNoDialog(selectDialog, "No Memory In Common",
				"The two programs have no memory addresses in common.\n" +
					"Do you want to continue?");
			if (selectedOption != OptionDialog.YES_OPTION) {
				newProgram.release(this);
				return false;
			}
		}
		if (secondaryDiffProgram != null) {
			closeProgram2();
		}

		primaryProgram = currentProgram;
		secondaryDiffProgram = newProgram;
		p2AddressFactory = secondaryDiffProgram.getAddressFactory();
		applyFilter = applySettingsMgr.getDefaultApplyFilter();
		diffDetails = new ProgramDiffDetails(primaryProgram, secondaryDiffProgram);
		primaryProgram.addListener(this);

		try {
			settingLocation = true;
			diffListingPanel.setProgram(secondaryDiffProgram);
			AddressSet p2ViewAddrSet =
				DiffUtility.getCompatibleAddressSet(p1ViewAddrSet, secondaryDiffProgram);
			diffListingPanel.setView(p2ViewAddrSet);
			// If the entire first program is being viewed then force any additional memory in
			// program2 that isn't in program1 but that is compatible with program1 to get added
			// to the first program's view.
			if (p1ViewAddrSet.contains(primaryProgram.getMemory())) {
				this.firePluginEvent(
					new ViewChangedPluginEvent(this.getName(), null, combinedAddresses));
			}
			FieldPanel fp = diffListingPanel.getFieldPanel();
			showSecondView();
			AddressIndexMap indexMap = diffListingPanel.getAddressIndexMap();
			fp.setBackgroundColorModel(
				new MarkerServiceBackgroundColorModel(markerManager, indexMap));
		}
		finally {
			settingLocation = false;
		}
		markerManager.setProgram(secondaryDiffProgram);
		setupBookmarkNavigators();

		sameProgramContext = ProgramMemoryComparator.sameProgramContextRegisterNames(primaryProgram,
			secondaryDiffProgram);
		actionManager.secondProgramOpened();
		actionManager.addActions();
		diffListingPanel.goTo(currentLocation);

		MarkerSet cursorMarkers = getCursorMarkers();
		Address currentP2Address = currentLocation.getAddress();
		if (currentLocation.getProgram() != secondaryDiffProgram) { // Make sure address is from P2.
			currentP2Address = SimpleDiffUtility.getCompatibleAddress(currentLocation.getProgram(),
				currentLocation.getAddress(), secondaryDiffProgram);
		}
		if (currentP2Address != null) {
			cursorMarkers.setAddressSet(new AddressSet(currentP2Address));
		}

		updatePgm2Enablement();

		if (diffControl != null) {
			clearDiff();
		}
		return true;
	}

	private void runSwing(Runnable r) {
		SystemUtilities.runIfSwingOrPostSwingLater(r);
	}

	private void showSecondView() {
		codeViewerService.setListingPanel(diffListingPanel);
		activeProgram = primaryProgram;
		showingSecondProgram = true;
	}

	private void removeSecondView() {
		codeViewerService.removeListingPanel(diffListingPanel);
		showingSecondProgram = false;
		actionManager.removeActions();
	}

	private void displayStatus(JComponent parent, String title, String message, int dialogType) {

		Component parentComponent = parent;
		if (parentComponent == null) {
			parentComponent = tool.getToolFrame();
		}

		switch (dialogType) {
			case OptionDialog.PLAIN_MESSAGE:
				Msg.showInfo(getClass(), parent, title, message);
				break;
			case OptionDialog.INFORMATION_MESSAGE:
				Msg.showInfo(getClass(), parent, title, message);
				break;
			case OptionDialog.WARNING_MESSAGE:
				Msg.showWarn(getClass(), parent, title, message);
				break;
			case OptionDialog.ERROR_MESSAGE:
				Msg.showError(getClass(), parent, title, message);
				break;
		}
	}

	private AddressSetView getDiffHighlightBlock() {
		if (diffControl == null) {
			return new AddressSet();
		}
		Address p1DiffAddress = diffControl.getCurrentAddress();
		Address p2DiffAddress = SimpleDiffUtility.getCompatibleAddress(primaryProgram,
			p1DiffAddress, secondaryDiffProgram);
		AddressRange range = p2DiffHighlight.getRangeContaining(p2DiffAddress);
		if (range == null) {
			return new AddressSet();
		}
		return new AddressSet(range);
	}

	private void setupBookmarkNavigators() {
		BookmarkManager bookmarkMgr = secondaryDiffProgram.getBookmarkManager();
		BookmarkNavigator.defineBookmarkTypes(secondaryDiffProgram);
		BookmarkType[] types = bookmarkMgr.getBookmarkTypes();
		for (BookmarkType element : types) {
			BookmarkNavigator nav = new BookmarkNavigator(markerManager, bookmarkMgr, element);
			nav.updateBookmarkers(
				new AddressSet(bookmarkMgr.getBookmarkAddresses(element.getTypeString())));
			bookmarkMap.put(element, nav);
		}
	}

	private String getDiffCountInfo(Address p1CodeUnitAddress) {
		Address p2CodeUnitAddress = SimpleDiffUtility.getCompatibleAddress(primaryProgram,
			p1CodeUnitAddress, secondaryDiffProgram);
		if (p2CodeUnitAddress == null) {
			return null;
		}
		int rangeCount = p2DiffHighlight.getNumAddressRanges();
		AddressRangeIterator p2DiffIter = p2DiffHighlight.getAddressRanges();
		for (int i = 0; i < rangeCount && p2DiffIter.hasNext(); i++) {
			AddressRange range = p2DiffIter.next();
			if (range.contains(p2CodeUnitAddress)) {
				return "Diff address range " + Integer.toString(i + 1) + " of " + rangeCount + ".";
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DiffActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent event) {
			String actionCommand = event.getActionCommand();
			// DETERMINE DIFFERENCES
			if ((event.getSource() instanceof ExecuteDiffDialog) &&
				(ExecuteDiffDialog.DIFF_ACTION.equals(actionCommand))) {

				execDiffFilter = executeDiffDialog.getDiffFilter();
				isLimitedToSelection = executeDiffDialog.isLimitedToSelection();

				AddressSetView displaySet = isLimitedToSelection ? createLimitingSet() : null;
				try {
					ProgramMemoryComparator programMemoryComparator =
						new ProgramMemoryComparator(primaryProgram, secondaryDiffProgram);
					addressesOnlyInP1 = programMemoryComparator.getAddressesOnlyInOne();
					compatibleOnlyInP2 = programMemoryComparator.getCompatibleAddressesOnlyInTwo();
				}
				catch (ProgramConflictException e) {
					Msg.showError(getClass(), tool.getToolFrame(), "Can't Compare Memory",
						"Diff can't compare the two programs memory. " + e.getMessage());
					return;
				}

				Task task =
					new CreateDiffTask(ProgramDiffPlugin.this, primaryProgram, secondaryDiffProgram,
						displaySet, isLimitedToSelection, execDiffFilter, applyFilter);
				tool.execute(task);
			}
		}

	}

	private class ApplySettingsActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent event) {
			String actionCommand = event.getActionCommand();

			// DIFF APPLY SETTINGS CHANGED
			// DIFFERENCES TO APPLY CHANGED
			if (DiffApplySettingsProvider.APPLY_FILTER_CHANGED_ACTION.equals(actionCommand)) {
				applyFilter = diffApplySettingsProvider.getApplyFilter();
				if (diffControl != null) {
					diffControl.setMergeFilter(applyFilter);
				}
				updatePgm2Enablement();
			}
		}
	}

	private class DiffDetailsActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent event) {
			String actionCommand = event.getActionCommand();

			if (DiffDetailsProvider.DIFF_DETAILS_HIDDEN_ACTION.equals(actionCommand)) {
				if (diffDetailsProvider != null) {
					tool.showComponentProvider(diffDetailsProvider, false);
				}
			}
		}
	}

	private class MyFieldMouseListener implements FieldMouseListener {
		@Override
		public void buttonPressed(FieldLocation location, Field field, MouseEvent ev) {
			// FieldPanel won't notify this listener for drag or button3 events.
			// This only wants to deal with left click to set highlight block to selected.
			if (ev.getButton() != MouseEvent.BUTTON1) {
				return;
			}

			// Listing Panel creates the selection when doing click or drag with Ctrl or Shift.
			if (DockingUtils.isControlModifier(ev) || ev.isShiftDown()) {
				return;
			}

			ListingField lf = (ListingField) field;
			FieldFactory factory = lf.getFieldFactory();
			ProgramLocation pLoc =
				factory.getProgramLocation(location.getRow(), location.getCol(), lf);

			// if clicked in dummy field, try and find the address for the white space.
			if (pLoc == null) {
				AddressIndexMap indexMap = diffListingPanel.getAddressIndexMap();

				Address addr = indexMap.getAddress(location.getIndex());

				if (addr != null && secondaryDiffProgram != null) {
					pLoc = new ProgramLocation(secondaryDiffProgram, addr);
				}
				else {
					return; // pLoc is null
				}
			}

			Address addr = pLoc.getAddress();
			if (!p2Selection.contains(addr)) {
				// Left click in a Diff highlight selects it and only it.
				// Left click outside all highlight blocks clears the selection.
				AddressSet set = new AddressSet(); // Start with no selection.
				if (p2DiffHighlight.contains(addr)) {
					// If clicked in a Diff Highlight then make that the selection.
					AddressRange range = p2DiffHighlight.getRangeContaining(addr);
					if (range != null) {
						set = new AddressSet(range);
					}
				}

				if (set.equals(p2Selection)) {
					return; // Selection is unchanged so do nothing.
				}
				MarkerSet selectionMarkers = getSelectionMarkers();
				selectionMarkers.clearAll();

				programSelectionChanged(new ProgramSelection(p2AddressFactory, set));
				updatePgm2Enablement();
			}
		}
	}

	private class OpenSecondProgramTask extends Task {
		private DomainFile domainFile;
		private Program diffProgram;
		private TaskMonitor monitor;

		OpenSecondProgramTask(DomainFile domainFile) {
			super("Opening Program for Diff", true, true, true);
			this.domainFile = domainFile;
		}

		@Override
		public void run(TaskMonitor taskMonitor) {
			this.monitor = taskMonitor;
			try {
				try {
					monitor.setMessage("Waiting on program file...");
					diffProgram =
						(Program) domainFile.getImmutableDomainObject(ProgramDiffPlugin.this,
							DomainFile.DEFAULT_VERSION, taskMonitor);
				}
				catch (VersionException e) {
					if (e.isUpgradable()) {
						try {
							diffProgram =
								(Program) domainFile.getReadOnlyDomainObject(ProgramDiffPlugin.this,
									DomainFile.DEFAULT_VERSION, taskMonitor);
						}
						catch (VersionException exc) {
							Msg.showError(this, null, "Error Getting Diff Program",
								"Getting read only file failed");
						}
						catch (IOException exc) {
							if (!taskMonitor.isCancelled()) {
								Msg.showError(this, null, "Error Getting Diff Program",
									"Getting read only file failed", exc);
							}
						}
					}
					else {
						Msg.showError(this, null, "Error Getting Diff Program",
							"File cannot be upgraded.");

					}
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error Getting Diff Program",
						"Getting read only file failed", e);
				}
			}
			catch (CancelledException e) {
				// For now do nothing if user cancels
			}

			monitor.setMessage("");
		}

		boolean wasCanceled() {
			return monitor.isCancelled();
		}

		Program getDiffProgram() {
			return diffProgram;
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (secondaryDiffProgram != null && diffDetailsProvider != null) {
			diffDetailsProvider.refreshDetails(currentLocation);
		}
	}
}
