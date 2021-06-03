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
package ghidra.feature.vt.gui.provider.functionassociation;

import static ghidra.feature.vt.api.impl.VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED;
import static ghidra.feature.vt.api.impl.VTChangeManager.DOCR_VT_MATCH_ADDED;
import static ghidra.feature.vt.api.impl.VTChangeManager.DOCR_VT_MATCH_DELETED;
import static ghidra.feature.vt.gui.provider.functionassociation.FilterSettings.SHOW_ALL;
import static ghidra.feature.vt.gui.provider.functionassociation.FilterSettings.SHOW_UNACCEPTED;
import static ghidra.feature.vt.gui.provider.functionassociation.FilterSettings.SHOW_UNMATCHED;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.JTableHeader;

import docking.*;
import docking.action.*;
import docking.actions.PopupActionProvider;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.label.GDLabel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonPanel;
import ghidra.app.services.GoToService;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.feature.vt.api.db.DeletedMatch;
import ghidra.feature.vt.api.impl.VersionTrackingChangeRecord;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.duallisting.VTListingNavigator;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.table.*;
import resources.Icons;
import resources.ResourceManager;

/**
 * Provider for the version tracking function association table. 
 */
public class VTFunctionAssociationProvider extends ComponentProviderAdapter
		implements VTControllerListener, PopupActionProvider {

	private static final String FILTER_SETTINGS_KEY = "FUNCTION_FILTER_SETTINGS";
	private static final String BASE_TITLE = "Version Tracking Functions";
	private static final ImageIcon PROVIDER_ICON =
		ResourceManager.loadImage("images/functions.gif");
	private static final String SOURCE_TITLE = "Source";
	private static final String DESTINATION_TITLE = "Destination";
	private static final String NO_SESSION = "None";
	private static final Icon SHOW_LISTINGS_ICON =
		ResourceManager.loadImage("images/application_tile_horizontal.png");
	private static final String SHOW_COMPARE_ACTION_GROUP = "A9_ShowCompare"; // "A9_" forces to right of other dual view actions in toolbar.

	private GhidraTable sourceFunctionsTable;
	private GhidraTable destinationFunctionsTable;
	private VTFunctionAssociationTableModel sourceFunctionsModel;
	private VTFunctionAssociationTableModel destinationFunctionsModel;
	private JComponent mainPanel;

	private GhidraTableFilterPanel<VTFunctionRowObject> sourceTableFilterPanel;
	private GhidraTableFilterPanel<VTFunctionRowObject> destinationTableFilterPanel;

	private GhidraThreadedTablePanel<VTFunctionRowObject> sourceThreadedTablePanel;
	private GhidraThreadedTablePanel<VTFunctionRowObject> destinationThreadedTablePanel;

	private final VTController controller;
	private Set<VTFunctionAssociationListener> functionAssociationListeners = new HashSet<>();

	private JSplitPane splitPane;
	private JLabel statusLabel;
	private String NO_ERROR_MESSAGE = " ";
	private String matchStatus = NO_ERROR_MESSAGE;
	private JLabel sourceSessionLabel;
	private JLabel destinationSessionLabel;

	private FilterSettings filterSettings = SHOW_ALL;

	private JPanel dualTablePanel;
	private FunctionComparisonPanel functionComparisonPanel;
	private JSplitPane comparisonSplitPane;
	private ToggleDualListingVisibilityAction toggleListingVisibility;

	public VTFunctionAssociationProvider(VTController controller) {
		super(controller.getTool(), BASE_TITLE, VTPlugin.OWNER);
		this.controller = controller;

		mainPanel = createWorkPanel();

		setWindowGroup(VTPlugin.WINDOW_GROUP);
		setIcon(PROVIDER_ICON);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIntraGroupPosition(WindowPosition.STACK);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Functions_Table"));

		addToTool();
		createActions();
		addGeneralCodeComparisonActions();
		controller.addListener(this);
		tool.addPopupActionProvider(this);
	}

	private void createActions() {
		CreateManualMatchAction manualMatchAction = new CreateManualMatchAction(controller);
		addLocalAction(manualMatchAction);

		addLocalAction(new CreateManualMatchAndAcceptAction(controller));
		addLocalAction(new CreateManualMatchAndAcceptAndApplyAction(controller));

		SelectExistingMatchAction selectAction = new SelectExistingMatchAction(controller);
		addLocalAction(selectAction);

		createFilterAction();
	}

	private void createFilterAction() {
		MultiStateDockingAction<FilterSettings> filterAction =
			new MultiStateDockingAction<>("Function Association Functions Filter", VTPlugin.OWNER) {

				@Override
				public void actionStateChanged(ActionState<FilterSettings> newActionState,
						EventTrigger trigger) {
					filterSettings = newActionState.getUserData();
					sourceFunctionsModel.setFilterSettings(filterSettings);
					destinationFunctionsModel.setFilterSettings(filterSettings);
				}
			};
		filterAction.setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Functions_Filter"));

		Icon allFunctionsIcon = ResourceManager.loadImage("images/function.png");
		ActionState<FilterSettings> allFunctionsActionState =
			new ActionState<>("Show All Functions", allFunctionsIcon, SHOW_ALL);
		allFunctionsActionState.setHelpLocation(
			new HelpLocation("VersionTrackingPlugin", "Show_All_Functions"));

		Icon unmatchedIcon = ResourceManager.loadImage("images/filter_matched.png");
		ActionState<FilterSettings> unmatchedOnlyActionState =
			new ActionState<>("Show Only Unmatched Functions", unmatchedIcon, SHOW_UNMATCHED);
		unmatchedOnlyActionState.setHelpLocation(
			new HelpLocation("VersionTrackingPlugin", "Show_Unmatched_Functions"));

		ActionState<FilterSettings> unacceptedOnlyActionState =
			new ActionState<>("Show Only Unaccepted Match Functions",
				Icons.FILTER_NOT_ACCEPTED_ICON, SHOW_UNACCEPTED);
		unacceptedOnlyActionState.setHelpLocation(
			new HelpLocation("VersionTrackingPlugin", "Show_Unaccepted_Functions"));

		filterAction.addActionState(allFunctionsActionState);
		filterAction.addActionState(unmatchedOnlyActionState);
		filterAction.addActionState(unacceptedOnlyActionState);

		addLocalAction(filterAction);
	}

	private void doReloadFunctions() {
		sourceFunctionsModel.reload();
		destinationFunctionsModel.reload();
	}

	@Override
	public void componentHidden() {
		sourceFunctionsModel.clear();
		destinationFunctionsModel.clear();
	}

	@Override
	public void componentShown() {
		reloadFromSession();
	}

	public Function getSelectedSourceFunction() {
		int selectedRowCount = sourceFunctionsTable.getSelectedRowCount();
		if (selectedRowCount == 1) {
			int selectedRow = sourceFunctionsTable.getSelectedRow();
			return sourceFunctionsModel.getFunction(selectedRow);
		}
		return null;
	}

	public Function getSelectedDestinationFunction() {
		int selectedRowCount = destinationFunctionsTable.getSelectedRowCount();
		if (selectedRowCount == 1) {
			int selectedRow = destinationFunctionsTable.getSelectedRow();

			return destinationFunctionsModel.getFunction(selectedRow);
		}
		return null;
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		if (context.getComponentProvider() == this) {
			ListingCodeComparisonPanel dualListingPanel =
				functionComparisonPanel.getDualListingPanel();
			if (dualListingPanel != null) {
				ListingPanel leftPanel = dualListingPanel.getLeftPanel();
				return leftPanel.getHeaderActions(getName());
			}
		}
		return new ArrayList<>();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {

		Object source = (event != null) ? event.getSource() : null;
		Component sourceComponent = (source instanceof Component) ? (Component) source : null;
		Function sourceFunction = getSelectedSourceFunction();
		Function destinationFunction = getSelectedDestinationFunction();

		// If action is on the function associations table, return a function association context 
		// for the popup actions.
		if (dualTablePanel.isAncestorOf(sourceComponent)) {
			return new VTFunctionAssociationContext(tool, sourceFunction, destinationFunction,
				getExistingMatch(sourceFunction, destinationFunction));
		}

		boolean isToolbarButtonAction = (event == null); // Toolbar buttons pass a null event to this method.
		// Tool bar or function compare panel.
		if (isToolbarButtonAction || functionComparisonPanel.isAncestorOf(sourceComponent)) {

			ListingCodeComparisonPanel dualListingPanel =
				functionComparisonPanel.getDualListingPanel();
			boolean isShowingDualListing =
				(dualListingPanel != null) && dualListingPanel.isVisible();
			boolean sourceIsADualFieldPanel =
				isShowingDualListing && dualListingPanel.isAncestorOf(sourceComponent) &&
					(sourceComponent instanceof FieldPanel);

			ListingPanel listingPanel = null; // Default is don't create a function association listing context.
			// Is the action being taken on the dual listing?
			if (sourceIsADualFieldPanel) {
				listingPanel = dualListingPanel.getListingPanel((FieldPanel) sourceComponent);
			}
			// Is the action being taken on a toolbar button while the dual listing is visible?
			else if (isToolbarButtonAction && isShowingDualListing) {
				listingPanel = dualListingPanel.getFocusedListingPanel();
			}
			// If the dual listing is showing and this is a toolbar action or the action is 
			// on one of the listings in the ListingCodeComparisonPanel
			// then return a special function association listing context. This will allow
			// popup actions for the ListingDiff and also the function association actions 
			// for the functions selected in the tables.
			if (listingPanel != null) {
				VTListingNavigator vtListingNavigator =
					new VTListingNavigator(dualListingPanel, listingPanel);
				VTFunctionAssociationCompareContext vtListingContext =
					new VTFunctionAssociationCompareContext(this, vtListingNavigator, tool,
						sourceFunction, destinationFunction,
						getExistingMatch(sourceFunction, destinationFunction));
				vtListingContext.setCodeComparisonPanel(dualListingPanel);
				vtListingContext.setContextObject(dualListingPanel);
				vtListingContext.setSourceObject(source);
				return vtListingContext;
			}

			// Let function comparison panel try to get a generic action context.
			// This will get the listing header context or dual listing marker margin context.
			ActionContext actionContext = functionComparisonPanel.getActionContext(event, this);
			if (actionContext != null) {
				return actionContext;
			}
			// Comparison other than dual listing can return a function association context.
			return new VTFunctionAssociationContext(tool, sourceFunction, destinationFunction,
				getExistingMatch(sourceFunction, destinationFunction));
		}
		return null;
	}

	private VTMatch getExistingMatch(Function sourceFunction, Function destinationFunction) {
		if (sourceFunction == null || destinationFunction == null) {
			return null;
		}

		Address sourceAddress = sourceFunction.getEntryPoint();
		Address destinationAddress = destinationFunction.getEntryPoint();
		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			Collection<VTMatch> matches = matchSet.getMatches(sourceAddress, destinationAddress);
			for (VTMatch match : matches) {
				return match;
			}
		}
		return null;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void showFunctions() {
		tool.showComponentProvider(this, true);
		splitPane.setDividerLocation(0.5);
	}

	@Override
	public void disposed() {
		sourceThreadedTablePanel.dispose();
		destinationThreadedTablePanel.dispose();
		functionComparisonPanel.dispose();

		sourceFunctionsTable.dispose();
		sourceTableFilterPanel.dispose();
		destinationFunctionsTable.dispose();
		destinationTableFilterPanel.dispose();

		tool.removePopupActionProvider(this);
	}

	public void reload() {
		if (isVisible()) {
			doReloadFunctions();
			notifyContextChanged();
		}
	}

	private JComponent createWorkPanel() {

		dualTablePanel = new JPanel(new BorderLayout());

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createSourceFunctionPanel(),
			createDestinationFunctionPanel());
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(6);
		splitPane.setDividerLocation(0.5);
		dualTablePanel.add(splitPane, BorderLayout.CENTER);

		JPanel statusPanel = new JPanel(new BorderLayout());
		statusLabel = new GDLabel(NO_ERROR_MESSAGE);
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		statusLabel.setForeground(Color.RED.darker());
		statusLabel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateMatchStatusToolTip();
			}
		});
		statusPanel.add(statusLabel, BorderLayout.CENTER);
		dualTablePanel.add(statusPanel, BorderLayout.SOUTH);

		functionComparisonPanel =
			new FunctionComparisonPanel(this, tool, (Function) null, (Function) null);
		addSpecificCodeComparisonActions();
		functionComparisonPanel.setCurrentTabbedComponent(ListingCodeComparisonPanel.TITLE);
		functionComparisonPanel.setTitlePrefixes("Source:", "Destination:");

		comparisonSplitPane =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, dualTablePanel, functionComparisonPanel);
		comparisonSplitPane.setResizeWeight(0.4);

		JPanel functionsPanel = new JPanel(new BorderLayout());
		functionsPanel.add(comparisonSplitPane, BorderLayout.CENTER);
		return functionsPanel;
	}

	private void addSpecificCodeComparisonActions() {
		DockingAction[] actions = functionComparisonPanel.getCodeComparisonActions();
		for (DockingAction dockingAction : actions) {
			addLocalAction(dockingAction);
		}
	}

	private void addGeneralCodeComparisonActions() {
		// Action for showing/hiding the dual code compare views.
		toggleListingVisibility = new ToggleDualListingVisibilityAction();
		addLocalAction(toggleListingVisibility);
	}

	/**
	 * Displays or hides the function comparison panel within the function association provider.
	 * @param show true indicates to show the function comparison within the provider. 
	 * Otherwise, hide it.
	 */
	private void showComparisonPanelWithinProvider(boolean show) {
		boolean contains = mainPanel.isAncestorOf(comparisonSplitPane);
		if (show) {
			if (!contains) {
				// Remove the src/dest functions table panel.
				mainPanel.remove(dualTablePanel);

				// Show the split pane with the dual table and the code compare.
				comparisonSplitPane.add(dualTablePanel);
				comparisonSplitPane.add(functionComparisonPanel);
				mainPanel.add(comparisonSplitPane, BorderLayout.CENTER);

				mainPanel.validate();
				functionComparisonPanel.loadFunctions(getSelectedSourceFunction(),
					getSelectedDestinationFunction());

				// Since we pull stuff out and put it back, we lose the focus, so set it back to the table.
				dualTablePanel.requestFocus();
			}
		}
		else {
			if (contains) {
				// Remove the split pane.
				mainPanel.remove(comparisonSplitPane);
				comparisonSplitPane.remove(functionComparisonPanel);
				comparisonSplitPane.remove(dualTablePanel);

				// Show only the src/dest functions table panel.
				mainPanel.add(dualTablePanel, BorderLayout.CENTER);

				mainPanel.validate();
				// Since we pull stuff out and put it back, we lose the focus, so set it back to the table.
				dualTablePanel.requestFocus();
			}
		}
		toggleListingVisibility.setSelected(show);
		functionComparisonPanel.updateActionEnablement();
	}

	private JComponent createSourceFunctionPanel() {

		GoToService goToService = tool.getService(GoToService.class);

		Program sourceProgram = controller.getSourceProgram();
		sourceFunctionsModel =
			new VTFunctionAssociationTableModel(tool, controller, sourceProgram, true);
		sourceThreadedTablePanel = new GhidraThreadedTablePanel<>(sourceFunctionsModel, 1000);
		sourceFunctionsTable = sourceThreadedTablePanel.getTable();
		sourceFunctionsTable.setName("SourceFunctionTable");
		sourceFunctionsTable.setPreferenceKey(
			"VTFunctionAssociationTableModel - Source Function Table");
		if (goToService != null) {
			sourceFunctionsTable.installNavigation(goToService,
				goToService.getDefaultNavigatable());
		}
		sourceFunctionsTable.setAutoLookupColumn(VTFunctionAssociationTableModel.NAME_COL);
		sourceFunctionsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		sourceFunctionsTable.setPreferredScrollableViewportSize(new Dimension(350, 150));
		sourceFunctionsTable.setRowSelectionAllowed(true);
		sourceFunctionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		sourceFunctionsTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			goToSelectedSourceFunction();
			validateSelectedMatch();
			notifyContextChanged();
			functionComparisonPanel.loadFunctions(getSelectedSourceFunction(),
				getSelectedDestinationFunction());
		});

		sourceFunctionsModel.addTableModelListener(new TitleUpdateListener());

		sourceFunctionsTable.getColumnModel()
				.getColumn(
					VTFunctionAssociationTableModel.ADDRESS_COL)
				.setPreferredWidth(
					VTFunctionAssociationTableModel.ADDRESS_COL_WIDTH);

		sourceTableFilterPanel =
			new GhidraTableFilterPanel<>(sourceFunctionsTable, sourceFunctionsModel);

		JPanel sourceFunctionPanel = new JPanel(new BorderLayout());
		String sourceString =
			(sourceProgram != null) ? sourceProgram.getDomainFile().toString() : NO_SESSION;
		String sourceTitle = SOURCE_TITLE + " = " + sourceString;
		sourceSessionLabel = new GDLabel(sourceTitle);
		sourceSessionLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
		sourceFunctionPanel.add(sourceSessionLabel, BorderLayout.NORTH);
		sourceFunctionPanel.add(sourceThreadedTablePanel, BorderLayout.CENTER);
		sourceFunctionPanel.add(sourceTableFilterPanel, BorderLayout.SOUTH);
		return sourceFunctionPanel;
	}

	private JComponent createDestinationFunctionPanel() {

		GoToService goToService = tool.getService(GoToService.class);

		Program destinationProgram = controller.getDestinationProgram();
		destinationFunctionsModel =
			new VTFunctionAssociationTableModel(tool, controller, destinationProgram, false);
		destinationThreadedTablePanel =
			new GhidraThreadedTablePanel<>(destinationFunctionsModel, 1000);
		destinationFunctionsTable = destinationThreadedTablePanel.getTable();
		destinationFunctionsTable.setName("DestinationFunctionTable");
		destinationFunctionsTable.setPreferenceKey(
			"VTFunctionAssociationTableModel - " + "Destination Function Table");
		if (goToService != null) {
			destinationFunctionsTable.installNavigation(goToService,
				goToService.getDefaultNavigatable());
		}
		destinationFunctionsTable.setAutoLookupColumn(VTFunctionAssociationTableModel.NAME_COL);
		destinationFunctionsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		destinationFunctionsTable.setPreferredScrollableViewportSize(new Dimension(350, 150));
		destinationFunctionsTable.setRowSelectionAllowed(true);
		destinationFunctionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		destinationFunctionsTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			goToSelectedDestinationFunction();
			validateSelectedMatch();
			notifyContextChanged();
			functionComparisonPanel.loadFunctions(getSelectedSourceFunction(),
				getSelectedDestinationFunction());
		});

		destinationFunctionsModel.addTableModelListener(new TitleUpdateListener());

		JTableHeader functionHeader = destinationFunctionsTable.getTableHeader();
		functionHeader.setUpdateTableInRealTime(true);

		destinationFunctionsTable.getColumnModel()
				.getColumn(
					VTFunctionAssociationTableModel.ADDRESS_COL)
				.setPreferredWidth(
					VTFunctionAssociationTableModel.ADDRESS_COL_WIDTH);

		destinationTableFilterPanel =
			new GhidraTableFilterPanel<>(destinationFunctionsTable, destinationFunctionsModel);

		JPanel destinationFunctionPanel = new JPanel(new BorderLayout());
		String destinationString =
			(destinationProgram != null) ? destinationProgram.getDomainFile().toString()
					: NO_SESSION;
		String destinationTitle = DESTINATION_TITLE + " = " + destinationString;
		destinationSessionLabel = new GDLabel(destinationTitle);
		destinationSessionLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
		destinationFunctionPanel.add(destinationSessionLabel, BorderLayout.NORTH);
		destinationFunctionPanel.add(destinationThreadedTablePanel, BorderLayout.CENTER);
		destinationFunctionPanel.add(destinationTableFilterPanel, BorderLayout.SOUTH);
		return destinationFunctionPanel;
	}

	protected void goToSelectedSourceFunction() {
		Function sourceFunction = getSelectedSourceFunction();
		if (sourceFunction != null) {
			controller.gotoSourceLocation(
				new ProgramLocation(sourceFunction.getProgram(), sourceFunction.getEntryPoint()));
		}
	}

	protected void goToSelectedDestinationFunction() {
		Function destinationFunction = getSelectedDestinationFunction();
		if (destinationFunction != null) {
			controller.gotoDestinationLocation(new ProgramLocation(destinationFunction.getProgram(),
				destinationFunction.getEntryPoint()));
		}
	}

	public void addSelectionListener(VTFunctionAssociationListener listener) {
		functionAssociationListeners.add(listener);
	}

	private void validateSelectedMatch() {
		int selectedSourceCount = sourceFunctionsTable.getSelectedRowCount();
		int selectedDestinationCount = destinationFunctionsTable.getSelectedRowCount();
		if (selectedSourceCount == 0 || selectedDestinationCount == 0) {
			String message = "Select a single source function and a single destination function.";
			setMatchStatus(message);
			return;
		}
		if (selectedSourceCount > 1 || selectedDestinationCount > 1) {
			String message =
				"Select no more than a single source function and a single destination function.";
			setMatchStatus(message);
			return;
		}

		Function sourceFunction = getSelectedSourceFunction();
		Function destinationFunction = getSelectedDestinationFunction();
		if (sourceFunction == null || destinationFunction == null) {
			String message = "Select a single source function and a single destination function.";
			setMatchStatus(message);
			return;
		}

		// Check to see if this match already exists
		VTMatch match = getExistingMatch(sourceFunction, destinationFunction);
		if (match != null) {
			String message = "A match already exists between " + sourceFunction.getName() +
				" and " + destinationFunction.getName() + ".";
			setMatchStatus(message);
			return;
		}
		setMatchStatus(NO_ERROR_MESSAGE);
	}

	private void setMatchStatus(String statusMessage) {
		if (SystemUtilities.isEqual(matchStatus, statusMessage)) {
			return;
		}
		matchStatus = statusMessage;
		statusLabel.setText(matchStatus);
		updateMatchStatusToolTip();
	}

	/**
	 * If the status text doesn't fit in the dialog, set a tool tip
	 * for the status label so the user can see what it says.
	 * If the status message fits then there is no tool tip.
	 */
	private void updateMatchStatusToolTip() {
		String text = statusLabel.getText();
		// Get the width of the message.
		FontMetrics fm = statusLabel.getFontMetrics(statusLabel.getFont());
		int messageWidth = 0;
		if ((fm != null) && (text != null)) {
			messageWidth = fm.stringWidth(text);
		}
		if (messageWidth > statusLabel.getWidth()) {
			statusLabel.setToolTipText(text);
		}
		else {
			statusLabel.setToolTipText(null);
		}
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		// Do nothing.
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		// Do nothing.
	}

	@Override
	public void optionsChanged(Options options) {
		// This doesn't currently rely on VT options at all.
	}

	@Override
	public void sessionChanged(VTSession session) {
		if (!isVisible()) {
			// Don't respond at all since not visible.
			// Instead reload when component is shown.
			return;
		}

		reloadFromSession();
	}

	private void reloadFromSession() {
		Program destinationProgram = controller.getDestinationProgram();
		destinationFunctionsModel.setProgram(destinationProgram);
		String destinationString =
			(destinationProgram != null) ? destinationProgram.getDomainFile().toString()
					: NO_SESSION;
		String destinationTitle = DESTINATION_TITLE + " = " + destinationString;
		destinationSessionLabel.setText(destinationTitle);

		Program sourceProgram = controller.getSourceProgram();
		sourceFunctionsModel.setProgram(sourceProgram);
		String sourceString =
			(sourceProgram != null) ? sourceProgram.getDomainFile().toString() : NO_SESSION;
		String sourceTitle = SOURCE_TITLE + " = " + sourceString;
		sourceSessionLabel.setText(sourceTitle);

		reload();
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			// Don't respond at all since not visible.
			// Instead reload when component is shown.
			return;
		}

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			reload();
			return;
		}

		boolean contextChanged = false;
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			int eventType = doRecord.getEventType();
			if (eventType == DOCR_VT_MATCH_ADDED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				VTMatch match = (VTMatch) vtRecord.getNewValue();
				sourceFunctionsModel.matchAdded(match);
				destinationFunctionsModel.matchAdded(match);
				contextChanged = true;
			}
			else if (eventType == DOCR_VT_MATCH_DELETED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				DeletedMatch deletedMatch = (DeletedMatch) vtRecord.getOldValue();
				sourceFunctionsModel.matchRemoved(deletedMatch);
				destinationFunctionsModel.matchRemoved(deletedMatch);
				contextChanged = true;
			}
			else if (eventType == DOCR_VT_ASSOCIATION_STATUS_CHANGED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				VTAssociation association = (VTAssociation) vtRecord.getObject();
				sourceFunctionsModel.associationChanged(association);
				destinationFunctionsModel.associationChanged(association);
				contextChanged = true;
			}
			else if (eventType == ChangeManager.DOCR_FUNCTION_ADDED) {
				functionAdded((ProgramChangeRecord) doRecord);
				contextChanged = true;
			}
			else if (eventType == ChangeManager.DOCR_FUNCTION_REMOVED) {
				functionRemoved((ProgramChangeRecord) doRecord);
				contextChanged = true;
			}
		}

		if (contextChanged) {
			// Update the context so that toolbar actions fix their enablement.
			notifyContextChanged();
		}
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	private void functionAdded(ProgramChangeRecord record) {
		Function function = (Function) record.getObject();
		Program program = function.getProgram();
		if (program == controller.getSourceProgram()) {
			sourceFunctionsModel.functionAdded(function);
		}
		else {
			destinationFunctionsModel.functionAdded(function);
		}
	}

	private void functionRemoved(ProgramChangeRecord record) {
		Function function = (Function) record.getObject();
		Program program = function.getProgram();
		if (program == controller.getSourceProgram()) {
			sourceFunctionsModel.functionRemoved(function);
		}
		else {
			destinationFunctionsModel.functionRemoved(function);
		}
	}

	public void readConfigState(SaveState saveState) {
		filterSettings = saveState.getEnum(FILTER_SETTINGS_KEY, SHOW_ALL);
		sourceFunctionsModel.setFilterSettings(filterSettings);
		destinationFunctionsModel.setFilterSettings(filterSettings);
		reload();
		functionComparisonPanel.readConfigState(getName(), saveState);
	}

	public void writeConfigState(SaveState saveState) {
		// save config state here
		functionComparisonPanel.writeConfigState(getName(), saveState);
		saveState.putEnum(FILTER_SETTINGS_KEY, filterSettings);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class TitleUpdateListener implements TableModelListener {
		@Override
		public void tableChanged(TableModelEvent e) {

			StringBuffer buffy = new StringBuffer();
			String sessionName = controller.getVersionTrackingSessionName();
			buffy.append("[Session: ").append(sessionName).append("] - ");
			getTableFilterString("Source Functions", sourceFunctionsModel, buffy);
			buffy.append(" / ");
			getTableFilterString("Destination Functions", destinationFunctionsModel, buffy);
			setSubTitle(buffy.toString());
		}

		private void getTableFilterString(String tableName, ThreadedTableModel<?, ?> model,
				StringBuffer buffy) {
			int filteredCount = model.getRowCount();
			int unfilteredCount = model.getUnfilteredRowCount();

			buffy.append(tableName).append(" - ").append(filteredCount).append(" functions");
			if (filteredCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(')');
			}
		}
	}

	private class ToggleDualListingVisibilityAction extends ToggleDockingAction {
		ToggleDualListingVisibilityAction() {
			super("Toggle Dual Listing Visibility", VTFunctionAssociationProvider.this.getName());
			setDescription("Toggle Visibility of Dual Comparison Views");
			setSelected(true);
			setEnabled(true);
			setToolBarData(new ToolBarData(SHOW_LISTINGS_ICON, SHOW_COMPARE_ACTION_GROUP));

			HelpLocation helpLocation = new HelpLocation("VersionTrackingPlugin",
				"Function_Association_Show_Hide_Function_Compare");
			setHelpLocation(helpLocation);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			boolean show = !functionComparisonPanel.isShowing();
			showComparisonPanelWithinProvider(show);
		}
	}
}
