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
package ghidra.feature.vt.gui.provider.markuptable;

import static ghidra.feature.vt.gui.plugin.VTPlugin.FILTERED_ICON;
import static ghidra.feature.vt.gui.plugin.VTPlugin.UNFILTERED_ICON;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.*;

import docking.*;
import docking.action.*;
import docking.actions.PopupActionProvider;
import docking.help.HelpService;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonPanel;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.duallisting.*;
import ghidra.feature.vt.gui.editors.AddressInputDialog;
import ghidra.feature.vt.gui.filters.*;
import ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.markuptable.VTMarkupItemsTableModel.AppliedDestinationAddressTableColumn;
import ghidra.feature.vt.gui.util.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.ResourceManager;

/**
 * This provides the GUI for displaying and working with version tracking markup items.
 */
public class VTMarkupItemsTableProvider extends ComponentProviderAdapter
		implements FilterDialogModel<VTMarkupItem>, VTControllerListener, PopupActionProvider {

	private static final String SHOW_COMPARISON_PANEL = "SHOW_COMPARISON_PANEL";

	private static final Icon SHOW_LISTINGS_ICON =
		ResourceManager.loadImage("images/application_tile_horizontal.png");

	private static final Icon FILTER_ICON = ResourceManager.loadImage("images/view-filter.png");
	private static final String SHOW_COMPARE_ACTION_GROUP = "A9_ShowCompare"; // "A9_" forces to right of other dual view actions in toolbar.

	private final VTController controller;

	private JComponent component;

	private JPanel markupPanel;
	private JSplitPane splitPane;
	private JPanel markupItemsTablePanel;
	private MarkupItemThreadedTablePanel tablePanel;
	private FunctionComparisonPanel functionComparisonPanel;

	private GhidraTable markupItemsTable;
	private VTMarkupItemsTableModel markupItemsTableModel;
	private ListSelectionListener markupItemSelectionListener;

	private AncillaryFilterDialogComponentProvider<VTMarkupItem> ancillaryFilterDialog;
	private JButton ancillaryFilterButton;

	private FilterIconFlashTimer<VTMarkupItem> iconTimer;
	private Set<Filter<VTMarkupItem>> filters = new HashSet<>();
	private FilterStatusListener refilterListener = new RefilterListener();
	private boolean filteringFrozen;

	private ToggleDualListingVisibilityAction toggleListingVisibility;
	private boolean processingSourceLocationChange = false;
	private boolean processingDestinationLocationChange = false;
	private boolean processingMarkupItemSelected = false;

	private VTDualListingHighlightProvider sourceHighlightProvider;
	private VTDualListingHighlightProvider destinationHighlightProvider;

	/**
	 * Creates a new markup items table provider for displaying markup items, and code comparison
	 * views such as a dual listing for the currently selected version tracking match.
	 * @param controller the version tracking controller for this provider
	 */
	public VTMarkupItemsTableProvider(VTController controller) {
		super(controller.getTool(), "Version Tracking Markup Items", VTPlugin.OWNER);
		this.controller = controller;
		controller.addListener(this);
		setWindowGroup(VTPlugin.WINDOW_GROUP);
		setIcon(ResourceManager.loadImage("images/application_view_detail.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIntraGroupPosition(WindowPosition.STACK);

		component = createComponent();

		createActions();
		addGeneralCodeComparisonActions();
		addToTool();

		ancillaryFilterDialog = new MarkupItemFilterDialogComponentProvider(controller, this);
		iconTimer = new FilterIconFlashTimer<>(UNFILTERED_ICON, FILTERED_ICON,
			ancillaryFilterDialog, ancillaryFilterButton);

		tool.addPopupActionProvider(this);

		HelpLocation helpLocation = new HelpLocation("VersionTrackingPlugin", "Markup Items Table");
		setHelpLocation(helpLocation);

		setVisible(true);
	}

	private JComponent createComponent() {

		markupPanel = new JPanel(new BorderLayout());
		markupItemsTable = createMarkupItemTable();
		markupItemsTablePanel = new JPanel(new BorderLayout());

		JPanel filterAreaPanel = createFilterArea();
		markupItemsTablePanel.add(tablePanel, BorderLayout.CENTER);
		markupItemsTablePanel.add(filterAreaPanel, BorderLayout.SOUTH);

		functionComparisonPanel =
			new FunctionComparisonPanel(this, tool, (Function) null, (Function) null);
		addSpecificCodeComparisonActions();
		functionComparisonPanel.setCurrentTabbedComponent(ListingCodeComparisonPanel.TITLE);
		functionComparisonPanel.setTitlePrefixes("Source:", "Destination:");
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		if (dualListingPanel != null) {
			dualListingPanel.setLeftProgramLocationListener(new SourceProgramLocationListener());
			dualListingPanel.setRightProgramLocationListener(
				new DestinationProgramLocationListener());

			sourceHighlightProvider = new VTDualListingHighlightProvider(controller, true);
			destinationHighlightProvider = new VTDualListingHighlightProvider(controller, false);
			dualListingPanel.addHighlightProviders(sourceHighlightProvider,
				destinationHighlightProvider);
			sourceHighlightProvider.setListingPanel(dualListingPanel.getLeftPanel());
			destinationHighlightProvider.setListingPanel(dualListingPanel.getRightPanel());

			new VTDualListingDragNDropHandler(controller, dualListingPanel);
		}

		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, markupItemsTablePanel,
			functionComparisonPanel);
		splitPane.setResizeWeight(0.4);
		markupPanel.add(splitPane, BorderLayout.CENTER);
		return markupPanel;
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

	class ToggleDualListingVisibilityAction extends ToggleDockingAction {
		ToggleDualListingVisibilityAction() {
			super("Toggle Dual Listing Visibility", VTMarkupItemsTableProvider.this.getName());
			setDescription("Toggle Visibility of Dual Comparison Views");
			setSelected(true);
			setEnabled(true);
			setToolBarData(new ToolBarData(SHOW_LISTINGS_ICON, SHOW_COMPARE_ACTION_GROUP));

			HelpLocation helpLocation =
				new HelpLocation("VersionTrackingPlugin", "Toggle Dual Listing Visibility");
			setHelpLocation(helpLocation);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			boolean show = !functionComparisonPanel.isShowing();
			showComparisonPanelWithinProvider(show);
		}
	}

	private GhidraTable createMarkupItemTable() {
		tablePanel = new MarkupItemThreadedTablePanel(createTableModel());
		final GhidraTable table = tablePanel.getTable();
		table.setActionsEnabled(true);

		table.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				iconTimer.restart();
			}
		});

		markupItemSelectionListener = new ListSelectionListener() {
			@Override
			@SuppressWarnings("unchecked")
			// it's our model, it must be our type
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}

				try {
					// Need the following flag to prevent selection changing when selecting 
					// in the markup table, if another of the same markup type exists with 
					// the same destination address.
					processingMarkupItemSelected = true;

					ListingCodeComparisonPanel dualListingPanel =
						functionComparisonPanel.getDualListingPanel();
					VTMarkupItem markupItem = null;
					if (table.getSelectedRowCount() == 1) {
						// we get out the model here in case it has been wrapped by one of the filters
						RowObjectTableModel<VTMarkupItem> model =
							(RowObjectTableModel<VTMarkupItem>) table.getModel();
						int selectedRow = table.getSelectedRow();
						markupItem = model.getRowObject(selectedRow);
					}
					else {
						// No markup item selected or multiple selected.
						if (dualListingPanel != null) {
							dualListingPanel.updateListings(); // refresh the dual listing's background markup colors.
						}
						controller.setSelectedMarkupItem(null); // Refresh the subTools markup backgrounds and location.
						return;
					}

					notifyContextChanged();

					if (dualListingPanel != null) {
						// Don't set source or destination if the location change was initiated by the dual listing.
						if (!processingSourceLocationChange &&
							!processingDestinationLocationChange) {
							dualListingPanel.setLeftLocation(dualListingPanel.getLeftProgram(),
								markupItem.getSourceLocation());
							dualListingPanel.setRightLocation(dualListingPanel.getRightProgram(),
								markupItem.getDestinationLocation());
						}
						else {
							// Only adjust the side of the dual listing panel that didn't initiate this.
							ProgramLocation sourceLocation = markupItem.getSourceLocation();
							if (processingDestinationLocationChange && sourceLocation != null) {
								dualListingPanel.setLeftLocation(dualListingPanel.getLeftProgram(),
									sourceLocation);
							}

							ProgramLocation destinationLocation =
								markupItem.getDestinationLocation();
							if (processingSourceLocationChange && destinationLocation != null) {
								dualListingPanel.setRightLocation(
									dualListingPanel.getRightProgram(), destinationLocation);
							}
						}
						dualListingPanel.updateListings(); // refresh the dual listing's background markup colors.
					}
					controller.setSelectedMarkupItem(markupItem); // Refresh the subTools markup backgrounds and location.
				}
				finally {
					processingMarkupItemSelected = false;
				}
			}
		};
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(markupItemSelectionListener);

		TableColumnModel columnModel = table.getColumnModel();

		int columnIndex =
			markupItemsTableModel.getColumnIndex(AppliedDestinationAddressTableColumn.class);
		TableColumn column = columnModel.getColumn(columnIndex);
		column.setCellEditor(new AddressInputDialog(controller));

		// override the default behavior so we see our columns in their preferred size
		Dimension size = table.getPreferredScrollableViewportSize();
		Dimension preferredSize = table.getPreferredSize();

		// ...account for the scroll bar width
		JScrollBar scrollBar = new JScrollBar(Adjustable.VERTICAL);
		Dimension scrollBarSize = scrollBar.getMinimumSize();
		size.width = preferredSize.width + scrollBarSize.width;
		table.setPreferredScrollableViewportSize(size);

		return table;
	}

	private VTMarkupItemsTableModel createTableModel() {
		markupItemsTableModel = new VTMarkupItemsTableModel(controller);
		markupItemsTableModel.addTableModelListener(e -> {
			int filteredCount = markupItemsTableModel.getRowCount();
			int unfilteredCount = markupItemsTableModel.getUnfilteredRowCount();

			String sessionName = controller.getVersionTrackingSessionName();
			StringBuffer buffy = new StringBuffer();
			buffy.append("[Session: ").append(sessionName).append("] ");
			buffy.append('-').append(markupItemsTableModel.getRowCount()).append(" markup items");
			if (filteredCount != unfilteredCount) {
				buffy.append(" (of ").append(markupItemsTableModel.getUnfilteredRowCount()).append(
					')');
			}

			setSubTitle(buffy.toString());

			updateFilterDisplay();
		});

		return markupItemsTableModel;
	}

	/**
	 * Displays or hides the function comparison panel within the markup items provider.
	 * @param show true indicates to show the function comparison within the provider. 
	 * Otherwise, hide it.
	 */
	private void showComparisonPanelWithinProvider(boolean show) {
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		boolean contains = markupPanel.isAncestorOf(splitPane);
		if (show) {
			if (!contains) {
				// Remove the markupItems panel.
				markupPanel.remove(markupItemsTablePanel);

				// Show the split pane.
				splitPane.add(markupItemsTablePanel);
				splitPane.add(functionComparisonPanel);
				markupPanel.add(splitPane, BorderLayout.CENTER);
				if (dualListingPanel != null) {
					dualListingPanel.setLeftProgramLocationListener(
						new SourceProgramLocationListener());
					dualListingPanel.setRightProgramLocationListener(
						new DestinationProgramLocationListener());
				}

				markupPanel.validate();
				load(controller.getMatchInfo());

				// Since we pull stuff out and put it back, we lose the focus, so set it back to the table.
				markupItemsTable.requestFocus();
			}
		}
		else {
			if (contains) {
				// Remove the split pane.
				if (dualListingPanel != null) {
					dualListingPanel.setLeftProgramLocationListener(null);
					dualListingPanel.setRightProgramLocationListener(null);
				}
				markupPanel.remove(splitPane);
				splitPane.remove(functionComparisonPanel);
				splitPane.remove(markupItemsTablePanel);

				// Show only the markupItems panel.
				markupPanel.add(markupItemsTablePanel, BorderLayout.CENTER);

				markupPanel.validate();
				// Since we pull stuff out and put it back, we lose the focus, so set it back to the table.
				markupItemsTable.requestFocus();
			}
		}
		toggleListingVisibility.setSelected(show);
		functionComparisonPanel.updateActionEnablement();
	}

	private JPanel createFilterArea() {
		JPanel parentPanel = new JPanel(new BorderLayout());

		JComponent nameFilterPanel = createTextFilterPanel();
		parentPanel.add(nameFilterPanel, BorderLayout.CENTER);

		ancillaryFilterButton = new JButton(FILTER_ICON);
		ancillaryFilterButton.addActionListener(
			e -> tool.showDialog(ancillaryFilterDialog, component));
		ancillaryFilterButton.setToolTipText("Filters Dialog");

		parentPanel.add(ancillaryFilterButton, BorderLayout.EAST);

		HelpLocation filterHelpLocation =
			new HelpLocation("VersionTrackingPlugin", "Markup_Filters");
		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(parentPanel, filterHelpLocation);
		helpService.registerHelp(ancillaryFilterButton, filterHelpLocation);

		return parentPanel;
	}

	private JComponent createTextFilterPanel() {
//		MarkupItemValueTextFilter nameFilterPanel =
//			new MarkupItemValueTextFilter(controller, markupItemsTable);
		AllTextFilter<VTMarkupItem> allTextFilter =
			new AllTextFilter<>(controller, markupItemsTable, markupItemsTableModel);
		addFilter(allTextFilter);
		return allTextFilter.getComponent();
	}

	private void refilter() {
		if (filteringFrozen) {
			return;
		}

		forceRefilter();
	}

	private void createActions() {
		addLocalAction(new ApplyUsingOptionsAndForcingMarkupItemAction(controller, true));
		addLocalAction(new ApplyAndAddMarkupItemAction(controller, false));
		addLocalAction(new ApplyAndAddAsPrimaryMarkupItemAction(controller, false));
		addLocalAction(new ApplyAndReplaceMarkupItemAction(controller, false));
		addLocalAction(new ReplaceDefaultMarkupItemAction(controller, false));
		addLocalAction(new ReplaceFirstMarkupItemAction(controller, false));
		addLocalAction(new DontKnowMarkupItemAction(controller, false));
		addLocalAction(new DontCareMarkupItemAction(controller, false));
		addLocalAction(new RejectMarkupItemAction(controller, true));
		addLocalAction(new ResetMarkupItemAction(controller, true));
		addLocalAction(new EditMarkupAddressAction(controller, false));
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		if (context.getComponentProvider() == this && dualListingPanel != null) {
			ListingPanel sourcePanel = dualListingPanel.getLeftPanel();
			return sourcePanel.getHeaderActions(getName());
		}
		return new ArrayList<>();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Object source = (event != null) ? event.getSource() : null;
		Component sourceComponent = (source instanceof Component) ? (Component) source : null;
		// If action is on the markup table, return a markup item context for markup popup actions.
		if (event == null || tablePanel.isAncestorOf(sourceComponent)) {
			List<VTMarkupItem> selectedItems = getSelectedMarkupItems();
			VTMarkupItemContext vtMarkupItemContext = new VTMarkupItemContext(this, selectedItems);
			if (functionComparisonPanel.isVisible()) {
				CodeComparisonPanel<? extends FieldPanelCoordinator> displayedPanel =
					functionComparisonPanel.getDisplayedPanel();
				vtMarkupItemContext.setCodeComparisonPanel(displayedPanel);
			}
			return vtMarkupItemContext;
		}
		// Is the action being taken on the dual listing.
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		if (dualListingPanel != null && dualListingPanel.isAncestorOf(sourceComponent)) {
			// If the action is on one of the listings in the ListingCodeComparisonPanel
			// then return a special version tracking listing context. This will allow
			// popup actions for the ListingDiff and also the markup item actions for the
			// current markup item.
			if (sourceComponent instanceof FieldPanel) {
				ListingPanel listingPanel =
					dualListingPanel.getListingPanel((FieldPanel) sourceComponent);
				if (listingPanel != null) {
					VTListingNavigator vtListingNavigator =
						new VTListingNavigator(dualListingPanel, listingPanel);
					VTListingContext vtListingContext =
						new VTListingContext(this, vtListingNavigator);
					vtListingContext.setCodeComparisonPanel(dualListingPanel);
					vtListingContext.setContextObject(dualListingPanel);
					vtListingContext.setSourceObject(source);
					return vtListingContext;
				}
			}
		}
		// Let function comparison panel try to get a generic action context.
		// This will get the listing header and dual listing marker margins.
		return functionComparisonPanel.getActionContext(event, this);
	}

	List<VTMarkupItem> getSelectedMarkupItems() {
		List<VTMarkupItem> list = new ArrayList<>();
		int[] selectedRows = markupItemsTable.getSelectedRows();
		for (int row : selectedRows) {
			VTMarkupItem markupItem = markupItemsTableModel.getRowObject(row);
			list.add(markupItem);
		}
		return list;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void disposed() {
		if (markupItemsTable == null) {
			return;
		}

		// must remove the listener first to avoid callback whilst we are disposing
		ListSelectionModel selectionModel = markupItemsTable.getSelectionModel();
		selectionModel.removeListSelectionListener(markupItemSelectionListener);

		markupItemsTableModel.dispose();

		for (Filter<VTMarkupItem> filter : filters) {
			filter.dispose();
		}

		tool.removePopupActionProvider(this);
	}

	VTController getController() {
		return controller;
	}

	private void refresh() {
		markupItemsTableModel.reload(false);
		markupItemsTable.repaint();
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		if (dualListingPanel != null) {
			dualListingPanel.updateListings();
		}
		sourceHighlightProvider.updateMarkup();
		destinationHighlightProvider.updateMarkup();
	}

	@Override
	public void componentHidden() {
		functionComparisonPanel.clear();
	}

	@Override
	public void componentShown() {
		sessionChanged(controller.getSession());
	}

	/**
	 * Causes the information for the currently selected match to be reloaded.
	 */
	public void reload() {
		if (!isVisible()) {
			return;
		}
		load(controller.getMatchInfo());

//        forceTableToRepaintEmptyWhileLoading();
	}

	/**
	 * Loads the markup items table and its function comparison panel with the indicated match.
	 * @param matchInfo indicates which match (if any) to load.
	 */
	public void load(MatchInfo matchInfo) {
		if (!isVisible()) {
			return;
		}
		markupItemsTable.clearSelection();
		markupItemsTableModel.reload();
		// Is the functionComparisonPanel showing?
		if (splitPane.isAncestorOf(functionComparisonPanel)) {
			loadComparisonPanel(matchInfo);
		}

//        forceTableToRepaintEmptyWhileLoading();
	}

	private void loadComparisonPanel(MatchInfo matchInfo) {
		if (matchInfo != null) {
			VTAssociationType type = matchInfo.getMatch().getAssociation().getType();
			if (type == VTAssociationType.DATA) {
				Data sourceData = matchInfo.getSourceData();
				Data destinationData = matchInfo.getDestinationData();
				if (sourceData != null && destinationData != null) {
					functionComparisonPanel.loadData(sourceData, destinationData);
				}
				else {
					loadAddresses(matchInfo);
				}
			}
			else {
				Function sourceFunction = matchInfo.getSourceFunction();
				Function destinationFunction = matchInfo.getDestinationFunction();
				if (sourceFunction != null && destinationFunction != null) {
					functionComparisonPanel.loadFunctions(sourceFunction, destinationFunction);
				}
				else {
					loadAddresses(matchInfo);
				}
			}
		}
		else {
			functionComparisonPanel.loadFunctions(null, null);
		}

		if (sourceHighlightProvider != null) {
			sourceHighlightProvider.updateMarkup();
		}
		if (destinationHighlightProvider != null) {
			destinationHighlightProvider.updateMarkup();
		}
		functionComparisonPanel.validate();
	}

	private void loadAddresses(MatchInfo matchInfo) {
		VTMatch match = matchInfo.getMatch();
		VTAssociation association = match.getAssociation();
		Address sourceAddress = association.getSourceAddress();
		Address destinationAddress = association.getDestinationAddress();
		int sourceLength = match.getSourceLength();
		int destinationLength = match.getDestinationLength();

		// We need to possibly adjust the source and destination start addresses to the beginning 
		// of the code units containing them or we won't display anything in the comparison panel.
		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Program destinationProgram = session.getDestinationProgram();
		Listing sourceListing = sourceProgram.getListing();
		Listing destinationListing = destinationProgram.getListing();
		CodeUnit sourceCodeUnit = sourceListing.getCodeUnitContaining(sourceAddress);
		CodeUnit destinationCodeUnit = destinationListing.getCodeUnitContaining(destinationAddress);
		Address sourceStart =
			(sourceCodeUnit != null) ? sourceCodeUnit.getMinAddress() : sourceAddress;
		Address destinationStart =
			(destinationCodeUnit != null) ? destinationCodeUnit.getMinAddress()
					: destinationAddress;

		Address sourceEnd = (sourceLength > 1) ? sourceAddress.add(sourceLength - 1) : sourceStart;
		Address destinationEnd =
			(destinationLength > 1) ? destinationAddress.add(destinationLength - 1)
					: destinationStart;
		AddressSetView sourceAddressSet = new AddressSet(sourceStart, sourceEnd);
		AddressSetView destinationAddressSet = new AddressSet(destinationStart, destinationEnd);
		functionComparisonPanel.loadAddresses(sourceProgram, destinationProgram, sourceAddressSet,
			destinationAddressSet);
	}

	public void processSourceLocationChange(ProgramLocation programLocation) {
		if (processingSourceLocationChange) {
			return;
		}
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return;
		}
		AddressSetView sourceAddressSet = matchInfo.getSourceAddressSet();
		Address address = programLocation.getAddress();
		if ((sourceAddressSet != null) && (sourceAddressSet.contains(address))) {
			try {
				processingSourceLocationChange = true;

				Program sourceProgram = controller.getSourceProgram();
				VTMarkupType markupType =
					MatchInfo.getMarkupTypeForLocation(programLocation, sourceProgram);
				if (markupType == null) {
					return;
				}
				Address markupAddress =
					MatchInfo.getMarkupAddressForLocation(programLocation, sourceProgram);
				selectMarkupItem(markupAddress, true, markupType); // using a source address

			}
			finally {
				processingSourceLocationChange = false;
			}
		}
	}

	public void processDestinationLocationChange(ProgramLocation programLocation) {
		if (processingDestinationLocationChange) {
			return;
		}
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return;
		}
		AddressSetView destinationAddressSet = matchInfo.getDestinationAddressSet();
		Address address = programLocation.getAddress();
		if ((destinationAddressSet != null) && (destinationAddressSet.contains(address))) {
			try {
				processingDestinationLocationChange = true;

				Program destinationProgram = controller.getDestinationProgram();
				VTMarkupType markupType = MatchInfo.getMarkupTypeForLocation(programLocation,
					controller.getDestinationProgram());
				if (markupType == null) {
					return;
				}
				Address markupAddress =
					MatchInfo.getMarkupAddressForLocation(programLocation, destinationProgram);
				selectMarkupItem(markupAddress, false, markupType); // using a destination address

			}
			finally {
				processingDestinationLocationChange = false;
			}
		}
	}

	void selectMarkupItem(Address address, boolean isSourceAddress, VTMarkupType markupType) {

		if (address == null) {
			return;
		}
		int rowCount = markupItemsTableModel.getRowCount();
		for (int row = 0; row < rowCount; row++) {
			VTMarkupItem markupItem = markupItemsTableModel.getRowObject(row);
			Address markupItemAddress = isSourceAddress ? markupItem.getSourceAddress()
					: markupItem.getDestinationAddress();
			if (address.equals(markupItemAddress) && (markupItem.getMarkupType() == markupType)) {

				selectRowAndMakeVisible(row);
			}
		}
	}

	private void selectRowAndMakeVisible(int row) {
		GhidraTable table = tablePanel.getTable();
		table.selectRow(row);
		Rectangle cellRect = table.getCellRect(row, 0, true);
		table.scrollRectToVisible(cellRect);
	}

	/**
	 * Determines whether or not the dual listing is currently being shown to the user.
	 * @return true if the dual listing is showing
	 */
	public boolean isDualListingShowing() {
		ListingCodeComparisonPanel dualListingPanel = functionComparisonPanel.getDualListingPanel();
		if (dualListingPanel == null) {
			return false;
		}
		return dualListingPanel.isShowing();
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		if (!isVisible()) {
			return;
		}
		load(matchInfo);
	}

	@Override
	public void sessionChanged(VTSession session) {
		if (!isVisible()) {
			return;
		}

		markupItemsTableModel.setProgram(controller.getSourceProgram());
		reload();
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(VTChangeManager.DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED) ||
			ev.containsEvent(VTChangeManager.DOCR_VT_MARKUP_ITEM_STATUS_CHANGED)) {

			// FIXME The following block of code still doesn't clear the markup item cache when Reset Match occurs.
			MatchInfo matchInfo = controller.getMatchInfo();
			if (matchInfo != null) {
				matchInfo.clearCache(); // FIXME
			}

			refresh();
			tool.contextChanged(this);
		}
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		if (sourceHighlightProvider != null) {
			sourceHighlightProvider.setMarkupItem(markupItem);
		}
		if (destinationHighlightProvider != null) {
			destinationHighlightProvider.setMarkupItem(markupItem);
		}
	}

	@Override
	public void optionsChanged(Options options) {
		// do nothing
	}

	/**
	 * Restores the markup items table provider's components to the indicated saved configuration state.
	 * @param saveState the configuration state to restore
	 */
	public void readConfigState(SaveState saveState) {
		functionComparisonPanel.readConfigState(getName(), saveState);
		showComparisonPanelWithinProvider(saveState.getBoolean(SHOW_COMPARISON_PANEL, true));

		for (Filter<VTMarkupItem> filter : filters) {
			filter.readConfigState(saveState);
		}

		updateFilterDisplay();
	}

	private void updateFilterDisplay() {
		if (ancillaryFilterDialog == null) {
			return; // not yet initialized
		}

		boolean filtered = ancillaryFilterDialog.isFiltered();
		if (filtered) {
			ancillaryFilterButton.setIcon(FILTERED_ICON);
		}
		else {
			ancillaryFilterButton.setIcon(UNFILTERED_ICON);
		}

		VTSession session = controller.getSession();
		if (session == null) {
			return;
		}

		if (filtered) {
			int filteredCount = markupItemsTableModel.getRowCount();
			int unfilteredCount = markupItemsTableModel.getUnfilteredRowCount();
			int filteredOutCount = unfilteredCount - filteredCount;
			ancillaryFilterButton.setToolTipText(
				"More Filters - " + filteredOutCount + " item(s) hidden");
		}
		else {
			ancillaryFilterButton.setToolTipText("More Filters - no active filters");
		}
	}

	/**
	 * Saves the current configuration state of the components that compose the markup items table provider.
	 * @param saveState the new configuration state
	 */
	public void writeConfigState(SaveState saveState) {
		// save config state here
		functionComparisonPanel.writeConfigState(getName(), saveState);
		saveState.putBoolean(SHOW_COMPARISON_PANEL, functionComparisonPanel.isShowing());

		for (Filter<VTMarkupItem> filter : filters) {
			filter.writeConfigState(saveState);
		}
	}

// pretty slick code to force a table to repaint before doing some long running task    
//    private void forceTableToRepaintEmptyWhileLoading() {
//        JScrollPane pane = (JScrollPane) component.getComponent( 0 );        
//        Rectangle paneBounds = pane.getBounds();
//        Insets insets = pane.getInsets();
//        int paneWidth = paneBounds.width - (insets.left + insets.right);
//        
//        // force the table to resize with no data
//        Rectangle tableBounds = markupItemsTable.getBounds();        
//        tableBounds.width = paneWidth;
//        tableBounds.height = 0;
//        markupItemsTable.setBounds( tableBounds );
//        markupItemsTable.doLayout();
//        
//        // force the view to resize with no data (hide the scrollbars)
//        JViewport viewport = pane.getViewport();
//        Rectangle viewportBounds = viewport.getBounds();
//        viewportBounds.width = paneWidth;
//        viewport.setBounds( viewportBounds );      
//        
//        // force the view's header to resize with no data
//        JViewport columnHeader = pane.getColumnHeader();
//        Rectangle columnHeaderBounds = columnHeader.getBounds();
//        columnHeaderBounds.width = paneWidth;
//        columnHeader.setBounds( columnHeaderBounds );
//
//        component.doLayout();
//        component.paintImmediately( component.getBounds() );    
//    }

//==================================================================================================
// FilterDialogModel Methods
//==================================================================================================    

	@Override
	public void addFilter(Filter<VTMarkupItem> filter) {
		filter.addFilterStatusListener(refilterListener);
		filters.add(filter);
		markupItemsTableModel.addFilter(filter);
	}

	/** 
	 * Forces a refilter, even though filtering operations may be disabled. The reload
	 * is necessary since the model contents may have changed
	 */
	@Override
	public void forceRefilter() {
		markupItemsTableModel.updateFilter();
		updateFilterDisplay();
	}

	@Override
	public void dialogVisibilityChanged(boolean isVisible) {
		filteringFrozen = isVisible; // don't allow any new filtering while this dialog is visible
		refilter(); // this will do nothing if we are frozen
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class RefilterListener implements FilterStatusListener {
		@Override
		public void filterStatusChanged(FilterEditingStatus status) {
			if (status != FilterEditingStatus.ERROR) {
				refilter();
			}
		}
	}

	private class MarkupItemThreadedTablePanel extends GhidraThreadedTablePanel<VTMarkupItem> {
		MarkupItemThreadedTablePanel(ThreadedTableModel<VTMarkupItem, ?> model) {
			super(model);
		}

		@Override
		protected GTable createTable(ThreadedTableModel<VTMarkupItem, ?> model) {
			return new MarkupTable(model);
		}

		private class MarkupTable extends GhidraTable {

			MarkupTable(RowObjectTableModel<VTMarkupItem> model) {
				super(model);
			}

			private TableCellRenderer renderer = new MarkupItemRenderer();

			@Override
			public TableCellRenderer getCellRenderer(int row, int col) {
				return renderer;
			}
		}
	}

	/**
	 * This notifies the Markup Items table of a location change in the source program of the Dual Listing provider.
	 */
	private class SourceProgramLocationListener implements ProgramLocationListener {

		@Override
		public void programLocationChanged(ProgramLocation loc, EventTrigger trigger) {
			if (!processingMarkupItemSelected) {
				processSourceLocationChange(loc);
			}
		}
	}

	/**
	 * This notifies the Markup Items table of a location change in the destination program of the Dual Listing provider.
	 */
	private class DestinationProgramLocationListener implements ProgramLocationListener {

		@Override
		public void programLocationChanged(ProgramLocation loc, EventTrigger trigger) {
			if (!processingMarkupItemSelected) {
				processDestinationLocationChange(loc);
			}
		}
	}

	/**
	 * Gets the function comparison panel component that possibly contains multiple different views 
	 * for comparing code such as a dual listing.
	 * @return the function comparison panel
	 */
	public FunctionComparisonPanel getFunctionComparisonPanel() {
		return functionComparisonPanel;
	}
}
