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
package ghidra.feature.vt.gui.provider.matchtable;

import static ghidra.feature.vt.api.impl.VTEvent.*;
import static ghidra.feature.vt.gui.actions.TableSelectionTrackingState.*;
import static ghidra.feature.vt.gui.plugin.VTPlugin.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static ghidra.framework.model.DomainObjectEvent.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.*;

import docking.*;
import docking.action.builder.ActionBuilder;
import docking.widgets.table.*;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import docking.widgets.table.columnfilter.ColumnFilterManager;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.theme.GIcon;
import ghidra.app.services.FunctionComparisonService;
import ghidra.feature.vt.api.impl.VTEvent;
import ghidra.feature.vt.api.impl.VersionTrackingChangeRecord;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.editors.MatchTagCellEditor;
import ghidra.feature.vt.gui.filters.*;
import ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel.*;
import ghidra.features.base.codecompare.model.MatchedFunctionComparisonModel;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.SwingUpdateManager;
import help.HelpService;

public class VTMatchTableProvider extends ComponentProviderAdapter
		implements FilterDialogModel<VTMatch>, VTControllerListener {

	private static final Icon COMPARISON_ICON = new GIcon("icon.plugin.functioncompare.new");

	private static final String TITLE = "Version Tracking Matches";
	private static final String TABLE_SELECTION_STATE = "TABLE_SELECTION_STATE";

	public static final String TEXT_FILTER_NAME = "matches.text.filter";

	private JComponent component;
	private MatchThreadedTablePanel tablePanel;
	private GhidraTable matchesTable;
	private ListSelectionListener matchSelectionListener;
	private VTMatchTableModel matchesTableModel;

	private AncillaryFilterDialogComponentProvider<VTMatch> ancillaryFilterDialog;
	private JButton ancillaryFilterButton;
	private ColumnFilterManager<VTMatch> columnFilterManager;
	private VTColumnFilter vtColumnFilter;

	private FilterIconFlashTimer<VTMatch> iconTimer;
	private Set<Filter<VTMatch>> filters = new HashSet<>();
	private FilterStatusListener refilterListener = new RefilterListener();

	private final VTController controller;

	private VTMatch latestMatch;
	private SelectionOverrideMemento selectionMemento;
	private boolean filteringFrozen;

	// a selection we may have to set later, after the table has finished loading
	private VTMatch pendingMatchSelection;
	private SwingUpdateManager selectMatchUpdateManager;
	private MatchTableSelectionAction tableSelectionStateAction;
	private TableSelectionTrackingState tableSelectionState;

	public VTMatchTableProvider(VTController controller) {
		super(controller.getTool(), TITLE, VTPlugin.OWNER);
		this.controller = controller;
		controller.addListener(this);
		setWindowGroup(VTPlugin.WINDOW_GROUP + ".MatchesTable");
		setIcon(VersionTrackingPluginPackage.ICON);
		setDefaultWindowPosition(WindowPosition.TOP);
		createActions();
		component = createComponent();

		setVisible(true);
		selectMatchUpdateManager = new SwingUpdateManager(350, () -> {
			VTMatchTableProvider.this.controller.setSelectedMatch(latestMatch);
			notifyContextChanged();
		});

		initializeOptions();

		ancillaryFilterDialog = new MatchesFilterDialogComponentProvider(controller, this);
		iconTimer = new FilterIconFlashTimer<>(UNFILTERED_ICON, FILTERED_ICON,
			ancillaryFilterDialog, ancillaryFilterButton);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Matches_Table"));
	}

	private void createActions() {
		addLocalAction(new AcceptMatchAction(controller));
		addLocalAction(new ApplyMatchAction(controller));
		addLocalAction(new ApplyBlockedMatchAction(controller));
		addLocalAction(new VTMatchApplySettingsAction(controller));
		addLocalAction(new RejectMatchAction(controller));
		addLocalAction(new ClearMatchAction(controller));
		addLocalAction(new ChooseMatchTagAction(controller));
		addLocalAction(new RemoveMatchTagAction());
		addLocalAction(new EditAllTagsAction(controller));
		addLocalAction(new RemoveMatchAction(controller));
		addLocalAction(new CreateSelectionAction(controller));
		tableSelectionStateAction = new MatchTableSelectionAction(this);
		addLocalAction(tableSelectionStateAction);

		new ActionBuilder("Compare Functions", getName()).popupMenuPath("Compare Functions")
				.popupMenuGroup("Selection")
				.popupMenuIcon(COMPARISON_ICON)
				.keyBinding("shift c")
				.sharedKeyBinding()
				.description("Compares the Function(s) with its remote match")
				.helpLocation(
					new HelpLocation("VersionTrackingPlugin", "Match_Table_Compare_Functions"))
				.withContext(VTMatchContext.class)
				.enabledWhen(this::isValidFunctionComparison)
				.onAction(this::compareFunctions)
				.buildAndInstallLocal(this);
	}

	private boolean isValidFunctionComparison(VTMatchContext context) {
		List<VTMatch> functionMatches = context.getFunctionMatches();
		return !functionMatches.isEmpty();
	}

	private void compareFunctions(VTMatchContext c) {
		MatchedFunctionComparisonModel model = new MatchedFunctionComparisonModel();
		List<VTMatch> matches = c.getFunctionMatches();

		for (VTMatch match : matches) {
			MatchInfo matchInfo = controller.getMatchInfo(match);

			Function sourceFunction = matchInfo.getSourceFunction();
			Function destinationFunction = matchInfo.getDestinationFunction();
			model.addMatch(sourceFunction, destinationFunction);
		}

		FunctionComparisonService service = tool.getService(FunctionComparisonService.class);
		service.createCustomComparison(model, null);
	}

	// callback method from the MatchTableSelectionAction
	public void setTableSelectionMode(TableSelectionTrackingState state) {
		this.tableSelectionState = state;

		if (state == NO_SELECTION_TRACKING) {
			matchesTable.getSelectionManager().clearSavedSelection();
		}
	}

	public void readConfigState(SaveState saveState) {
		for (Filter<VTMatch> filter : filters) {
			filter.readConfigState(saveState);
		}

		updateFilterDisplay();

		setTableSelecionState(saveState);

		refilter();
	}

	private void setTableSelecionState(SaveState saveState) {
		String selectionStateName = saveState.getString(TABLE_SELECTION_STATE, null);
		if (selectionStateName == null) {
			return;
		}

		TableSelectionTrackingState state = TableSelectionTrackingState.valueOf(selectionStateName);
		if (state != null) {
			tableSelectionStateAction.setCurrentActionStateByUserData(state);
		}
	}

	private void updateFilterDisplay() {
		if (ancillaryFilterDialog == null) {
			return;// not yet initialized
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
			int filteredCount = matchesTableModel.getRowCount();
			int unfilteredCount = matchesTableModel.getUnfilteredRowCount();
			int filteredOutCount = unfilteredCount - filteredCount;
			ancillaryFilterButton
					.setToolTipText("More Filters - " + filteredOutCount + " item(s) hidden");
		}
		else {
			ancillaryFilterButton.setToolTipText("More Filters - no active filters");
		}
	}

	public void writeConfigState(SaveState saveState) {
		for (Filter<VTMatch> filter : filters) {
			filter.writeConfigState(saveState);
		}

		saveState.putString(TABLE_SELECTION_STATE, tableSelectionState.name());
	}

	@Override
	public void componentShown() {
		if (latestMatch != null) {
			setSelectedMatch(latestMatch);
		}
		matchesTableModel.sessionChanged();
		notifyContextChanged();
	}

	GTable getTable() {
		return matchesTable;
	}

	private JComponent createComponent() {

		matchesTable = createMatchesTable();
		JPanel matchesTablePanel = new JPanel(new BorderLayout());
		JPanel filterAreaPanel = createFilterArea();
		matchesTablePanel.add(tablePanel, BorderLayout.CENTER);
		matchesTablePanel.add(filterAreaPanel, BorderLayout.SOUTH);
		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(matchesTablePanel);

		matchesTable.setAccessibleNamePrefix("Matches");

		return parentPanel;
	}

	private VTMatchTableModel createTableModel() {
		matchesTableModel = new VTMatchTableModel(controller);
		matchesTableModel.addTableModelListener(e -> {
			if (matchesTable == null) {
				return; // we've been disposed
			}

			int filteredCount = matchesTableModel.getRowCount();
			int unfilteredCount = matchesTableModel.getUnfilteredRowCount();

			String sessionName = controller.getVersionTrackingSessionName();
			StringBuilder buffy = new StringBuilder();
			buffy.append("[Session: ").append(sessionName).append("] - ");
			buffy.append(filteredCount).append(" matches");
			if (filteredCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(')');
			}

			setSubTitle(buffy.toString());

			updateFilterDisplay();

			if (pendingMatchSelection != null) {
				setSelectedMatch(pendingMatchSelection);
			}
			else if (selectionMemento != null) {
				selectionMemento.restoreSelection();
			}
		});
		return matchesTableModel;
	}

	private GhidraTable createMatchesTable() {
		tablePanel = new MatchThreadedTablePanel(createTableModel());
		final GhidraTable table = tablePanel.getTable();
		table.setActionsEnabled(true);

		table.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				iconTimer.restart();
			}
		});

		matchSelectionListener = new ListSelectionListener() {
			@Override
			@SuppressWarnings("unchecked")
			// it's our model, it must be our type
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}

				// we get out the model here in case it has been wrapped by one of the filters
				RowObjectTableModel<VTMatch> model =
					(RowObjectTableModel<VTMatch>) table.getModel();
				boolean hasSingleSelection = table.getSelectedRowCount() == 1;
				int selectedRow = table.getSelectedRow();
				VTMatch match = hasSingleSelection ? model.getRowObject(selectedRow) : null;
				if (!SystemUtilities.isEqual(latestMatch, match)) {
					latestMatch = match;

					// call updateLater() instead of update(), as the latter can execute in the
					// swing thread, causing the display to get sluggish
					selectMatchUpdateManager.updateLater();
				}
				else {
					// for any selection that is not handled by the match changing we want to
					// notify that context has changed so that actions properly update
					notifyContextChanged();
				}
			}
		};
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(matchSelectionListener);

		// setup the renderers
		TableColumnModel columnModel = table.getColumnModel();

		int tagColumnIndex = matchesTableModel.getColumnIndex(TagTableColumn.class);
		TableColumn tagColumn = columnModel.getColumn(tagColumnIndex);
		tagColumn.setCellEditor(new MatchTagCellEditor(controller));

		int sourceLabelColumnIndex = matchesTableModel.getColumnIndex(SourceLabelTableColumn.class);
		TableColumn sourceLabelColumn = columnModel.getColumn(sourceLabelColumnIndex);
		sourceLabelColumn
				.setCellRenderer(new VTSymbolRenderer(controller.getServiceProvider(), table));

		int destinationLabelColumnIndex =
			matchesTableModel.getColumnIndex(DestinationLabelTableColumn.class);
		TableColumn destinationLabelColumn = columnModel.getColumn(destinationLabelColumnIndex);
		destinationLabelColumn
				.setCellRenderer(new VTSymbolRenderer(controller.getServiceProvider(), table));

		int statusColumnIndex = matchesTableModel.getColumnIndex(StatusTableColumn.class);
		TableColumn statusColumn = columnModel.getColumn(statusColumnIndex);
		statusColumn.setCellRenderer(new MatchStatusRenderer());

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

	private JPanel createFilterArea() {
		JPanel parentPanel = new JPanel(new BorderLayout());

		JPanel innerPanel = new JPanel(new HorizontalLayout(4));
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));

		JComponent textFilterPanel = createTextFilterPanel();
		parentPanel.add(textFilterPanel, BorderLayout.CENTER);
		parentPanel.add(innerPanel, BorderLayout.EAST);

		JComponent scoreFilterPanel = createScoreFilterPanel();
		innerPanel.add(scoreFilterPanel);

		JComponent confidenceFilterPanel = createConfidenceFilterPanel();
		innerPanel.add(confidenceFilterPanel);

		JComponent lengthFilterPanel = createLengthFilterPanel();
		innerPanel.add(lengthFilterPanel);

		ancillaryFilterButton = new JButton(UNFILTERED_ICON);
		ancillaryFilterButton
				.addActionListener(e -> tool.showDialog(ancillaryFilterDialog, component));
		ancillaryFilterButton.setToolTipText("Filters Dialog");
		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation filterHelpLocation =
			new HelpLocation("VersionTrackingPlugin", "Match_Filters");
		helpService.registerHelp(parentPanel, filterHelpLocation);
		helpService.registerHelp(ancillaryFilterButton, filterHelpLocation);

		JButton columnFilterButton = createColumnFilterButton();
		innerPanel.add(columnFilterButton);

		innerPanel.add(ancillaryFilterButton);

		return parentPanel;
	}

	private JButton createColumnFilterButton() {

		String preferenceKey =
			matchesTable.getPreferenceKey() + ColumnFilterManager.FILTER_EXTENSION;
		columnFilterManager = new ColumnFilterManager<VTMatch>(matchesTable, matchesTableModel,
			preferenceKey, this::updateColumnFilter);

		vtColumnFilter = new VTColumnFilter(columnFilterManager.getCurrentFilter());
		addFilter(vtColumnFilter);

		return columnFilterManager.getConfigureButton();
	}

	private void updateColumnFilter() {
		vtColumnFilter.setFilter(columnFilterManager.getCurrentFilter());
		refilter();
	}

	private JComponent createTextFilterPanel() {
		AllTextFilter<VTMatch> allTextFilter =
			new AllTextFilter<>(controller, matchesTable, matchesTableModel);
		allTextFilter.setName(TEXT_FILTER_NAME);
		addFilter(allTextFilter);
		return allTextFilter.getComponent();
	}

	private JComponent createLengthFilterPanel() {
		LengthFilter lengthFilter = new LengthFilter();
		addFilter(lengthFilter);
		return lengthFilter.getComponent();
	}

	private JComponent createScoreFilterPanel() {
		ScoreFilter scoreFilter = new ScoreFilter();
		addFilter(scoreFilter);
		return scoreFilter.getComponent();
	}

	private JComponent createConfidenceFilterPanel() {
		ConfidenceFilter confidenceFilter = new ConfidenceFilter();
		addFilter(confidenceFilter);
		return confidenceFilter.getComponent();
	}

	private void refilter() {
		if (filteringFrozen) {
			return;
		}

		forceRefilter();
	}

	private void setSelectedMatch(VTMatch match) {
		int row = matchesTableModel.getRowIndex(match);
		if (row < 0) {
			pendingMatchSelection = match;
			// this happen while reloading. If so, save the match and listen for
			// the table data changed and restore the selection at that point
			return;
		}

		pendingMatchSelection = null;
		matchesTable.getSelectionModel().setSelectionInterval(row, row);
		Rectangle rect = matchesTable.getCellRect(row, 0, false);
		matchesTable.scrollRectToVisible(rect);
	}

	public void repaint() {
		if (matchesTable == null) {
			return;
		}
		matchesTable.repaint();
	}

	private void reload() {
		controller.setSelectedMatch(null);
		matchesTableModel.clearData();
		matchesTableModel.reload();

		notifyContextChanged();
	}

	private void updateWithoutFullReload() {
		matchesTableModel.reSort();
		matchesTableModel.updateFilter();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void disposed() {
		if (matchesTable == null) {
			return;
		}

		// must remove the listener first to avoid callback whilst we are disposing
		ListSelectionModel selectionModel = matchesTable.getSelectionModel();
		selectionModel.removeListSelectionListener(matchSelectionListener);

		matchesTableModel.dispose();

		for (Filter<VTMatch> filter : filters) {
			filter.dispose();
		}

		ancillaryFilterDialog.dispose();

		columnFilterManager.dispose();
	}

	@Override
	public void sessionChanged(VTSession session) {
		if (!isVisible()) {
			return;
		}
		latestMatch = null;
		selectionMemento = null;

		matchesTableModel.sessionChanged();
		updateFilterDisplay();
		if (session != null && isVisible()) {// bring to front
			tool.toFront(this);
		}

		notifyContextChanged();
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}

		if (ev.contains(RESTORED, MATCH_SET_ADDED)) {// save some work
			saveComplexSelectionUpdate();
			reload();
			return;
		}

		boolean matchesContextChanged = false;
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			EventType eventType = doRecord.getEventType();

			if (eventType == ASSOCIATION_STATUS_CHANGED ||
				eventType == VTEvent.ASSOCIATION_MARKUP_STATUS_CHANGED) {

				updateWithoutFullReload();
				matchesContextChanged = true;
				saveComplexSelectionUpdate();
			}
			else if (eventType == VTEvent.MATCH_TAG_CHANGED) {
				updateWithoutFullReload();
				matchesContextChanged = true;
			}
			else if (eventType == VTEvent.MATCH_ADDED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				matchesTableModel.addObject((VTMatch) vtRecord.getNewValue());
				matchesContextChanged = true;
			}
			else if (eventType == VTEvent.MATCH_DELETED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				matchesTableModel.removeObject((VTMatch) vtRecord.getObject());
				matchesContextChanged = true;
			}
		}

		if (matchesContextChanged) {
			// Now that all records have been processed,
			// since the match table changed perform a reload to apply filters.
			reload();

			// Update the context so that toolbar actions fix their enablement.
			tool.contextChanged(this);
		}
	}

	private SelectionOverrideMemento saveComplexSelectionUpdate() {
		SelectionOverrideMemento mostRecentMemento = getCurrentSelectionMemento();
		if (mostRecentMemento != null) {
			// prefer the current selection over a saved one
			selectionMemento = mostRecentMemento;
			return selectionMemento;// return this for later usage
		}

		// return the current memento, which could be null
		return selectionMemento;
	}

	private SelectionOverrideMemento getCurrentSelectionMemento() {
		int[] selectedRows = matchesTable.getSelectedRows();
		int length = selectedRows.length;
		if (length == 0) {
			return null;
		}

		int row = selectedRows[0];
		VTMatch match = matchesTableModel.getRowObject(row);
		return new SelectionOverrideMemento(row, match);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		List<VTMatch> selectedMatches = getSelectedMatches();
		return new VTMatchContext(this, selectedMatches, controller.getSession());
	}

	private List<VTMatch> getSelectedMatches() {
		List<VTMatch> list = new ArrayList<>();
		if (matchesTable == null) {
			return list;
		}

		int[] selectedRows = matchesTable.getSelectedRows();
		for (int row : selectedRows) {
			VTMatch match = matchesTableModel.getRowObject(row);
			if (match != null) {
				list.add(match);
			}
		}
		return list;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		VTMatch match = matchInfo == null ? null : matchInfo.getMatch();
		if (match == latestMatch) {
			return;
		}

		if (!isVisible()) {
			latestMatch = match;
			return;
		}

		setSelectedMatch(match);
	}

	@Override
	public void optionsChanged(Options options) {
		// implemented as ControllerListener. Don't care about options changed right
		// now.
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		// Do nothing since the matches table doesn't need to respond to the mark-up
		// that is selected.
	}

	private void initializeOptions() {
		Options vtOptions = controller.getOptions();
		vtOptions.registerOption(AUTO_CREATE_IMPLIED_MATCH, true, null,
			"Create implied (referenced) matches when accepting a match");
		vtOptions.registerOption(APPLY_FUNCTION_NAME_ON_ACCEPT, true, null,
			"Automatically apply function names when accepting a match");
		vtOptions.registerOption(APPLY_DATA_NAME_ON_ACCEPT, true, null,
			"Automatically apply data labels when accepting a match");

		vtOptions.registerOption(DATA_MATCH_DATA_TYPE, DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE,
			null,
			"The default apply action <b>for the data type on a data match</b> when performing bulk apply operations");

		vtOptions.registerOption(LABELS, DEFAULT_OPTION_FOR_LABELS, null,
			"The default apply action <b>for labels</b> when performing bulk apply operations");

		vtOptions.registerOption(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME, null,
			"The default apply action <b>for function name</b> when performing bulk apply operations");

		vtOptions.registerOption(FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE, null,
			"The default apply action <b>for the function signature</b> " +
				"when performing bulk apply operations");

		vtOptions.registerOption(PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS, null,
			"The default apply action <b>for plate comments</b> when performing bulk apply operations");

		vtOptions.registerOption(PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS, null,
			"The default apply action <b>for pre comments</b> when performing bulk apply operations");

		vtOptions.registerOption(END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS, null,
			"The default apply action <b>for end of line comments</b> when performing bulk apply operations");

		vtOptions.registerOption(REPEATABLE_COMMENT, DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS, null,
			"The default apply action <b>for repeatable comments</b> when performing bulk apply operations");

		vtOptions.registerOption(POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS, null,
			"The default apply action <b>for post comments</b> when performing bulk apply operations");

		vtOptions.registerOption(INLINE, DEFAULT_OPTION_FOR_INLINE, null,
			"The default apply action <b>for the function inline flag</b> to use " +
				"when applying the function signature as part of a bulk apply operation");

		vtOptions.registerOption(NO_RETURN, DEFAULT_OPTION_FOR_NO_RETURN, null,
			"The default apply action <b>for the function no return flag</b> to use " +
				"when applying the function signature as part of a bulk apply operation");

		vtOptions.registerOption(CALLING_CONVENTION, DEFAULT_OPTION_FOR_CALLING_CONVENTION, null,
			"The default apply action <b>for the function calling convention</b> to use " +
				"when applying the function signature as part of a bulk apply operation");

		vtOptions.registerOption(CALL_FIXUP, DEFAULT_OPTION_FOR_CALL_FIXUP, null,
			"The default apply action <b>for whether or not to apply call fixup</b> " +
				"when applying the function signature as part of a bulk apply operation");

		vtOptions.registerOption(VAR_ARGS, DEFAULT_OPTION_FOR_VAR_ARGS, null,
			"The default apply action <b>for the var args flag</b> to use " +
				"when applying the function signature as part of a bulk apply operation");

		vtOptions.registerOption(FUNCTION_RETURN_TYPE, DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE,
			null, "The default apply action <b>for function return type</b> when performing bulk " +
				"apply operations");

		vtOptions.registerOption(PARAMETER_DATA_TYPES, DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES,
			null,
			"The default apply action <b>for function parameter data types</b> when performing bulk " +
				"apply operations");

		vtOptions.registerOption(PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES, null,
			"The default apply action <b>for function parameter names</b> when performing bulk " +
				"apply operations");

		vtOptions.registerOption(HIGHEST_NAME_PRIORITY, DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY,
			null, "The default apply action <b>for which source type is the highest priority</b> " +
				"when applying parameter names using a priority replace");

		vtOptions.registerOption(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
			DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, null,
			"When function signature parameter names are being replaced based on source type priority, " +
				"replace the destination name with the source name if their source types are the same.");

		vtOptions.registerOption(PARAMETER_COMMENTS, DEFAULT_OPTION_FOR_PARAMETER_COMMENTS, null,
			"The default apply action <b>for function parameter comments</b> " +
				"when applying parameter names as part of a bulk apply operations");

		vtOptions.registerOption(IGNORE_EXCLUDED_MARKUP_ITEMS,
			DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS, null,
			"Types of markup items that have been excluded when applying should become ignored by " +
				"applying a match.");
		vtOptions.registerOption(IGNORE_INCOMPLETE_MARKUP_ITEMS,
			DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS, null,
			"Markup items that are incomplete (for example, no destination address is specified) " +
				"should become ignored by applying a match.");

		vtOptions.getOptions(APPLY_MARKUP_OPTIONS_NAME)
				.registerOptionsEditor(() -> new ApplyMarkupPropertyEditor(controller));
		vtOptions.getOptions(DISPLAY_APPLY_MARKUP_OPTIONS)
				.setOptionsHelpLocation(
					new HelpLocation("VersionTracking", "Apply Markup Options"));

		// Auto VT options

		// put checkboxes to determine which correlators to run during auto VT
		vtOptions.registerOption(CREATE_IMPLIED_MATCHES_OPTION, true, null,
			"Create Implied Matches when AutoVT correlators apply function matches.");
		vtOptions.registerOption(RUN_EXACT_DATA_OPTION, true, null,
			"Run the Exact Data Correlator");
		vtOptions.registerOption(RUN_EXACT_SYMBOL_OPTION, true, null,
			"Run the Exact Symbol Correlator");
		vtOptions.registerOption(RUN_EXACT_FUNCTION_BYTES_OPTION, true, null,
			"Run the Exact Function Bytes Correlator");
		vtOptions.registerOption(RUN_EXACT_FUNCTION_INST_OPTION, true, null,
			"Run the Exact Function Instruction Bytes and Mnemonics Correlators");
		vtOptions.registerOption(RUN_DUPE_FUNCTION_OPTION, true, null,
			"Run the Duplicate Function Instruction Correlator");
		vtOptions.registerOption(RUN_REF_CORRELATORS_OPTION, true, null,
			"Run the Reference Correlators");

		// set help for the sub categories

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_IMPLIED_MATCH_CORRELATOR)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_SYMBOL_CORRELATOR)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_DATA_CORRELATOR)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_EXACT_FUNCTION_CORRELATORS)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_DUPLICATE_FUNCTION_CORRELATOR)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_REFERENCE_CORRELATORS)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		// create sub options for each auto VT correlator
		vtOptions.registerOption(APPLY_IMPLIED_MATCHES_OPTION, true, null,
			"Apply implied matches if minimum vote count is met and maximum conflict count is not exceeded.");
		vtOptions.registerOption(MIN_VOTES_OPTION, 2, null,
			"The minimum number of votes needed to apply an implied match.");
		vtOptions.registerOption(MAX_CONFLICTS_OPTION, 0, null,
			"The maximum number of conflicts allowed to apply an implied match.");

		vtOptions.registerOption(SYMBOL_CORRELATOR_MIN_LEN_OPTION, 3, null,
			"Minimum Symbol Name Length of Auto Version Tracking Symbol Correlator");
		vtOptions.getOptions(SYMBOL_CORRELATOR_MIN_LEN_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.registerOption(DATA_CORRELATOR_MIN_LEN_OPTION, 5, null,
			"Minimum Data Length of Auto Version Tracking Data Correlator");
		vtOptions.getOptions(DATA_CORRELATOR_MIN_LEN_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.registerOption(FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10, null,
			"Minimum Function Length of Auto Version Tracking Duplicate Function Correlator");
		vtOptions.getOptions(FUNCTION_CORRELATOR_MIN_LEN_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.registerOption(DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10, null,
			"Minimum Function Length of Auto Version Tracking Duplicate Function Correlator");
		vtOptions.getOptions(DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.registerOption(REF_CORRELATOR_MIN_SCORE_OPTION, 0.95, null,
			"Minimum Score of all Auto Version Tracking Reference Function Correlators (Data, Function, and Combined Function and Data)");
		vtOptions.getOptions(REF_CORRELATOR_MIN_SCORE_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		vtOptions.registerOption(REF_CORRELATOR_MIN_CONF_OPTION, 10.0, null,
			"Minimum Confidence of all Auto Version Tracking Reference Function Correlator (Data, Function, and Combined Function and Data)");
		vtOptions.getOptions(REF_CORRELATOR_MIN_CONF_OPTION)
				.setOptionsHelpLocation(
					new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options"));

		HelpLocation applyOptionsHelpLocation =
			new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Version_Tracking_Apply_Options");
		HelpLocation applyMatchOptionsHelpLocation =
			new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Match_Apply_Options");

		HelpLocation autoVTHelpLocation =
			new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Auto_Version_Tracking_Options");

		vtOptions.setOptionsHelpLocation(applyOptionsHelpLocation);

		vtOptions.getOptions(ACCEPT_MATCH_OPTIONS_NAME)
				.setOptionsHelpLocation(applyMatchOptionsHelpLocation);

		vtOptions.getOptions(APPLY_MARKUP_OPTIONS_NAME)
				.setOptionsHelpLocation(applyMatchOptionsHelpLocation);

		vtOptions.setOptionsHelpLocation(autoVTHelpLocation);
		vtOptions.getOptions(AUTO_VT_OPTIONS_NAME).setOptionsHelpLocation(autoVTHelpLocation);
	}

//==================================================================================================
// FilterDialogModel Methods
//==================================================================================================

	@Override
	public void addFilter(Filter<VTMatch> filter) {
		filter.addFilterStatusListener(refilterListener);
		filters.add(filter);
		matchesTableModel.addFilter(filter);
	}

	/**
	 * Forces a refilter, even though filtering operations may be disabled. The
	 * reload is necessary since the model contents may have changed
	 */
	@Override
	public void forceRefilter() {
		matchesTableModel.updateFilter();
		updateFilterDisplay();
	}

	@Override
	public void dialogVisibilityChanged(boolean isVisible) {
		filteringFrozen = isVisible;// don't allow any new filtering while this dialog is visible
		refilter();// this will do nothing if we are frozen
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

	private class MatchThreadedTablePanel extends GhidraThreadedTablePanel<VTMatch> {
		private MatchTableRenderer matchRenderer = new MatchTableRenderer();

		MatchThreadedTablePanel(ThreadedTableModel<VTMatch, ?> model) {
			super(model);
		}

		@Override
		protected GTable createTable(ThreadedTableModel<VTMatch, ?> model) {
			return new MatchTable(model);
		}

		private class MatchTable extends GhidraTable {

			MatchTable(RowObjectTableModel<VTMatch> model) {
				super(model);
			}

			@Override
			public TableCellRenderer getCellRenderer(int row, int col) {
				// special composite renderer
				return matchRenderer;
			}

			@SuppressWarnings("unchecked")
			// this is our table model--we know its real type
			@Override
			protected SelectionManager createSelectionManager() {
				return new VTMatchTableSelectionManager(this,
					(AbstractSortedTableModel<VTMatch>) getModel());
			}
		}
	}

	/**
	 * A class meant to override the default table selection behavior <b>in special
	 * situations</b>.
	 * <p>
	 * <u>Issue 1:</u> Accepting or applying a match can trigger the match to be
	 * filtered out of the table. The default SelectionManager does not restore the
	 * selection for that item, as it knows that the item is gone.
	 * <p>
	 * <u>Issue 2:</u> Accepting or applying a match can trigger the match to be
	 * moved due to a sort operation after the edit.
	 * <p>
	 * <u>Desired Behavior:</u> Have the selection restored to the previous
	 * location, even if the item is moved or removed.
	 * <p>
	 * Creating this object will cancel the default behavior. Calling
	 * <tt>restoreSelection</tt> will set the new selection, depending upon the
	 * conditions described above.
	 */
	private class SelectionOverrideMemento {
		private final int row;
		private final VTMatch match;

		/*
		 * (see the class header for details) {@link SelectionOverrideMemento}
		 */
		SelectionOverrideMemento(int row, VTMatch match) {
			this.row = row;
			this.match = match;

			if (row < 0) {
				throw new AssertException("Saved selection row must be > 0!");
			}

			if (match == null) {
				throw new AssertException("Saved selected match cannot be null!");
			}

			// override default behavior
			SelectionManager selectionManager = matchesTable.getSelectionManager();
			selectionManager.clearSavedSelection();
		}

		void restoreSelection() {
			if (tableSelectionState == NO_SELECTION_TRACKING) {
				return;
			}

			int rowCount = matchesTableModel.getRowCount();
			if (rowCount == 0) {
				// nothing to select; don't erase the memento, we may be asked again to restore
				return;
			}

			selectionMemento = null;// clear the selection memento

			ListSelectionModel selectionModel = matchesTable.getSelectionModel();
			int rowToSelect = row;
			if (row > matchesTableModel.getRowCount()) {
				// The model has shrunk. Not sure what the best action is?
				tryToSelectMatch(selectionModel);// this only works if we are tracking by match and not index
				return;
			}

			// At this point the selection model may still believe that its selection is the
			// value we are setting. Calling clearSelection() will kick the model. Without
			// the
			// kick, the setSelectionInterval() call we make may ultimately have no effect.
			selectionModel.clearSelection();

			if (tableSelectionState == MAINTAIN_SELECTED_ROW_INDEX) {
				// In this state we are tracking row selection, so just select the previously
				// selected row.
				selectionModel.setSelectionInterval(rowToSelect, rowToSelect);
				matchesTable.scrollToSelectedRow();
			}
			else if (tableSelectionState == MAINTAIN_SELECTED_ROW_VALUE) {
				tryToSelectMatch(selectionModel);
			}
			else {
				throw new AssertException(
					"Unhandled " + TableSelectionTrackingState.class.getSimpleName() +
						" value--a new state " + "must have been added");
			}
		}

		private void tryToSelectMatch(ListSelectionModel selectionModel) {
			// In this state we are tracking the value that was selected and we want to
			// reselect that value.
			int matchRow = matchesTableModel.getRowIndex(match);
			if (matchRow >= 0 && matchRow < matchesTableModel.getRowCount()) {
				selectionModel.setSelectionInterval(matchRow, matchRow);
				matchesTable.scrollToSelectedRow();
			}
		}

		@Override
		public String toString() {
			return "row=" + row + "; match=" + match;
		}
	}

	/**
	 * Override the built-in SelectionManager so that we can respond to the current
	 * table selection mode.
	 */
	private class VTMatchTableSelectionManager extends RowObjectSelectionManager<VTMatch> {
		VTMatchTableSelectionManager(JTable table, AbstractSortedTableModel<VTMatch> tableModel) {
			super(table, tableModel);
		}

		@Override
		protected List<VTMatch> translateRowsToValues(int[] rows) {
			switch (tableSelectionState) {
				case MAINTAIN_SELECTED_ROW_INDEX:
					ArrayList<VTMatch> list = new ArrayList<>(rowsToMatches(rows));
					return list;
				case MAINTAIN_SELECTED_ROW_VALUE:
					return super.translateRowsToValues(rows);
				case NO_SELECTION_TRACKING:
					return Collections.emptyList();
				default:
					throw new AssertException(
						"Unhandled " + TableSelectionTrackingState.class.getSimpleName() +
							" value--a new state " + "must have been added");
			}
		}

		private List<VTMatch> rowsToMatches(int[] rows) {
			List<VTMatch> list = new ArrayList<>(rows.length);
			for (int row : rows) {
				VTMatch match = matchesTableModel.getRowObject(row);
				list.add(match);
			}
			return list;
		}
	}

	private class VTColumnFilter extends Filter<VTMatch> {

		private ColumnBasedTableFilter<VTMatch> columnFilter;

		VTColumnFilter(ColumnBasedTableFilter<VTMatch> columnFilter) {
			this.columnFilter = columnFilter;
		}

		void setFilter(ColumnBasedTableFilter<VTMatch> columnFilter) {
			this.columnFilter = columnFilter;
		}

		@Override
		public boolean passesFilter(VTMatch t) {
			if (columnFilter == null) {
				return true;
			}
			return columnFilter.acceptsRow(t);
		}

		@Override
		public FilterEditingStatus getFilterStatus() {
			if (columnFilter == null || columnFilter.isEmpty()) {
				return FilterEditingStatus.NONE;
			}

			return FilterEditingStatus.APPLIED;
		}

		@Override
		public JComponent getComponent() {
			// This filter is configured outside of the VT filter API
			throw new UnsupportedOperationException();
		}

		@Override
		public FilterShortcutState getFilterShortcutState() {
			return FilterShortcutState.REQUIRES_CHECK;
		}

		@Override
		public Filter<VTMatch> createCopy() {
			return this; // does not currently support copying; should not be needed
		}

		@Override
		public void readConfigState(SaveState saveState) {
			// handled by the column filter manager
		}

		@Override
		public void writeConfigState(SaveState saveState) {
			// handled by the column filter manager
		}

		@Override
		public boolean isSubFilterOf(Filter<VTMatch> otherFilter) {

			Class<?> clazz = getClass();
			Class<?> otherClazz = otherFilter.getClass();
			if (!clazz.equals(otherClazz)) {
				return false; // must be the same class
			}

			VTColumnFilter otherColumnFilter = (VTColumnFilter) otherFilter;
			if (columnFilter == null && otherColumnFilter.columnFilter == null) {
				return true;
			}
			return columnFilter.isSubFilterOf(otherColumnFilter.columnFilter);
		}

	}

}
