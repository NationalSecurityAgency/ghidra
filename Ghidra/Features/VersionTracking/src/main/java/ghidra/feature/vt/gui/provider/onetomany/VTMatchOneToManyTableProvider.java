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
package ghidra.feature.vt.gui.provider.onetomany;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.*;

import docking.ActionContext;
import docking.widgets.label.GDLabel;
import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.filters.*;
import ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.markuptable.DisplayableListingAddress;
import ghidra.feature.vt.gui.provider.matchtable.MatchTableRenderer;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel.StatusTableColumn;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.MatchStatusRenderer;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.ResourceManager;

/**
 * The docking window that provides a table of the other tool's function matches for the function
 * containing the current cursor location in this tool's listing.
 */
public abstract class VTMatchOneToManyTableProvider extends ComponentProviderAdapter
		implements FilterDialogModel<VTMatch>, VTControllerListener, VTSubToolManagerListener {

	private static final String TITLE_PREFIX = "Version Tracking Matches for ";
	private static final Icon ICON = ResourceManager.loadImage("images/text_list_bullets.png");

	protected static final Color LOCAL_INFO_FOREGROUND_COLOR = new Color(0, 128, 0);

	private JComponent component;
	private MatchThreadedTablePanel tablePanel;
	protected GhidraTable matchesTable;
	private ListSelectionListener matchSelectionListener;
	protected VTMatchOneToManyTableModel oneToManyTableModel;

	private JToggleButton ancillaryFilterButton;
	private Set<Filter<VTMatch>> filters = new HashSet<>();
	private FilterStatusListener refilterListener = new RefilterListener();

	protected final VTController controller;
	protected final VTSubToolManager subToolManager;
	private Address matchAddress = null;

	private JPanel localPanel;
	private JLabel label;
	private JLabel labelValue;
	private JLabel labelType;
	private JLabel labelTypeValue;
	private JLabel address;
	private JLabel addressValue;
	private boolean isSource;

	private VTMatch latestMatch;
	private boolean filteringFrozen;

	// a selection we may have to set later, after the table has finished loading
	private VTMatch pendingMatchSelection;

	public VTMatchOneToManyTableProvider(PluginTool tool, VTController controller,
			VTSubToolManager subToolManager, boolean isSource) {
		super(tool, TITLE_PREFIX + (isSource ? "Source" : "Destination"), VTPlugin.OWNER);
		this.controller = controller;
		this.subToolManager = subToolManager;
		this.isSource = isSource;

		setWindowGroup(VTPlugin.WINDOW_GROUP);
		setIcon(ICON);

		component = createComponent();
		createActions();
		controller.addListener(this);
		subToolManager.addListener(this);
		addToTool();
		HelpLocation helpLocation =
			new HelpLocation("VersionTrackingPlugin", "Related Matches Table");
		setHelpLocation(helpLocation);
		setVisible(true);

	}

	@Override
	public String getTitle() {
		return TITLE_PREFIX + (isSource ? "Source" : "Destination");
	}

	private void createActions() {
		addLocalAction(new SetVTMatchFromOneToManyAction(controller, true));
		addLocalAction(new ClearMatchAction(controller));
		addLocalAction(new AcceptMatchAction(controller));
	}

	@Override
	public void componentHidden() {
		matchesTable.getSelectionModel().clearSelection();
		loadLocalInfo(null);
		oneToManyTableModel.setAddress(null);
	}

	@Override
	public void componentShown() {
		oneToManyTableModel.sessionChanged();
		setSelectedMatch(latestMatch);
		setAddress(matchAddress);
	}

	JTable getTable() {
		return matchesTable;
	}

	private JComponent createComponent() {

		JPanel localMatchInfoPanel = createLocalInfoPanel();

		matchesTable = initializeMatchesTable();
		JPanel matchDestinationTablePanel = new JPanel(new BorderLayout());
		matchDestinationTablePanel.add(tablePanel, BorderLayout.CENTER);

		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(localMatchInfoPanel, BorderLayout.NORTH);
		parentPanel.add(matchDestinationTablePanel, BorderLayout.CENTER);

		return parentPanel;
	}

	protected GhidraTable initializeMatchesTable() {
		oneToManyTableModel = getMatchesTableModel();
		oneToManyTableModel.addTableModelListener(e -> {
			if (pendingMatchSelection != null) {
				setSelectedMatch(pendingMatchSelection);
			}
		});

		tablePanel = new MatchThreadedTablePanel(oneToManyTableModel);
		final GhidraTable table = tablePanel.getTable();

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
				int selectedRow = table.getSelectedRow();
				VTMatch match =
					(table.getSelectedRowCount() == 1) ? model.getRowObject(selectedRow) : null;
				if (!SystemUtilities.isEqual(latestMatch, match) && match != null) {
					latestMatch = match;
					subToolManager.setMatch(match);
				}
				notifyContextChanged();
			}
		};
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(matchSelectionListener);

		// setup the renderers
		TableColumnModel columnModel = table.getColumnModel();

		int statusColumnIndex = oneToManyTableModel.getColumnIndex(StatusTableColumn.class);
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

	protected abstract VTMatchOneToManyTableModel getMatchesTableModel();

	private void refilter() {
		if (filteringFrozen) {
			return;
		}
		oneToManyTableModel.reFilter();
	}

	@Override
	public void setSelectedMatch(VTMatch match) {
		int row = oneToManyTableModel.getRowIndex(match);
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

	public void reload() {
		oneToManyTableModel.clearData();
		oneToManyTableModel.reload();
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

		oneToManyTableModel.dispose();

		for (Filter<VTMatch> filter : filters) {
			filter.dispose();
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		List<VTMatch> selectedMatches = getSelectedMatches();
		return new VTMatchOneToManyContext(this, selectedMatches);
	}

	private List<VTMatch> getSelectedMatches() {
		List<VTMatch> list = new ArrayList<>();
		int selectedRowCount = matchesTable.getSelectedRowCount();
		if (selectedRowCount == 1) {
			int row = matchesTable.getSelectedRow();
			VTMatch mySelectedMatch = oneToManyTableModel.getRowObject(row);
			list.add(mySelectedMatch);
		}
		return list;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	public void setAddress(Address matchAddress) {
		boolean sameAsLastAddress = SystemUtilities.isEqual(this.matchAddress, matchAddress);
		if (!sameAsLastAddress) {
			// Save this address as the match address whether we are showing or not.
			this.matchAddress = matchAddress;
		}
		if (!isVisible() || (controller.getSession() == null)) {
			return;
		}
		if (!sameAsLastAddress) {
			// If we're showing and the address changed then clear the selection.
			matchesTable.getSelectionModel().clearSelection();
		}
		loadLocalInfo(matchAddress);
		oneToManyTableModel.setAddress(matchAddress);
	}

	protected JPanel createLocalInfoPanel() {
		localPanel = new JPanel(new HorizontalLayout(10));
		JPanel labelPanel = new JPanel();
		JPanel labelTypePanel = new JPanel();
		JPanel addressPanel = new JPanel();

		// LABEL,
		String labelText = (isSource ? "Source" : "Destination") + " Label: ";
		label = new GDLabel(labelText);
//		label.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		labelValue = new GDLabel("     ");
		labelValue.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		labelPanel.add(label);
		labelPanel.add(labelValue);

		// LABEL_TYPE,
		String labelTypeText = "Label Type: ";
		labelType = new GDLabel(labelTypeText);
//		labelType.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		labelTypeValue = new GDLabel("     ");
		labelTypeValue.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		labelTypePanel.add(labelType);
		labelTypePanel.add(labelTypeValue);

		// ADDRESS
		String addressText = (isSource ? "Source" : "Destination") + " Address: ";
		address = new GDLabel(addressText);
//		address.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		addressValue = new GDLabel("     ");
		addressValue.setForeground(LOCAL_INFO_FOREGROUND_COLOR);
		addressPanel.add(address);
		addressPanel.add(addressValue);

		localPanel.add(labelPanel);
		localPanel.add(labelTypePanel);
		localPanel.add(addressPanel);

		return localPanel;
	}

	public void loadLocalInfo(Address infoAddress) {
		if (infoAddress == null) {
			labelValue.setText("");
			labelTypeValue.setText("");
			addressValue.setText("");
			return;
		}

		VTSession session = controller.getSession();
		Program program = (isSource ? session.getSourceProgram() : session.getDestinationProgram());

		// LABEL,
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(infoAddress);
		String labelValueText;
		if (symbol == null) {
			labelValueText = "<No Symbol>";
		}
		else {
			labelValueText = symbol.getName();
		}
		labelValue.setText(labelValueText);

		// LABEL_SOURCE,
		String labelTypeValueText;
		if (symbol == null) {
			labelTypeValueText = "<none>";
		}
		else {
			labelTypeValueText = symbol.getSource().getDisplayString();
		}
		labelTypeValue.setText(labelTypeValueText);

		// ADDRESS
		DisplayableListingAddress displayableAddress =
			new DisplayableListingAddress(program, infoAddress);
		addressValue.setText(displayableAddress.getDisplayString());

		localPanel.validate();
		localPanel.invalidate();
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		VTMatch match = matchInfo == null ? null : matchInfo.getMatch();
		if (match == latestMatch) {
			return;
		}
		latestMatch = match;
		if (!isVisible()) {
			return;
		}
		setSelectedMatch(match);
	}

	@Override
	public void sessionChanged(VTSession session) {
		latestMatch = null;
		if (!isVisible()) {
			return;
		}
		oneToManyTableModel.sessionChanged();
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}
		// Check event since some may require reload of table if more or fewer matches.
		boolean matchesContextChanged = false;
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			int eventType = doRecord.getEventType();

			if (eventType == VTChangeManager.DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED ||
				eventType == VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED ||
				eventType == VTChangeManager.DOCR_VT_MATCH_TAG_CHANGED) {

				oneToManyTableModel.refresh();
				repaint();
				matchesContextChanged = true;
			}
			else if (eventType == DomainObject.DO_OBJECT_RESTORED ||
				eventType == VTChangeManager.DOCR_VT_MATCH_SET_ADDED ||
				eventType == VTChangeManager.DOCR_VT_MATCH_ADDED ||
				eventType == VTChangeManager.DOCR_VT_MATCH_DELETED) {

				reload();
				repaint();
				matchesContextChanged = true;
			}
		}
		if (matchesContextChanged) {
			// Update the context so that toolbar actions fix their enablement.
			tool.contextChanged(this);
		}
	}

	@Override
	public void optionsChanged(Options options) {
		// do nothing
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		// Do nothing since the one to many match table doesn't need to respond to the mark-up that is selected.
	}

//==================================================================================================
// FilterDialogModel Methods
//==================================================================================================	

	@Override
	public void addFilter(Filter<VTMatch> filter) {
		filter.addFilterStatusListener(refilterListener);
		filters.add(filter);
		oneToManyTableModel.addFilter(filter);
	}

	/** Forces a refilter, even though filtering operations may be disabled */
	@Override
	public void forceRefilter() {
		oneToManyTableModel.reFilter();
	}

	@Override
	public void dialogVisibilityChanged(boolean isVisible) {
		if (!isVisible) {
			ancillaryFilterButton.setSelected(false);
		}
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

	private class MatchThreadedTablePanel extends GhidraThreadedTablePanel<VTMatch> {
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

			private TableCellRenderer renderer = new MatchTableRenderer();

			@Override
			public TableCellRenderer getCellRenderer(int row, int col) {
				// special composite renderer
				return renderer;
			}
		}
	}
}
