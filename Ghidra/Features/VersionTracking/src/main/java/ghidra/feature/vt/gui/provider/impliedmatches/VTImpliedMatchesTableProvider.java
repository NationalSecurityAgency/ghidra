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
package ghidra.feature.vt.gui.provider.impliedmatches;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.feature.vt.api.db.DeletedMatch;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.impl.VersionTrackingChangeRecord;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.actions.CreateImpliedMatchAction;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel.*;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.Icons;
import resources.ResourceManager;

public class VTImpliedMatchesTableProvider extends ComponentProviderAdapter
		implements VTControllerListener {

	private static final Icon REFERNCE_FROM_ICON = Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON;
	private static final Icon REFERNCE_TO_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
	private VTController controller;
	private JComponent component;
	private VTImpliedMatchesTableModel impliedMatchTableModel;
	private ListSelectionListener impliedSelectionListener;
	private GTable impliedMatchesTable;
	private GhidraTableFilterPanel<ImpliedMatchWrapperRowObject> filterPanel;

	private ToggleDockingAction showReferenceLocationAction;
	protected boolean showReferenceLocation = true;
	private ToggleDockingAction showReferenceToLocationAction;

	public VTImpliedMatchesTableProvider(VTController controller) {
		super(controller.getTool(), "Version Tracking Implied Matches", VTPlugin.OWNER);
		this.controller = controller;
		controller.addListener(this);
		setWindowGroup(VTPlugin.WINDOW_GROUP);
		setIcon(ResourceManager.loadImage("images/application_view_detail.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIntraGroupPosition(WindowPosition.STACK);

		component = createComponent();
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Implied_Matches_Table"));
		createActions();
		addToTool();

		setVisible(true);
	}

	private JComponent createComponent() {
		JPanel panel = new JPanel(new BorderLayout());

		GThreadedTablePanel<ImpliedMatchWrapperRowObject> tablePanel =
			createImpliedMatchTablePanel();
		filterPanel = new GhidraTableFilterPanel<>(impliedMatchesTable, impliedMatchTableModel);
		panel.add(tablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);
		return panel;
	}

	private void createActions() {
		showReferenceLocationAction =
			new ToggleDockingAction("Show Reference Locations", VTPlugin.OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					showReferenceLocation = true;
					showReferenceToLocationAction.setSelected(false);
					navigateSelectedItem();
				}
			};
		showReferenceLocationAction.setSelected(true);
		showReferenceLocationAction.setToolBarData(new ToolBarData(REFERNCE_FROM_ICON, "2"));
		showReferenceLocationAction.setDescription(
			"<html>Sets table selection navigation mode to " +
				"navigate <br> to <b>Source</b> and <b>Dest Reference Address</b> columns");
		showReferenceLocationAction.setHelpLocation(
			new HelpLocation("VersionTrackingPlugin", "Navigate_References"));
		addLocalAction(showReferenceLocationAction);

		showReferenceToLocationAction =
			new ToggleDockingAction("Show Locations Reference", VTPlugin.OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					showReferenceLocation = false;
					showReferenceLocationAction.setSelected(false);
					navigateSelectedItem();
				}
			};
		showReferenceToLocationAction.setToolBarData(new ToolBarData(REFERNCE_TO_ICON, "2"));
		showReferenceToLocationAction.setDescription(
			"<html>Sets table selection navigation mode to " +
				"navigate <br> to <b>Source</b> and <b>Dest Address</b> columns");
		showReferenceToLocationAction.setHelpLocation(
			new HelpLocation("VersionTrackingPlugin", "Navigate_Match"));
		addLocalAction(showReferenceToLocationAction);

		DockingAction action = new CreateImpliedMatchAction(controller, this);
		addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void componentHidden() {
		// matchSelected() and sessionChanged() check isVisible before responding.
	}

	@Override
	public void componentShown() {
		impliedMatchTableModel.sessionChanged();
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		// don't care
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		if (!isVisible()) {
			// Don't respond at all since not visible.
			// Instead calls sessionChanged() when component is shown.
			return;
		}
		impliedMatchTableModel.reload();
	}

	@Override
	public void optionsChanged(Options options) {
		// don't care
	}

	public void readConfigState(SaveState saveState) {
		// don't care
	}

	public void writeConfigState(SaveState saveState) {
		// don't care
	}

	@Override
	public void sessionChanged(VTSession session) {
		if (!isVisible()) {
			// Don't respond at all since not visible.
			// Instead calls sessionChanged() when component is shown.
			return;
		}
		impliedMatchTableModel.sessionChanged();
	}

	@Override
	public void disposed() {
		if (impliedMatchesTable == null) {
			return;
		}

		// must remove the listener first to avoid callback whilst we are disposing
		ListSelectionModel selectionModel = impliedMatchesTable.getSelectionModel();
		selectionModel.removeListSelectionListener(impliedSelectionListener);

		impliedMatchesTable.dispose();
		impliedMatchTableModel.dispose();
		filterPanel.dispose();
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}

		boolean matchesContextChanged = false;
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			int eventType = doRecord.getEventType();

			if (eventType == VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED ||
				eventType == VTChangeManager.DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED) {
				matchesContextChanged = true;
			}
			else if (eventType == DomainObject.DO_OBJECT_RESTORED ||
				eventType == VTChangeManager.DOCR_VT_MATCH_SET_ADDED) {
				reload();
				matchesContextChanged = true;
			}
			else if (eventType == VTChangeManager.DOCR_VT_MATCH_ADDED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				impliedMatchTableModel.matchAdded((VTMatch) vtRecord.getNewValue());
				matchesContextChanged = true;
			}
			else if (eventType == VTChangeManager.DOCR_VT_MATCH_DELETED) {
				VersionTrackingChangeRecord vtRecord = (VersionTrackingChangeRecord) doRecord;
				impliedMatchTableModel.matchDeleted((DeletedMatch) vtRecord.getOldValue());
				matchesContextChanged = true;
			}
		}
		if (matchesContextChanged) {
			// Update the context so that toolbar actions fix their enablement.
			impliedMatchesTable.repaint();
			tool.contextChanged(this);
		}
	}

	private void reload() {
		impliedMatchTableModel.clear();
		impliedMatchTableModel.reload();
	}

	private GThreadedTablePanel<ImpliedMatchWrapperRowObject> createImpliedMatchTablePanel() {
		impliedMatchTableModel = new VTImpliedMatchesTableModel(controller);
		GhidraThreadedTablePanel<ImpliedMatchWrapperRowObject> impliedMatchTablePanel =
			new GhidraThreadedTablePanel<>(impliedMatchTableModel);

		impliedMatchesTable = impliedMatchTablePanel.getTable();

		impliedSelectionListener = e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			navigateSelectedItem();
			tool.contextChanged(VTImpliedMatchesTableProvider.this);
		};
		ListSelectionModel selectionModel = impliedMatchesTable.getSelectionModel();
		selectionModel.addListSelectionListener(impliedSelectionListener);

		impliedMatchTableModel.addTableModelListener(e -> {
			int filteredCount = impliedMatchTableModel.getRowCount();
			int unfilteredCount = impliedMatchTableModel.getUnfilteredRowCount();

			String sessionName = controller.getVersionTrackingSessionName();
			StringBuffer buffy = new StringBuffer();
			buffy.append("[Session: ").append(sessionName).append("] ");
			buffy.append('-').append(filteredCount).append(" matches");
			if (filteredCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(')');
			}

			setSubTitle(buffy.toString());
		});

		// setup the renderers
		TableColumnModel columnModel = impliedMatchesTable.getColumnModel();

		int sourceLabelColumnIndex =
			impliedMatchTableModel.getColumnIndex(SourceLabelTableColumn.class);
		TableColumn sourceLabelColumn = columnModel.getColumn(sourceLabelColumnIndex);
		sourceLabelColumn.setCellRenderer(
			new VTSymbolRenderer(controller.getServiceProvider(), impliedMatchesTable));

		int destinationLabelColumnIndex =
			impliedMatchTableModel.getColumnIndex(DestinationLabelTableColumn.class);
		TableColumn destinationLabelColumn = columnModel.getColumn(destinationLabelColumnIndex);
		destinationLabelColumn.setCellRenderer(
			new VTSymbolRenderer(controller.getServiceProvider(), impliedMatchesTable));

		int statusColumnIndex = impliedMatchTableModel.getColumnIndex(StatusTableColumn.class);
		TableColumn statusColumn = columnModel.getColumn(statusColumnIndex);
		statusColumn.setCellRenderer(new MatchStatusRenderer());

		// override the default behavior so we see our columns in their preferred size
		Dimension size = impliedMatchesTable.getPreferredScrollableViewportSize();
		Dimension preferredSize = impliedMatchesTable.getPreferredSize();

		// ...account for the scroll bar width
		JScrollBar scrollBar = new JScrollBar(Adjustable.VERTICAL);
		Dimension scrollBarSize = scrollBar.getMinimumSize();
		size.width = preferredSize.width + scrollBarSize.width;
		impliedMatchesTable.setPreferredScrollableViewportSize(size);

		return impliedMatchTablePanel;
	}

	@SuppressWarnings("unchecked")
	protected void navigateSelectedItem() {
		if (impliedMatchesTable.getSelectedRowCount() != 1) {
			return;
		}

		// Note: we get out the model here in case it has been wrapped by one of the filters
		RowObjectTableModel<ImpliedMatchWrapperRowObject> model =
			(RowObjectTableModel<ImpliedMatchWrapperRowObject>) impliedMatchesTable.getModel();
		int selectedRow = impliedMatchesTable.getSelectedRow();
		VTImpliedMatchInfo impliedMatch = model.getRowObject(selectedRow);
		if (showReferenceLocation) {
			controller.gotoSourceLocation(impliedMatch.getSourceReferenceLocation());
			controller.gotoDestinationLocation(impliedMatch.getDestinationReferenceLocation());
		}
		else {
			ProgramLocation sourceLoc =
				new ProgramLocation(controller.getSourceProgram(), impliedMatch.getSourceAddress());
			ProgramLocation destinationLoc = new ProgramLocation(controller.getDestinationProgram(),
				impliedMatch.getDestinationAddress());
			controller.gotoSourceLocation(sourceLoc);
			controller.gotoDestinationLocation(destinationLoc);
		}
	}

	@SuppressWarnings("unchecked")
	public List<VTMatch> getSelectedMatches() {
		// Note: we get out the model here in case it has been wrapped by one of the filters
		RowObjectTableModel<ImpliedMatchWrapperRowObject> model =
			(RowObjectTableModel<ImpliedMatchWrapperRowObject>) impliedMatchesTable.getModel();
		List<VTMatch> list = new ArrayList<>();
		int[] selectedRows = impliedMatchesTable.getSelectedRows();
		for (int row : selectedRows) {
			ImpliedMatchWrapperRowObject rowObject = model.getRowObject(row);
			VTMatch match = rowObject.getMatch();
			if (match != null) {
				list.add(match);
			}
		}
		return list;
	}

	@SuppressWarnings("unchecked")
	public List<VTImpliedMatchInfo> getSelectedImpliedMatches() {
		// Note: we get out the model here in case it has been wrapped by one of the filters
		RowObjectTableModel<ImpliedMatchWrapperRowObject> model =
			(RowObjectTableModel<ImpliedMatchWrapperRowObject>) impliedMatchesTable.getModel();
		List<VTImpliedMatchInfo> list = new ArrayList<>();
		int[] selectedRows = impliedMatchesTable.getSelectedRows();
		for (int row : selectedRows) {
			ImpliedMatchWrapperRowObject rowObject = model.getRowObject(row);
			VTMatch match = rowObject.getMatch();
			if (match == null) {
				list.add(rowObject);
			}
		}
		return list;
	}
}
