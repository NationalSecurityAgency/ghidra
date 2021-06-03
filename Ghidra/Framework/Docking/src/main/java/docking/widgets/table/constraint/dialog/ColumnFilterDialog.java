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
package docking.widgets.table.constraint.dialog;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.CompoundBorder;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.table.columnfilter.*;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import generic.util.WindowUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;
import utility.function.Callback;

/**
 * Dialog for creating and editing column table filters.
 *
 * @param <R> the row type of the table being filtered.
 */
public class ColumnFilterDialog<R> extends DialogComponentProvider
		implements TableFilterDialogModelListener {

	private final ColumnFilterDialogModel<R> filterModel;

	private JPanel filterPanelContainer;
	private List<ColumnFilterPanel> filterPanels = new ArrayList<>();

	private Callback closeCallback;
	private GTableFilterPanel<R> gTableFilterPanel;

	private JPanel bottomPanel;

	private JTable table;
	private RowObjectFilterModel<R> tableModel;

	/**
	 * Constructor
	 *
	 * @param gTableFilterPanel the GTableFilterPanel that launched this dialog.
	 * @param table the table being filtered.
	 * @param tableModel the table model.
	 */
	public ColumnFilterDialog(GTableFilterPanel<R> gTableFilterPanel, JTable table,
			RowObjectFilterModel<R> tableModel) {
		super("Table Column Filters", WindowUtilities.areModalDialogsVisible());
		this.gTableFilterPanel = gTableFilterPanel;
		this.table = table;
		this.tableModel = tableModel;

		ColumnBasedTableFilter<R> columnTableFilter = gTableFilterPanel.getColumnTableFilter();

		filterModel =
			new ColumnFilterDialogModel<>(tableModel, table.getColumnModel(), columnTableFilter);
		filterModel.addListener(this);

		setHelpLocation(new HelpLocation("Trees", "Column_Filters"));
		addWorkPanel(buildMainPanel());

		addApplyButton();
		applyButton.setText("Apply Filter");
		addDismissButton();
		addClearFilterButton();

		addToolbarActions();

		setPreferredSize(1000, 500);
		updateStatus();
	}

	public static <R> boolean hasFilterableColumns(JTable table,
			RowObjectFilterModel<R> model) {
		return !ColumnFilterDialogModel.getAllColumnFilterData(model, table.getColumnModel())
				.isEmpty();
	}

	private void addClearFilterButton() {
		JButton button = new JButton("Clear Filter");
		button.addActionListener(e -> clearFilter());
		button.setToolTipText("Clears any applied column filter and clears the dialog.");
		addButton(button);
	}

	String getTableName() {
		return tableModel.getName();
	}

	private void addToolbarActions() {

		DockingAction saveAction = new DockingAction("Save", "Filter") {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !filterModel.getFilterRows().isEmpty() && filterModel.isValid();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				saveFilter();
			}
		};
		saveAction.setHelpLocation(new HelpLocation("Trees", "Save_Filter"));
		saveAction.setDescription("Save Filter");
		saveAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/disk.png")));
		addAction(saveAction);

		DockingAction loadAction = new DockingAction("Load", "Filter") {
			@Override
			public void actionPerformed(ActionContext context) {
				loadFilter();
			}
		};
		loadAction.setDescription("Load Filter");
		loadAction.setHelpLocation(new HelpLocation("Trees", "Load_Filter"));
		loadAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/openSmallFolder.png")));
		addAction(loadAction);
	}

	private void saveFilter() {
		ColumnFilterSaveManager<R> filterSaveManager = new ColumnFilterSaveManager<>(
			gTableFilterPanel, table, tableModel, filterModel.getDataSource());
		ColumnBasedTableFilter<R> filter = filterModel.getTableColumnFilter();

		String defaultName = new Date().toString();
		InputDialog dialog = new InputDialog("Save Filter", "Filter Name: ", defaultName, d -> {
			String name = d.getValue();
			if (StringUtils.isBlank(name)) {
				d.setStatusText("Please enter a name!");
				return false;
			}
			else if (filterSaveManager.containsFilterWithName(name)) {
				d.setStatusText("Filter already exists with that name!");
				return false;
			}
			return true;
		});

		DockingWindowManager.showDialog(this.getComponent(), dialog);
		if (dialog.isCanceled()) {
			return;
		}

		String filterName = dialog.getValue().trim();
		filter = filter.copy();
		filter.setName(filterName);
		filterSaveManager.addFilter(filter);
		filterSaveManager.save();
		gTableFilterPanel.updateSavedFilters(filter, true);
		filterModel.setFilter(filter);
	}

	private void loadFilter() {
		ColumnFilterSaveManager<R> filterSaveManager = new ColumnFilterSaveManager<>(
			gTableFilterPanel, table, tableModel, filterModel.getDataSource());
		List<ColumnBasedTableFilter<R>> savedFilters = filterSaveManager.getSavedFilters();
		if (savedFilters.isEmpty()) {
			Msg.showInfo(this, getComponent(), "No Saved Filters",
				"No saved filters exist for this table.");
			return;
		}

		ColumnFilterArchiveDialog<R> archiveDialog =
			new ColumnFilterArchiveDialog<>(this, filterSaveManager, getTableName());

		DockingWindowManager.showDialog(getComponent(), archiveDialog);

		ColumnBasedTableFilter<R> selectedFilter = archiveDialog.getSelectedColumnFilter();
		if (selectedFilter != null) {
			filterModel.setFilter(selectedFilter);
		}
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildFilterPanelContainer(), BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildFilterPanelContainer() {

		filterPanelContainer = new JPanel(new VerticalLayout(4));
		filterPanelContainer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		JScrollPane jScrollPane = new JScrollPane(filterPanelContainer);

		jScrollPane.setColumnHeaderView(buildHeaderPanel());

		loadFilterRows();

		return jScrollPane;
	}

	private JComponent getBottomPanel() {
		if (bottomPanel == null) {
			bottomPanel = new JPanel(new BorderLayout());
			JPanel innerPanel = new JPanel(new VerticalLayout(3));

			JButton addAndConditionButton =
				new JButton("Add AND condition", ResourceManager.loadImage("images/Plus.png"));

			addAndConditionButton.addActionListener(e -> addFilterCondition(LogicOperation.AND));
			addAndConditionButton.setEnabled(true);

			JButton addOrConditionButton =
				new JButton("Add  OR   condition", ResourceManager.loadImage("images/Plus.png"));

			addOrConditionButton.setHorizontalAlignment(SwingConstants.LEFT);
			addOrConditionButton.addActionListener(e -> addFilterCondition(LogicOperation.OR));
			addOrConditionButton.setEnabled(true);

			innerPanel.add(addAndConditionButton);
			innerPanel.add(addOrConditionButton);
			bottomPanel.add(innerPanel, BorderLayout.EAST);
		}

		return bottomPanel;
	}

	private void updateDialogTitle() {
		StringBuilder sb = new StringBuilder();
		if (tableModel.getName() != null) {
			sb.append(tableModel.getName()).append(" ");
		}
		sb.append("Column Filter");

		ColumnBasedTableFilter<R> filter = filterModel.getTableColumnFilter();
		if (filter != null && filter.getName() != null) {
			sb.append(": ").append(filter.getName());
		}

		setTitle(sb.toString());
	}

	@Override
	public void close() {

		// Before closing, check if user made any changes that haven't been applied...
		if (canClose()) {
			super.close();
		}
	}

	private boolean canClose() {
		// Possible filter/UI states:
		//
		// * Dialog state matches applied filter - proceed to close
		// * Dialog state is different from applied filter and valid - prompt to apply filter.
		// * Dialog state is different from applied filter, but invalid - prompt if should really close

		if (!filterModel.hasUnappliedChanges()) {
			return true;
		}
		if (dialogHasValidFilter()) {
			return promptToApplyFilter();
		}
		return promptToCloseAndLoseChanges();
	}

	/**
	 * Ask the user if they want to apply the filter changes before closing. If they agree, then
	 * apply the filter.
	 *
	 * @return true if they don't cancel, false if they answer yes or no.
	 */
	private boolean promptToApplyFilter() {
		int choice = OptionDialog.showOptionDialog(null, "Unapplied Changes",
			"You have unapplied changes that will be lost!\n" +
				"Do you want to apply them before you exit?",
			"Apply Changes", "Discard Changes", OptionDialog.QUESTION_MESSAGE);

		if (choice == OptionDialog.OPTION_ONE) {
			applyFilter();
		}
		return choice != OptionDialog.CANCEL_OPTION;
	}

	/**
	 * Ask the user if they want to continue or lose their filter changes.
	 *
	 * @return true to close the dialog and lose the changes, false to abort the close.
	 */
	private boolean promptToCloseAndLoseChanges() {

		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Unapplied Changes", "Exit dialog and discard changes?", "Discard Changes");

		return choice != OptionDialog.CANCEL_OPTION;
	}

	private boolean dialogHasValidFilter() {
		return filterModel.getTableColumnFilter() != null;
	}

	@Override
	protected void dialogClosed() {
		filterModel.dispose();
		if (closeCallback != null) {
			closeCallback.call();
		}
	}

	@Override
	protected void okCallback() {
		applyFilter();
		close();
	}

	@Override
	protected void applyCallback() {
		applyFilter();
	}

	private void clearFilter() {
		this.gTableFilterPanel.setColumnTableFilter(null);
		filterModel.clear();
		updateStatus();
	}

	private void applyFilter() {
		ColumnBasedTableFilter<R> tableColumnFilter = filterModel.getTableColumnFilter();
		filterModel.setCurrentlyAppliedFilter(tableColumnFilter);
		this.gTableFilterPanel.setColumnTableFilter(tableColumnFilter);
	}

	private void loadFilterRows() {
		filterPanelContainer.removeAll();
		filterPanels.clear();

		List<DialogFilterRow> filterRows = filterModel.getFilterRows();
		for (int i = 0; i < filterRows.size(); i++) {
			DialogFilterRow filterRow = filterRows.get(i);
			ColumnFilterPanel panel = new ColumnFilterPanel(filterRow);
			if (i != 0) {
				filterPanelContainer.add(
					createLogicalOperationLabel(filterRow.getLogicOperation()));
			}
			filterPanelContainer.add(panel);
			filterPanels.add(panel);
		}
		filterPanelContainer.add(getBottomPanel());
		filterPanelContainer.getParent().validate();
	}

	private GLabel createLogicalOperationLabel(LogicOperation op) {
		GLabel label = new GLabel("<" + op + ">", SwingConstants.CENTER);
		label.setForeground(Color.GRAY);
		return label;
	}

	private JComponent buildHeaderPanel() {
		JPanel headerPanel = new JPanel(new FilterPanelLayout(200, 0));

		headerPanel.add(new GLabel("Table Column", SwingConstants.CENTER));
		headerPanel.add(new GLabel("Filter", SwingConstants.CENTER));
		headerPanel.add(new GLabel("Filter Value", SwingConstants.CENTER));

		headerPanel.setBorder(new CompoundBorder(
			BorderFactory.createMatteBorder(0, 0, 1, 0, Color.DARK_GRAY.brighter().brighter()),
			BorderFactory.createEmptyBorder(4, 0, 4, 0)));
		return headerPanel;
	}

	private void addFilterCondition(LogicOperation logicalOperation) {
		filterModel.createFilterRow(logicalOperation);
		scrollFilterPanelToBottom();
	}

	private void scrollFilterPanelToBottom() {

		Container filterPanelParent = SwingUtilities.getUnwrappedParent(filterPanelContainer);
		if (filterPanelParent instanceof JViewport) {

			Rectangle filterPanelBounds = filterPanelContainer.getBounds();

			Rectangle bottomOfContainer = new Rectangle(filterPanelBounds.x,
				filterPanelBounds.height, filterPanelBounds.width, 1);

			((JViewport) filterPanelParent).scrollRectToVisible(bottomOfContainer);
		}
	}

	void updateStatus() {
		setStatusText(getStatusMessage());

		boolean isValid = filterModel.isValid();
		setOkEnabled(isValid);
		setApplyEnabled(isValid);

		ActionContext context = new ActionContext();

		for (DockingActionIf action : getActions()) {
			action.setEnabled(action.isEnabledForContext(context));
		}
		updateDialogTitle();
	}

	public void filterChanged(ColumnBasedTableFilter<R> newFilter) {
		if (Objects.equals(newFilter, filterModel.getTableColumnFilter())) {
			return;
		}
		getComponent().requestFocus();  // work around for java parenting bug where dialog appears behind
		if (filterModel.hasUnappliedChanges()) {
			int result = OptionDialog.showYesNoDialog(getComponent(), "Filter Changed",
				"The filter has been changed externally.\n" +
					" Do you want to update this editor and lose your current changes?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		filterModel.setFilter(newFilter);
	}

	private String getStatusMessage() {
		if (filterModel.isEmpty()) {
			return "Please add a filter condition!";
		}
		if (!filterModel.isValid()) {
			return "One or more filter values are invalid!";
		}
		return "";
	}

	/**
	 * The callback to call when the "Apply" or "Ok" button is pressed.
	 *
	 * @param callback the callback to execute to apply the filter.
	 */
	public void setCloseCallback(Callback callback) {
		closeCallback = callback;
	}

//==================================================================================================
// TableFilterDialogModelListener methods
//==================================================================================================

	@Override
	public void editorValueChanged(ColumnConstraintEditor<?> editor) {
		updateStatus();
	}

	@Override
	public void structureChanged() {
		loadFilterRows();
		updateStatus();
	}

	void filterRemoved(ColumnBasedTableFilter<R> filter) {
		gTableFilterPanel.updateSavedFilters(filter, false);

	}


}
