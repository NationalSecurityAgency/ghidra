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
package docking.widgets.table.columnfilter;

import java.util.*;

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.DockingWindowManager;
import docking.menu.*;
import docking.widgets.EventTrigger;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.table.constraint.dialog.ColumnFilterDialog;
import generic.theme.GIcon;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;
import utility.function.Callback;

/**
 * A class that manages column filters for a table.  This includes creating the UI elements that 
 * allow users to build filters, as well as a means to save and restore filters.
 *
 * @param <ROW_OBJECT> the row type
 */
public class ColumnFilterManager<ROW_OBJECT> {

	public static final String FILTER_EXTENSION = ".FilterExtension";
	public static final String FILTER_TEXTFIELD_NAME = "filter.panel.textfield";
	private static final Icon FILTER_ON_ICON = new GIcon("icon.widget.filterpanel.filter.on");
	private static final Icon FILTER_OFF_ICON = new GIcon("icon.widget.filterpanel.filter.off");
	private static final Icon APPLY_FILTER_ICON = Icons.OPEN_FOLDER_ICON;
	private static final Icon CLEAR_FILTER_ICON = Icons.DELETE_ICON;

	private MultiStateDockingAction<ColumnBasedTableFilter<ROW_OBJECT>> columnFilterAction;
	private JButton configureButton;
	private ColumnFilterDialog<ROW_OBJECT> columnFilterDialog;

	private ColumnBasedTableFilter<ROW_OBJECT> lastUsedFilter;
	private ColumnBasedTableFilter<ROW_OBJECT> currentFilter;
	private List<ColumnBasedTableFilter<ROW_OBJECT>> savedFilters = new ArrayList<>();

	private JTable table;
	private RowObjectFilterModel<ROW_OBJECT> rowObjectFilterModel;
	private String preferenceKey;
	private Callback filterChangedCallback;

	public ColumnFilterManager(JTable table, RowObjectFilterModel<ROW_OBJECT> rowObjectFilterModel,
			String preferenceKey, Callback filterChangedCallback) {
		this.table = Objects.requireNonNull(table);
		this.rowObjectFilterModel = Objects.requireNonNull(rowObjectFilterModel);
		this.preferenceKey = Objects.requireNonNull(preferenceKey);
		this.filterChangedCallback = Objects.requireNonNull(filterChangedCallback);

		configureButton = buildColumnFilterStateButton();

		DockingWindowManager.registerComponentLoadedListener(table,
			(windowManager, provider) -> initializeSavedFilters());
	}

	private void initializeSavedFilters() {
		TableModel model = table.getModel();
		if (!(model instanceof GDynamicColumnTableModel)) {
			return;
		}

		@SuppressWarnings("unchecked")
		GDynamicColumnTableModel<ROW_OBJECT, ?> dynamicModel =
			(GDynamicColumnTableModel<ROW_OBJECT, ?>) model;

		ColumnFilterSaveManager<ROW_OBJECT> saveManager = new ColumnFilterSaveManager<>(
			preferenceKey, table, dynamicModel, dynamicModel.getDataSource());

		savedFilters = saveManager.getSavedFilters();
		Collections.reverse(savedFilters);
		updateColumnFilterButton();
	}

	public ColumnBasedTableFilter<ROW_OBJECT> getCurrentFilter() {
		return currentFilter;
	}

	public JButton getConfigureButton() {
		return configureButton;
	}

	public String getPreferenceKey() {
		return preferenceKey;
	}

	public void setFilter(ColumnBasedTableFilter<ROW_OBJECT> newFilter) {
		if (Objects.equals(newFilter, this.currentFilter)) {
			return;
		}

		if (currentFilter != null && !currentFilter.isSaved()) {
			lastUsedFilter = currentFilter;
		}
		currentFilter = newFilter;

		updateColumnFilterButton();
		if (columnFilterDialog != null) {
			columnFilterDialog.filterChanged(newFilter);
		}

		filterChangedCallback.call();
	}

	public void updateSavedFilters(ColumnBasedTableFilter<ROW_OBJECT> filter, boolean add) {

		if (add) {
			ArrayList<ColumnBasedTableFilter<ROW_OBJECT>> list = new ArrayList<>();
			list.add(filter);
			list.addAll(savedFilters);
			savedFilters = list;
			if (filter.isEquivalent(currentFilter)) {
				setFilter(filter);
			}
		}
		else {
			savedFilters.remove(filter);
		}

		updateColumnFilterButton();

		filterChangedCallback.call();
	}

	public void dispose() {
		if (columnFilterDialog != null) {
			columnFilterDialog.dispose();
			columnFilterDialog = null;
		}

		filterChangedCallback = Callback.dummy();
	}

	private JButton buildColumnFilterStateButton() {

		columnFilterAction =
			new NonToolbarMultiStateAction<>("Column Filter", "GTableFilterPanel") {

				@Override
				public void actionStateChanged(
						ActionState<ColumnBasedTableFilter<ROW_OBJECT>> newActionState,
						EventTrigger trigger) {
					if (trigger != EventTrigger.GUI_ACTION) {
						return;
					}
					ColumnFilterActionState state = (ColumnFilterActionState) newActionState;
					state.performAction();
				}

				@Override
				protected void actionPerformed() {
					showFilterDialog(rowObjectFilterModel);
				}

			};

		HelpLocation helpLocation = new HelpLocation("Trees", "Column_Filters");
		columnFilterAction.setHelpLocation(helpLocation);

		updateColumnFilterButton();
		JButton button = columnFilterAction.createButton();
		DockingWindowManager.getHelpService().registerHelp(button, helpLocation);

		return button;
	}

	private void updateColumnFilterButton() {
		List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> list = getActionStates();
		columnFilterAction.setActionStates(list);
	}

	private List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> getActionStates() {
		List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> list = new ArrayList<>();
		if (currentFilter == null) {
			list.add(new CreateFilterActionState());
		}
		else {
			list.add(new EditFilterActionState(currentFilter));
			list.add(new ClearFilterActionState());
		}
		if (lastUsedFilter != null) {
			list.add(new ApplyLastUsedActionState(lastUsedFilter));
		}
		for (ColumnBasedTableFilter<ROW_OBJECT> filter : savedFilters) {
			list.add(new ApplyFilterActionState(filter));
		}
		return list;
	}

	private void showFilterDialog(RowObjectFilterModel<ROW_OBJECT> tableModel) {
		if (columnFilterDialog == null) {
			if (ColumnFilterDialog.hasFilterableColumns(table, tableModel)) {
				columnFilterDialog = new ColumnFilterDialog<>(this, table, rowObjectFilterModel);
			}
			else {
				Msg.showError(this, null, "Column Filter Error",
					"This table contains no filterable columns!");
				return;
			}

		}

		DockingWindowManager.showDialog(table, columnFilterDialog);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private abstract class ColumnFilterActionState
			extends ActionState<ColumnBasedTableFilter<ROW_OBJECT>> {

		ColumnFilterActionState(String name, Icon icon, ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super(name, icon, filter);
		}

		abstract void performAction();
	}

	String getFilterName(ColumnBasedTableFilter<ROW_OBJECT> filter) {
		String filterName = filter.getName();
		return filterName == null ? "Unsaved" : filterName;
	}

	private class ClearFilterActionState extends ColumnFilterActionState {
		public ClearFilterActionState() {
			super("Clear Filter", CLEAR_FILTER_ICON, null);
		}

		@Override
		void performAction() {
			setFilter(null);
		}
	}

	private class CreateFilterActionState extends ColumnFilterActionState {
		public CreateFilterActionState() {
			super("Create Column Filter", FILTER_OFF_ICON, null);
		}

		@Override
		void performAction() {
			showFilterDialog(rowObjectFilterModel);
		}
	}

	private class EditFilterActionState extends ColumnFilterActionState {
		public EditFilterActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Edit: " + getFilterName(filter), FILTER_ON_ICON, filter);
		}

		@Override
		void performAction() {
			showFilterDialog(rowObjectFilterModel);
		}
	}

	private class ApplyFilterActionState extends ColumnFilterActionState {
		public ApplyFilterActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Apply: " + getFilterName(filter), APPLY_FILTER_ICON, filter);
		}

		@Override
		void performAction() {
			setFilter(getUserData());
		}
	}

	private class ApplyLastUsedActionState extends ColumnFilterActionState {
		public ApplyLastUsedActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Apply Last Unsaved", FILTER_ON_ICON, filter);
		}

		@Override
		void performAction() {
			setFilter(getUserData());
		}
	}
}
