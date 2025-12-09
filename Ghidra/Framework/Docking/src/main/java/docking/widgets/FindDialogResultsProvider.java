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
package docking.widgets;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.widgets.search.SearchLocationContext;
import docking.widgets.search.SearchResults;
import docking.widgets.table.*;
import docking.widgets.table.actions.DeleteTableRowAction;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class FindDialogResultsProvider extends ComponentProvider
		implements TableModelListener {

	private static final String OWNER_NAME = "Search";

	private SearchResults searchResults;

	private JPanel componentPanel;
	private FindResultsModel model;
	private GTable table;
	private GTableFilterPanel<SearchLocation> filterPanel;

	private DockingAction removeItemsAction;

	FindDialogResultsProvider(Tool tool, String title, String subTitle,
			SearchResults searchResults) {

		super(tool, "Find All", OWNER_NAME);
		this.searchResults = searchResults;

		this.model = new FindResultsModel(searchResults);
		setTransient();
		setTitle(title + subTitle);
		setSubTitle(subTitle);
		setWindowMenuGroup(title);

		componentPanel = buildMainPanel();
		updateTitle();

		addToTool();
		installRemoveItemsAction();

		model.addTableModelListener(this);

		setVisible(true);
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		table = new GTable(model);
		table.setHTMLRenderingEnabled(true);
		filterPanel = new GTableFilterPanel<>(table, model);
		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			getTool().contextChanged(FindDialogResultsProvider.this);
		});

		table.setActionsEnabled(true);

		// add row listener to go to the field for that row when the user arrows 
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		selectionModel.addListSelectionListener(lse -> {
			if (lse.getValueIsAdjusting()) {
				return;
			}

			setSearchLocationFromRow();
		});

		// this listener works around the case where the user clicks and already selected row
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() < 2) {
					return;
				}

				setSearchLocationFromRow();
			}
		});

		panel.add(new JScrollPane(table), BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		return panel;
	}

	private void setSearchLocationFromRow() {
		int row = table.getSelectedRow();
		if (row == -1) {
			searchResults.setActiveLocation(null);
			return;
		}

		SearchLocation location = model.getRowObject(row);
		searchResults.setActiveLocation(location);
	}

	public void installRemoveItemsAction() {
		if (removeItemsAction != null) {
			return;
		}

		removeItemsAction = new DeleteTableRowAction(table, OWNER_NAME) {
			@Override
			protected void removeSelectedItems() {

				int[] rows = table.getSelectedRows();
				List<Object> itemsToRemove = new ArrayList<>();
				for (int row : rows) {
					itemsToRemove.add(model.getRowObject(row));
				}

				removeRowObjects(model, itemsToRemove);

				// put some selection back
				int restoreRow = rows[0];
				selectRow(model, restoreRow);
			}

			@Override
			protected void removeRowObjects(TableModel tm, List<Object> itemsToRemove) {
				model.remove(itemsToRemove);
			}
		};

		getTool().addLocalAction(this, removeItemsAction);
	}

	private String generateSubTitle() {
		StringBuilder buffer = new StringBuilder();
		String filteredText = "";
		if (filterPanel.isFiltered()) {
			filteredText = " of " + filterPanel.getUnfilteredRowCount();
		}

		int n = model.getRowCount();
		if (n == 1) {
			buffer.append("    (1 entry").append(filteredText).append(")");
		}
		else if (n > 1) {
			buffer.append("    (").append(n).append(" entries").append(filteredText).append(")");
		}
		return buffer.toString();
	}

	@Override
	public void closeComponent() {
		searchResults.dispose();

		super.closeComponent();

		filterPanel.dispose();
	}

	@Override
	public JComponent getComponent() {
		return componentPanel;
	}

	@Override
	public void componentActivated() {
		searchResults.activate();

		setSearchLocationFromRow();
	}

	@Override
	public void componentDeactived() {
		// We don't want this, as the user may wish to click around in the text pane and keep the 
		// highlights, which this call would break.
		// searchResults.deactivate();
	}

	@Override
	public void tableChanged(TableModelEvent ev) {
		updateTitle();
	}

	private void updateTitle() {
		setSubTitle(generateSubTitle());
	}

	public GTable getTable() {
		return table;
	}

	// for testing
	public List<SearchLocation> getResults() {
		return new ArrayList<>(model.getModelData());
	}

	private class FindResultsModel extends GDynamicColumnTableModel<SearchLocation, Object> {

		private List<SearchLocation> data;

		FindResultsModel(SearchResults results) {
			super(new ServiceProviderStub());
			this.data = results.getLocations();
		}

		void remove(List<Object> itemsToRemove) {
			for (Object object : itemsToRemove) {
				data.remove(object);
			}
			fireTableDataChanged();
		}

		@Override
		public List<SearchLocation> getModelData() {
			return data;
		}

		@Override
		protected TableColumnDescriptor<SearchLocation> createTableColumnDescriptor() {

			TableColumnDescriptor<SearchLocation> descriptor =
				new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new LineNumberColumn(), 1, true);
			descriptor.addVisibleColumn(new ContextColumn());
			return descriptor;
		}

		@Override
		public String getName() {
			return "Find All Results";
		}

		@Override
		public Object getDataSource() {
			return null;
		}

		private class LineNumberColumn
				extends AbstractDynamicTableColumnStub<SearchLocation, Integer> {

			@Override
			public Integer getValue(SearchLocation rowObject, Settings settings,
					ServiceProvider sp) throws IllegalArgumentException {
				return rowObject.getLineNumber();
			}

			@Override
			public String getColumnName() {
				return "Line";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 75;
			}
		}

		private class ContextColumn extends
				AbstractDynamicTableColumnStub<SearchLocation, SearchLocationContext> {

			private GColumnRenderer<SearchLocationContext> renderer = new ContextCellRenderer();

			@Override
			public SearchLocationContext getValue(SearchLocation rowObject,
					Settings settings,
					ServiceProvider sp) throws IllegalArgumentException {

				SearchLocationContext context = rowObject.getContext();
				return context;
			}

			@Override
			public String getColumnName() {
				return "Context";
			}

			@Override
			public GColumnRenderer<SearchLocationContext> getColumnRenderer() {
				return renderer;
			}

			private class ContextCellRenderer
					extends AbstractGColumnRenderer<SearchLocationContext> {

				{
					// the context uses html
					setHTMLRenderingEnabled(true);
				}

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData cellData) {

					// initialize
					super.getTableCellRendererComponent(cellData);

					SearchLocation match = (SearchLocation) cellData.getRowObject();
					SearchLocationContext context = match.getContext();
					String text = context.getBoldMatchingText();
					setText(text);
					return this;
				}

				@Override
				public String getFilterString(SearchLocationContext context, Settings settings) {
					return context.getPlainText();
				}
			}
		}
	}
}
