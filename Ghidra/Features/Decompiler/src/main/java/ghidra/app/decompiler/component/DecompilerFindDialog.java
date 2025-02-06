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
package ghidra.app.decompiler.component;

import java.awt.Component;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.ListSelectionModel;

import docking.DockingWindowManager;
import docking.Tool;
import docking.widgets.FindDialog;
import docking.widgets.SearchLocation;
import docking.widgets.button.GButton;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.table.*;
import ghidra.app.plugin.core.decompile.actions.DecompilerSearchLocation;
import ghidra.app.plugin.core.decompile.actions.DecompilerSearcher;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.query.TableService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.*;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

public class DecompilerFindDialog extends FindDialog {

	private DecompilerPanel decompilerPanel;
	private GButton showAllButton;

	public DecompilerFindDialog(DecompilerPanel decompilerPanel) {
		super("Decompiler Find Text", new DecompilerSearcher(decompilerPanel));
		this.decompilerPanel = decompilerPanel;

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));

		showAllButton = new GButton("Search All");
		showAllButton.addActionListener(e -> showAll());

		// move this button to the end
		removeButton(dismissButton);

		addButton(showAllButton);
		addButton(dismissButton);
	}

	@Override
	protected void enableButtons(boolean b) {
		super.enableButtons(b);
		showAllButton.setEnabled(b);
	}

	private void showAll() {

		String searchText = getSearchText();

		close();

		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		Tool tool = dwm.getTool();
		TableService tableService = tool.getService(TableService.class);
		if (tableService == null) {
			Msg.error(this,
				"Cannot use the Decompiler Search All action without having a TableService " +
					"installed");
			return;
		}

		List<SearchLocation> results = searcher.searchAll(searchText, useRegex());
		if (!results.isEmpty()) {
			// save off searches that find results so users can reuse them later
			storeSearchText(getSearchText());
		}

		Program program = decompilerPanel.getProgram();
		DecompilerFindResultsModel model = new DecompilerFindResultsModel(tool, program, results);

		String title = "Decompiler Search '%s'".formatted(getSearchText());
		String type = "Decompiler Search Results";
		String subMenuName = "Search";
		TableComponentProvider<DecompilerSearchLocation> provider =
			tableService.showTable(title, type, model, subMenuName, null);

		// The Decompiler does not support some of the table's basic actions, such as making
		// selections for a given row, so remove them.
		provider.removeAllActions();
		provider.installRemoveItemsAction();

		GhidraThreadedTablePanel<DecompilerSearchLocation> panel = provider.getThreadedTablePanel();
		GhidraTable table = panel.getTable();

		// add row listener to go to the field for that row
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(lse -> {
			if (lse.getValueIsAdjusting()) {
				return;
			}

			int row = table.getSelectedRow();
			if (row == -1) {
				searcher.highlightSearchResults(null);
				return;
			}

			DecompilerSearchLocation location = model.getRowObject(row);

			notifySearchHit(location);
		});

		// add listener to table closed to clear highlights
		provider.setClosedCallback(() -> decompilerPanel.setSearchResults(null));

		// set the tab text to the short and descriptive search term
		provider.setTabText("'%s'".formatted(getSearchText()));
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class DecompilerFindResultsModel
			extends GhidraProgramTableModel<DecompilerSearchLocation> {

		private List<DecompilerSearchLocation> searchLocations;

		DecompilerFindResultsModel(ServiceProvider sp, Program program,
				List<SearchLocation> searchLocations) {
			super("Decompiler Search All Results", sp, program, null);
			this.searchLocations = searchLocations.stream()
					.map(l -> (DecompilerSearchLocation) l)
					.collect(Collectors.toList());
		}

		@Override
		protected TableColumnDescriptor<DecompilerSearchLocation> createTableColumnDescriptor() {

			TableColumnDescriptor<DecompilerSearchLocation> descriptor =
				new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new LineNumberColumn(), 1, true);
			descriptor.addVisibleColumn(new ContextColumn());
			return descriptor;
		}

		@Override
		protected void doLoad(Accumulator<DecompilerSearchLocation> accumulator,
				TaskMonitor monitor)
				throws CancelledException {

			for (DecompilerSearchLocation location : searchLocations) {
				accumulator.add(location);
			}
		}

		@Override
		public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
			return null; // This doesn't really make sense for this model
		}

		@Override
		public ProgramSelection getProgramSelection(int[] modelRows) {
			return new ProgramSelection(); // This doesn't really make sense for this model
		}

		private class LineNumberColumn
				extends AbstractDynamicTableColumnStub<DecompilerSearchLocation, Integer> {

			@Override
			public Integer getValue(DecompilerSearchLocation rowObject, Settings settings,
					ServiceProvider sp) throws IllegalArgumentException {
				FieldLocation fieldLocation = rowObject.getFieldLocation();
				return fieldLocation.getIndex().intValue() + 1; // +1 for 1-based lines
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

		private class ContextColumn
				extends
				AbstractDynamicTableColumnStub<DecompilerSearchLocation, LocationReferenceContext> {

			private GColumnRenderer<LocationReferenceContext> renderer = new ContextCellRenderer();

			@Override
			public LocationReferenceContext getValue(DecompilerSearchLocation rowObject,
					Settings settings,
					ServiceProvider sp) throws IllegalArgumentException {

				LocationReferenceContext context = rowObject.getContext();
				return context;
				// return rowObject.getTextLine();
			}

			@Override
			public String getColumnName() {
				return "Context";
			}

			@Override
			public GColumnRenderer<LocationReferenceContext> getColumnRenderer() {
				return renderer;
			}

			private class ContextCellRenderer
					extends AbstractGhidraColumnRenderer<LocationReferenceContext> {

				{
					// the context uses html
					setHTMLRenderingEnabled(true);
				}

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					// initialize
					super.getTableCellRendererComponent(data);

					DecompilerSearchLocation match = (DecompilerSearchLocation) data.getRowObject();
					LocationReferenceContext context = match.getContext();
					String text = context.getBoldMatchingText();
					setText(text);
					return this;
				}

				@Override
				public String getFilterString(LocationReferenceContext context, Settings settings) {
					return context.getPlainText();
				}
			}
		}
	}
}
