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
package ghidra.features.bsim.gui.search.results;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.*;

import javax.swing.JPanel;
import javax.swing.event.HyperlinkEvent;

import docking.widgets.HyperlinkComponent;
import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.query.TableService;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.query.facade.SFQueryResult;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Panel that displays the list of functions to be included in a BSim query.
 *
 */
class DisplayFunctionsPanel extends JPanel {

	private static final String SHOW_TABLE_HREF_NAME = "ShowTable";

	private static final Color MARKER_COLOR = Palette.getColor("lightskyblue");

	private HyperlinkComponent functionsHTMLComponent;

	private TableComponentProvider<?> tableProvider;
	private final ServiceProvider serviceProvider;
	private Set<FunctionSymbol> selectedFunctions;

	// Maps input functions to the number of matches associated with it. This is 
	// here to provide quick access for the MatchCountTableColumn. 
	private Map<String, Integer> functionMatchMap = new HashMap<>();
	private String description;

	DisplayFunctionsPanel(ServiceProvider serviceProvider, String desc) {
		super(new BorderLayout());
		this.serviceProvider = serviceProvider;
		this.description = desc;

		functionsHTMLComponent = new HyperlinkComponent(getNoFunctionsSelectedMessage());
		functionsHTMLComponent.addHyperlinkListener(SHOW_TABLE_HREF_NAME, e -> {
			if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
				// not a mouse click
				return;
			}
			showAllSelectedFunctionsTable();
		});

		add(functionsHTMLComponent, BorderLayout.CENTER);
	}

	/**
	 * Takes a new set of query results and parses the function counts.
	 * 
	 * @param queryResult the object to hold the load results
	 */
	public void loadQueryResults(SFQueryResult queryResult) {
		parseFunctionMatchCounts(queryResult);
	}

	private String getNoFunctionsSelectedMessage() {
		StringBuilder buffy = new StringBuilder();
		buffy.append(
			"<html><font color=\"" + Palette.GRAY + "\"><i>No functions selected</i></font>");
		return buffy.toString();
	}

	void close() {
		if (tableProvider != null) {
			tableProvider.removeFromTool();
			tableProvider = null;
		}

		selectedFunctions = null;
	}

	void setSelectedFunctions(Set<FunctionSymbol> functions) {

		this.selectedFunctions = functions;
		if (tableProvider != null && tableProvider.isInTool()) {
			tableProvider.removeFromTool();
			tableProvider = null;
		}

		if (functions.isEmpty()) {
			functionsHTMLComponent.setText(getNoFunctionsSelectedMessage());
			return;
		}

		String text = createTextForSelectedFunctions(functions);
		functionsHTMLComponent.setText(text);
	}

	private String createTextForSelectedFunctions(Set<FunctionSymbol> functions) {

		if (functions.isEmpty()) {
			return "";
		}
		StringBuilder buffy = new StringBuilder();
		int count = functions.size();
		Function firstFunc = (Function) functions.iterator().next().getObject();
		String programName = firstFunc.getProgram().getDomainFile().getPathname();
		buffy.append(description).append(" ");
		buffy.append(firstFunc.getName());
		if (count > 1) {
			buffy.append(" and ");
			buffy.append(count - 1);
			buffy.append(" other function");
		}
		if (count > 2) {
			buffy.append("s");
		}
		buffy.append(" from ");
		buffy.append(programName);
		buffy.append(" <a href=\"").append(SHOW_TABLE_HREF_NAME).append("\">"); // open anchor
		buffy.append("<font color=\"" + Palette.BLUE + "\">");
		buffy.append(" (show table) ");
		buffy.append("</font>");
		buffy.append("</a>"); // close anchor
		return buffy.toString();
	}

	private void showAllSelectedFunctionsTable() {
		if (tableProvider != null) {
			if (tableProvider.isInTool()) {
				tableProvider.setVisible(true);
				return;
			}

			// it has been closed--cleanup
			tableProvider = null;
		}

		TableService tableService = serviceProvider.getService(TableService.class);
		if (tableService == null) {
			Msg.showWarn(getClass(), this, "No Table Service Found",
				"Unable to locate the Table Service.  Make sure the plugin is installed.");
			return;
		}

		FunctionSymbol arbitraryFunction = selectedFunctions.iterator().next();
		Program program = arbitraryFunction.getProgram();
		SelectedFunctionsModel model =
			new SelectedFunctionsModel(program, serviceProvider, selectedFunctions);
		tableProvider = tableService.showTableWithMarkers("Selected Query Functions",
			"QueryDialogTable", model, MARKER_COLOR, null /*icon*/, "Selected Query Functions",
			null /*navigatable - use default*/);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SelectedFunctionsModel extends AddressBasedTableModel<Function> {
		private final List<FunctionSymbol> functions;

		SelectedFunctionsModel(Program program, ServiceProvider serviceProvider,
				Set<FunctionSymbol> functions) {
			super("Selected Query Functions", serviceProvider, program, null);
			this.functions = new ArrayList<>(functions);
		}

		@Override
		protected TableColumnDescriptor<Function> createTableColumnDescriptor() {
			TableColumnDescriptor<Function> descriptor = new TableColumnDescriptor<>();

			descriptor.addVisibleColumn(
				DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
			descriptor.addVisibleColumn(
				DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
			descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
				new FunctionSignatureTableColumn()));
			descriptor.addVisibleColumn(new MatchCountTableColumn());

			return descriptor;
		}

		@Override
		public Address getAddress(int row) {
			Function function = getRowObject(row);
			return function.getEntryPoint();
		}

		@Override
		protected void doLoad(Accumulator<Function> accumulator, TaskMonitor monitor)
				throws CancelledException {
			for (FunctionSymbol sym : functions) {
				Object obj = sym.getObject();
				if (obj != null) {
					accumulator.add((Function) obj);
				}
			}
		}

		@Override
		public ProgramLocation getProgramLocation(int row, int column) {
// TODO: I cannot reconcile how to show the user a table of functions and let them 
//		 navigate in a way that is understandable (if they navigate, that changes the selected
//		 functions, which would then clear the table)
//		
//		Sad Face :(
//		
			return null;
		}
	}

	/**
	 * Calculates how many matches are associated with each base function in
	 * the given result set and stores them in the {@link DisplayFunctionsPanel#functionMatchMap}.
	 * 
	 * @param queryResult the object that holds the function matches
	 */
	private void parseFunctionMatchCounts(SFQueryResult queryResult) {

		List<SimilarityResult> results = queryResult.getSimilarityResults();

		for (SimilarityResult result : results) {
			String funcName = result.getBase().getFunctionName();
			functionMatchMap.put(funcName, result.getTotalCount());
		}
	}

	/**
	 * Column for showing the number of matches each base function has. 
	 * 
	 * To make this as fast as possible, the counts for each function are NOT determined
	 * here; they're calculated when a new result set is received and stored in the
	 * {@link DisplayFunctionsPanel#functionMatchMap}. This class has only to
	 * go to that map and extract the correct value.
	 * 
	 * @see DisplayFunctionsPanel#parseFunctionMatchCounts(SFQueryResult)
	 *
	 */
	private class MatchCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<Function, Integer> {

		@Override
		public String getColumnName() {
			return "Matches";
		}

		@Override
		public Integer getValue(Function rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			if (functionMatchMap == null) {
				return 0;
			}
			return functionMatchMap.get(rowObject.getName());
		}
	}
}
