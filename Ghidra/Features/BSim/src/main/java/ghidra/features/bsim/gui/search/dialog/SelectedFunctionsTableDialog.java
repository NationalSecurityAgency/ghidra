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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.BorderLayout;
import java.util.Map;
import java.util.Set;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.FunctionSignatureTableColumn;
import ghidra.util.task.TaskMonitor;

/**
 * Dialog for display selected functions
 */
public class SelectedFunctionsTableDialog extends DialogComponentProvider {

	private Set<FunctionSymbol> functions;
	private FunctionsTableModel model;
	private Map<Address, Integer> matchCounts;

	public SelectedFunctionsTableDialog(Set<FunctionSymbol> functionSymbols,
			GoToService gotoService, HelpLocation help) {
		this(functionSymbols, gotoService, help, null);
	}

	public SelectedFunctionsTableDialog(Set<FunctionSymbol> functionSymbols,
			GoToService gotoService, HelpLocation help, Map<Address, Integer> matchCounts) {
		super("Selected Functions For Bsim Search");
		this.functions = functionSymbols;
		this.matchCounts = matchCounts;
		addWorkPanel(buildMainPanel(gotoService));
		addDismissButton();
		setHelpLocation(help);
	}

	private Program getProgram() {
		if (functions.isEmpty()) {
			return null;
		}
		FunctionSymbol next = functions.iterator().next();
		return next.getProgram();
	}

	private JComponent buildMainPanel(GoToService goToService) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildFunctionsTable(getProgram(), goToService), BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildFunctionsTable(Program program, GoToService goToService) {
		model = new FunctionsTableModel(program);
		GhidraFilterTable<FunctionSymbol> table = new GhidraFilterTable<>(model);
		table.setNavigateOnSelectionEnabled(true);
		table.installNavigation(goToService);
		return table;
	}

	private class FunctionsTableModel extends AddressBasedTableModel<FunctionSymbol> {

		public FunctionsTableModel(Program program) {
			super("Selected Functions", new ServiceProviderStub(), program, TaskMonitor.DUMMY);
		}

		@Override
		protected TableColumnDescriptor<FunctionSymbol> createTableColumnDescriptor() {
			TableColumnDescriptor<FunctionSymbol> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new SymbolNameColumn());

			descriptor.addVisibleColumn(new SymbolAddressColumn(), 1, true);

			descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
				new FunctionSignatureTableColumn()));

			if (matchCounts != null) {
				descriptor.addVisibleColumn(new MatchCountColumn());
			}

			return descriptor;
		}

		@Override
		public Address getAddress(int row) {
			return getModelData().get(row).getAddress();
		}

		@Override
		protected void doLoad(Accumulator<FunctionSymbol> accumulator, TaskMonitor monitor)
				throws CancelledException {
			accumulator.addAll(functions);
		}

		private class SymbolNameColumn
				extends AbstractProgramBasedDynamicTableColumn<FunctionSymbol, String> {

			@Override
			public String getColumnName() {
				return "Name";
			}

			@Override
			public String getValue(FunctionSymbol symbol, Settings settings, Program data,
					ServiceProvider provider) throws IllegalArgumentException {

				return symbol.getName();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 150;
			}
		}

		private class MatchCountColumn
				extends AbstractProgramBasedDynamicTableColumn<FunctionSymbol, Integer> {

			@Override
			public String getColumnName() {
				return "Matches";
			}

			@Override
			public Integer getValue(FunctionSymbol symbol, Settings settings, Program data,
					ServiceProvider provider) throws IllegalArgumentException {

				Integer count = matchCounts.get(symbol.getAddress());
				return count != null ? count : 0;
			}

			@Override
			public int getColumnPreferredWidth() {
				return 100;
			}
		}

		private class SymbolAddressColumn
				extends AbstractProgramBasedDynamicTableColumn<FunctionSymbol, String> {

			@Override
			public String getColumnName() {
				return "Address";
			}

			@Override
			public String getValue(FunctionSymbol symbol, Settings settings, Program data,
					ServiceProvider provider) throws IllegalArgumentException {
				Address addr = symbol.getAddress();
				return addr.toString();
			}

			@Override
			public int getColumnPreferredWidth() {
				return 150;
			}
		}

	}

}
