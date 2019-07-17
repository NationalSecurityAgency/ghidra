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
package ghidra.app.plugin.core.reachability;

import java.awt.*;
import java.util.Collections;
import java.util.List;

import javax.swing.*;

import docking.ComponentProvider;
import docking.WindowPosition;
import docking.widgets.label.GDLabel;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

public class FunctionReachabilityProvider extends ComponentProvider {

	private static final String TITLE = "Function Reachability";

	private FunctionReachabilityPlugin plugin;

	private Program program;
	private Function fromFunction;
	private Function toFunction;

	private JComponent component;
	private JTextField fromAddressField;
	private JLabel fromFunctionLabel;
	private JTextField toAddressField;
	private JLabel toFunctionLabel;

// TODO use a filter panel
	private FunctionReachabilityTableModel resultsModel;
	private GhidraTable resultsTable;
	private FRPathsModel pathsModel;
	private GhidraTable pathsTable;

	public FunctionReachabilityProvider(FunctionReachabilityPlugin plugin) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;

		component = buildComponent();

		// try to give the trees a suitable amount of space by default
		component.setPreferredSize(new Dimension(800, 400));

		setTransient();

		setWindowMenuGroup(TITLE);
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		setIcon(FunctionReachabilityPlugin.ICON);
		setHelpLocation(new HelpLocation(plugin.getName(), "Function_Reachability_Plugin"));

		addToTool();

		createActions();
	}

	private void createActions() {
		// TODO

		// TODO work on selections???
		//  -only show paths in selection?

		// refresh/reload button

		// delete rows from table

		// color addresses in row(s)

		// selection for row

		// create bookmarks for addresses in row (entry points)

		// create a view for addresses in row

		// track incoming location/selection changes
		//   -select paths containing

		// action to show all paths containing a:
		// -function
		// -address
	}

	private JComponent buildComponent() {
		// TODO Auto-generated method stub
		/*
		 
		 Text Field | browse button       |     Results table
		 Function Name Label              |
		 		Swap Button               |     ___________________
		                                  |
		 Text Field | browse button       |     Path entry table (for each result)
		 Function Name Label              |
		                                  |
		 Go Button                        |
		 
		 */

		//
		// Input Panel
		//
		JPanel inputPanel = new JPanel();

// TODO use GridBagLayout		
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));

		fromAddressField = new JTextField(15);
		fromFunctionLabel = new GDLabel();

		JButton swapButton = new JButton("Swap");
		swapButton.addActionListener(e -> {
			String fromText = fromAddressField.getText();
			String toText = toAddressField.getText();
			fromAddressField.setText(toText);
			toAddressField.setText(fromText);
		});

		toAddressField = new JTextField(15);
		toFunctionLabel = new GDLabel();

		JButton goButton = new JButton("Go");
		goButton.addActionListener(e -> findPaths());

		inputPanel.add(fromAddressField);
		inputPanel.add(fromFunctionLabel);
		inputPanel.add(Box.createVerticalStrut(20));
		inputPanel.add(swapButton);
		inputPanel.add(Box.createVerticalStrut(20));
		inputPanel.add(toAddressField);
		inputPanel.add(toFunctionLabel);
		inputPanel.add(Box.createVerticalStrut(30));
		inputPanel.add(goButton);

		//
		// Output Panel
		//
		JPanel outputPanel = new JPanel(new GridLayout(1, 2));

// TODO rename to 'FR'		
		resultsModel = new FunctionReachabilityTableModel(plugin.getTool(), program);

		GhidraThreadedTablePanel<FunctionReachabilityResult> tablePanel =
			new GhidraThreadedTablePanel<>(resultsModel);

		resultsTable = tablePanel.getTable();

		GoToService goToService = plugin.getTool().getService(GoToService.class);
		if (goToService != null) {
			resultsTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

		resultsTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			int[] selectedRows = resultsTable.getSelectedRows();
			if (selectedRows.length != 1) {
				List<FRVertex> emptyList = Collections.emptyList();
				pathsModel.setPath(emptyList);
				return;
			}

			FunctionReachabilityResult result = resultsModel.getRowObject(selectedRows[0]);
			pathsModel.setPath(result.getPath());
		});

		outputPanel.add(tablePanel);

		pathsModel = new FRPathsModel(plugin.getTool(), program);
		pathsTable = new GhidraTable(pathsModel);

		if (goToService != null) {
			pathsTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

		outputPanel.add(new JScrollPane(pathsTable));

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(inputPanel, BorderLayout.WEST);
		panel.add(outputPanel, BorderLayout.CENTER);

		return panel;
	}

	private void findPaths() {
		if (!validateFunctions()) {
			return;
		}

		resultsModel.setFunctions(fromFunction, toFunction);
	}

	private boolean validateFunctions() {

		PluginTool tool = plugin.getTool();

		String text = fromAddressField.getText();
		if (isNumpty(text)) {
			tool.setStatusInfo("Must input two valid functions: 'from' address is empty", true);
			return false;
		}

		fromFunction = getFunction(text);
		if (fromFunction == null) {
			fromFunctionLabel.setText("");
			tool.setStatusInfo(
				"Must input two valid functions: 'from' address is not in a function: " + text,
				true);
			return false;
		}
		fromFunctionLabel.setText(fromFunction.getName());

		text = toAddressField.getText();
		if (isNumpty(text)) {
			tool.setStatusInfo("Must input two valid functions: 'to' address is empty", true);
			return false;
		}

		toFunction = getFunction(text);
		if (toFunction == null) {
			toFunctionLabel.setText("");
			tool.setStatusInfo(
				"Must input two valid functions: 'to' address is not in a function: " + text, true);
			return false;
		}
		toFunctionLabel.setText(toFunction.getName());

		return true;
	}

	private Function getFunction(String addressString) {
		FunctionManager functionManager = program.getFunctionManager();
		AddressFactory factory = program.getAddressFactory();
		Address address = factory.getAddress(addressString);
		if (address == null) {
			return null;
		}
		return functionManager.getFunctionContaining(address);
	}

	private boolean isNumpty(String text) {
		return text == null || text.isEmpty();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void componentHidden() {
		plugin.removeProvider(this);
	}

	void initialize(Program p, ProgramLocation location) {
		if (p == null) { // no program open
			return;
		}

		this.program = p;
		resultsModel.setProgram(p);
		pathsModel.setProgram(p);

// TODO do we care about changes to the program?...like to remove invalid paths?		
//		currentProgram.addListener(this);
		doSetLocation(location);
	}

	private void doSetLocation(ProgramLocation location) {
		if (location == null) {
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();
		Address address = location.getAddress();
		Function function = functionManager.getFunctionContaining(address);

// TODO see CallTreesPlugin for resolving our 'fake' functions at the beginning of programs		
//		function = resolveFunction(function, address);
		setFromFunction(function);
	}

	private void setFromFunction(Function function) {
		this.fromFunction = function;

		Address address = null;
		String functionText = "";
		if (fromFunction != null) {
			address = fromFunction.getEntryPoint();
			functionText = function.getName();
		}

		String addressText = address == null ? "" : address.toString();
		fromAddressField.setText(addressText);
		fromFunctionLabel.setText(functionText);
	}
}
