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
import java.awt.Component;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;

/**
 * Dialog for initiating a BSim similar function match search.
 */
public class BSimSearchDialog extends AbstractBSimSearchDialog {
	private static final Icon FUNCTIONS_ICON = new GIcon("icon.bsim.functions.table");

	protected Set<FunctionSymbol> selectedFunctions;
	private JTextField functionsField;
	private BSimFilterPanel filterPanel;

	// Query Settings
	private IntegerTextField maxResultsField;

	public BSimSearchDialog(PluginTool tool, BSimSearchService service,
			BSimServerManager serverManager, Set<FunctionSymbol> functions) {
		super("Bsim Search Dialog", tool, service, serverManager);
		selectedFunctions = functions;
		setHelpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "BSim_Search_Dialog"));
		setMinimumSize(500, 400);
		updateSearchFunctionsLabel();
		setOkButtonText("Search");
	}

	@Override
	protected void initializeSettings(BSimSearchSettings lastUsedSearchSettings) {
		super.initializeSettings(lastUsedSearchSettings);
		maxResultsField.setValue(lastUsedSearchSettings.getMaxResults());
		filterPanel.setFilterSet(lastUsedSearchSettings.getBSimFilterSet());
	}

	@Override
	protected void okCallback() {
		searchService.search(serverCache, getSearchSettings(), selectedFunctions);
		close();
	}

	@Override
	protected void setServerCache(BSimServerCache serverCache) {
		super.setServerCache(serverCache);
		updateFilters();
	}

	protected void updateSearchFunctionsLabel() {
		if (selectedFunctions.isEmpty()) {
			functionsField.setText("<none>");
		}
		else if (selectedFunctions.size() == 1) {
			FunctionSymbol symbol = selectedFunctions.iterator().next();
			functionsField.setText(symbol.getName());
		}
		else {
			functionsField.setText("" + selectedFunctions.size() + " selected functions");
		}
	}

	protected JPanel buildServerPanel() {
		JPanel panel = super.buildServerPanel();
		panel.add(new JLabel("Function(s): "));
		panel.add(buildSelectedFunctionPanel());
		return panel;
	}

	protected JPanel buildCenterPanel() {
		filterPanel = new BSimFilterPanel(this::filterPanelChanged);
		return createTitledPanel("Filters:", filterPanel, true);
	}

	@Override
	protected boolean canQuery() {
		if (!super.canQuery()) {
			return false;
		}
		else if (!filterPanel.hasValidFilters()) {
			setStatusText("One or more filters has invalid data!", MessageType.ERROR);
			return false;
		}
		clearStatusText();
		return true;
	}

	@Override
	protected JPanel buildOptionsPanel() {
		JPanel panel = super.buildOptionsPanel();

		maxResultsField = new IntegerTextField(10);
		maxResultsField.setValue(100);
		maxResultsField.setMinValue(BigInteger.ONE);
		maxResultsField.setAllowNegativeValues(false);
		maxResultsField.setAllowsHexPrefix(false);
		maxResultsField.setShowNumberMode(false);

		panel.add(new JLabel("Max Matches Per Function:"));
		panel.add(maxResultsField.getComponent());
		return panel;
	}

	protected BSimSearchSettings getSearchSettings() {
		double similarity = similarityField.getValue();
		double confidence = confidenceField.getValue();
		int maxResults = maxResultsField.getIntValue();
		BSimFilterSet set = filterPanel.getFilterSet();
		return new BSimSearchSettings(similarity, confidence, maxResults, set);
	}

	private void updateFilters() {
		DatabaseInformation databaseInfo = getDatabaseInformation();
		List<BSimFilterType> filters = BSimFilterType.generateBsimFilters(databaseInfo, true);
		filterPanel.setFilters(filters);
	}

	private void filterPanelChanged() {
		updateSearchEnablement();
	}

	private Component buildSelectedFunctionPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		JPanel innerPanel = new JPanel(new BorderLayout());
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
		functionsField = new JTextField(20);
		functionsField.setEditable(false);
		innerPanel.add(functionsField, BorderLayout.CENTER);
		panel.add(innerPanel, BorderLayout.CENTER);
		JButton button = new EmptyBorderButton(FUNCTIONS_ICON);
		button.setToolTipText("Show table of selected functions");
		button.addActionListener(e -> showSelectedFunctionsDialog());
		panel.add(button, BorderLayout.EAST);
		return panel;
	}

	private void showSelectedFunctionsDialog() {
		if (selectedFunctions == null) {
			return;
		}
		GoToService service = tool.getService(GoToService.class);
		HelpLocation help = new HelpLocation("BSimSearchPlugin", "Selected_Functions");
		DialogComponentProvider dialog =
			new SelectedFunctionsTableDialog(selectedFunctions, service, help);
		DockingWindowManager.showDialog(dialog);
	}

//==================================================================================================
// Test methods
//==================================================================================================
	Set<FunctionSymbol> getSelectedFunction() {
		return selectedFunctions;
	}

	BSimFilterPanel getFilterPanel() {
		return filterPanel;
	}

}
