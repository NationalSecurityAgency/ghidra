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
package ghidra.app.plugin.core.scalartable;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.help.HelpService;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.plugin.core.scalartable.RangeFilterTextField.FilterType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * Dialog allowing the user to set parameters when initiating a scalar search on a program. 
 * 
 */
public class ScalarSearchDialog extends DialogComponentProvider {

	private static String NULL_SELECTION = "Nothing currently selected";

	private JButton beginSearchButton;

	private ScalarSearchPlugin plugin;

	private JPanel mainPanel;
	private IntegerTextField exactValueField;

	private RangeFilterTextField minField;
	private RangeFilterTextField maxField;

	private SearchPanel searchLayout;
	private RangeFilter rangeFilter;

	// Selection radio buttons
	private JRadioButton searchAllScalars;
	private JRadioButton searchAScalar;

	private JRadioButton searchSelectionRadioButton;
	private JRadioButton searchAllRadioButton;
	private ScalarSearchProvider provider;

	ScalarSearchDialog(ScalarSearchPlugin plugin) {
		super("Search for Scalars", true, true, true, true);
		this.plugin = plugin;

		mainPanel = buildMainPanel();

		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(mainPanel, new HelpLocation(plugin.getName(), "Scalar_Search"));

		addWorkPanel(mainPanel);

		buildSearchButton();
		addCancelButton();

		// wide enough for the default values in the range fields
		setPreferredSize(425, 300);
	}

	public void show() {
		clearStatusText();
		exactValueField.requestFocus();
		exactValueField.selectAll();
		PluginTool tool = plugin.getTool();
		tool.showDialog(ScalarSearchDialog.this, provider);
	}

	public void setFilterValues(long minFilterValue, long maxFilterValue) {
		minField.setValue(minFilterValue);
		maxField.setValue(maxFilterValue);
	}

	public void setSpecificScalarValue(int value) {
		exactValueField.setValue(value);
	}

	public void setSearchAScalar() {
		searchAScalar.setSelected(true);
		exactValueField.setEnabled(true);
		minField.setEnabled(false);
		maxField.setEnabled(false);
	}

	ScalarSearchProvider getProvider() {
		return provider;
	}

	private JPanel buildMainPanel() {
		JPanel newMainPanel = new JPanel();

		newMainPanel.setLayout(new BorderLayout());
		newMainPanel.add(buildSearchLayout(), BorderLayout.NORTH);

		return newMainPanel;
	}

	private JPanel buildSearchLayout() {

		searchLayout = new SearchPanel();

		JPanel finalPanel = new JPanel(new BorderLayout());

		finalPanel.add(searchLayout, BorderLayout.NORTH);
		finalPanel.add(buildSelectionPanel(), BorderLayout.SOUTH);

		return finalPanel;
	}

	private Component createMinFilterWidget() {
		minField = new RangeFilterTextField(FilterType.MIN, plugin.getCurrentProgram());
		return minField.getComponent();
	}

	private Component createMaxFilterWidget() {
		maxField = new RangeFilterTextField(FilterType.MAX, plugin.getCurrentProgram());
		return maxField.getComponent();
	}

	private Component buildSelectionPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(new TitledBorder("Search Scope"));

		searchSelectionRadioButton = new GRadioButton("Search Selection");
		searchAllRadioButton = new GRadioButton("Search All");

		searchSelectionRadioButton.setToolTipText("Search only the current selection");
		searchAllRadioButton.setToolTipText("Search the entire program");

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(searchSelectionRadioButton);
		buttonGroup.add(searchAllRadioButton);

		ProgramSelection selection = plugin.getProgramSelection();
		if (selection == null) {
			searchAllRadioButton.setSelected(true);
			searchSelectionRadioButton.setEnabled(false);
		}
		else {
			searchSelectionRadioButton.setSelected(true);
		}

		panel.add(searchAllRadioButton);
		panel.add(searchSelectionRadioButton);

		JPanel selectionPanel = new JPanel();
		selectionPanel.setLayout(new BorderLayout());
		selectionPanel.add(panel, BorderLayout.NORTH);

		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(selectionPanel,
			new HelpLocation(plugin.getName(), "Scalar_Selection_Scope"));

		return selectionPanel;
	}

	private void buildSearchButton() {

		beginSearchButton = new JButton("Search");
		beginSearchButton.setMnemonic('B');
		beginSearchButton.addActionListener(ev -> searchCallback());
		this.addButton(beginSearchButton);
	}

	private void searchCallback() {

		if (searchAllRadioButton.isSelected()) {
			provider = new ScalarSearchProvider(plugin, null);
			updateProviderFilterValues();
			provider.setVisible(true);
			close();
			return;
		}

		ProgramSelection currentSelection = plugin.getProgramSelection();
		if (currentSelection == null) {
			setStatusText(NULL_SELECTION);
			return;
		}

		provider = new ScalarSearchProvider(plugin, currentSelection);
		updateProviderFilterValues();
		provider.setVisible(true);

		close();
	}

	/**
	 * Forwards the current filter settings to the provider.
	 */
	private void updateProviderFilterValues() {
		if (searchAScalar.isSelected()) {
			provider.updateSearchRangeValues(this);
		}
		else {
			provider.updateSearchRangeValues(this);
		}
	}

	long getMinSearchValue() {
		if (searchAScalar.isSelected()) {
			return exactValueField.getLongValue();
		}
		return minField.getFilterValue();
	}

	long getMaxSearchValue() {
		if (searchAScalar.isSelected()) {
			return exactValueField.getLongValue();
		}
		return maxField.getFilterValue();
	}

	String getMinSearchValueText() {
		if (searchAScalar.isSelected()) {
			return exactValueField.getText();
		}
		return minField.getText();
	}

	String getMaxSearchValueText() {
		if (searchAScalar.isSelected()) {
			return exactValueField.getText();
		}
		return maxField.getText();
	}

	private class SearchPanel extends JPanel {

		public SearchPanel() {

			HelpLocation help = new HelpLocation(plugin.getName(), "Search_For");
			HelpService helpService = DockingWindowManager.getHelpService();
			helpService.registerHelp(this, help);

			setLayout(new BorderLayout());
			setBorder(new TitledBorder("Search Type"));

			searchAllScalars = new GRadioButton("Scalars in Range:");
			searchAScalar = new GRadioButton("Specific Scalar:");

			searchAllScalars.setToolTipText(
				"Search program (or selection) for scalar operands or defined scalar data types with values in the following range:");
			searchAScalar.setToolTipText(
				"Search program (or selection) for scalar operands or defined scalar data types with the following value:");

			searchAllScalars.addActionListener(e -> {
				if (searchAllScalars.isSelected()) {
					minField.setEnabled(true);
					maxField.setEnabled(true);
					exactValueField.setEnabled(false);
				}
			});

			searchAScalar.addActionListener(e -> {
				if (searchAScalar.isSelected()) {
					minField.setEnabled(false);
					maxField.setEnabled(false);
					exactValueField.setEnabled(true);
				}
			});

			ButtonGroup buttonGroup = new ButtonGroup();
			buttonGroup.add(searchAllScalars);
			buttonGroup.add(searchAScalar);

			JPanel allScalarsPanel = new JPanel();
			allScalarsPanel.setLayout(new BorderLayout());
			allScalarsPanel.add(searchAllScalars, BorderLayout.NORTH);

			rangeFilter = new RangeFilter();
			allScalarsPanel.add(Box.createHorizontalStrut(18), BorderLayout.WEST);
			allScalarsPanel.add(rangeFilter, BorderLayout.CENTER);

			JPanel aScalarPanel = new JPanel();
			aScalarPanel.setLayout(new BorderLayout());
			aScalarPanel.add(searchAScalar, BorderLayout.NORTH);

			exactValueField = new IntegerTextField(8);

			aScalarPanel.add(Box.createHorizontalStrut(18), BorderLayout.WEST);
			aScalarPanel.add(exactValueField.getComponent(), BorderLayout.CENTER);

			add(allScalarsPanel, BorderLayout.NORTH);
			add(aScalarPanel, BorderLayout.CENTER);

			searchAllScalars.setSelected(true);
			exactValueField.setEnabled(false);
		}
	}

	/**
	 * Panel consisting of two {@link RangeFilterTextField} instances, allowing the
	 * user to specify minimum/maximum values for filtering the scalar results.
	 */
	private class RangeFilter extends JPanel {

		private HelpLocation help;

		public RangeFilter() {
			help = new HelpLocation(plugin.getName(), "Filter_Scalars");
			HelpService helpService = DockingWindowManager.getHelpService();
			helpService.registerHelp(this, help);

			setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));

			add(Box.createHorizontalStrut(4));
			add(new GLabel("Min:"));
			add(Box.createHorizontalStrut(5));
			add(createMinFilterWidget());

			add(Box.createHorizontalStrut(10));

			add(new GLabel("Max:"));
			add(Box.createHorizontalStrut(5));
			add(createMaxFilterWidget());
		}
	}

}
