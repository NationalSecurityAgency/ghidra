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
package ghidra.examples;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import docking.widgets.table.GFilterTable;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.layout.MiddleLayout;
import resources.ResourceManager;

public class SampleTableProvider extends ComponentProviderAdapter implements OptionsChangeListener {

	private static final String OPTIONS_TITLE = "Sample Table";
	private static final String RESET_TABLE_DATA_OPTION = "Reset Table Data";

	private SampleTablePlugin plugin;

	private JComponent component;
	private GFilterTable<FunctionStatsRowObject> filterTable;
	private SampleTableModel model;

	private List<FunctionAlgorithm> discoveredAlgorithms;
	private GCheckBox[] checkBoxes;

	private GhidraFileChooserPanel fileChooserPanel;

	private boolean resetTableData;

	public SampleTableProvider(SampleTablePlugin plugin) {
		super(plugin.getTool(), "Sample Table Provider", plugin.getName());
		this.plugin = plugin;

		discoveredAlgorithms = findAlgorithms();

		component = build();

		createActions();

		initializeOptions();
	}

	void dispose() {
		filterTable.dispose();
		removeFromTool();
	}

	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(buildTablePanel(), BorderLayout.CENTER);
		panel.add(buildControlPanel(), BorderLayout.NORTH);

		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(buildAlgorithmsPanel(), BorderLayout.WEST);
		panel.add(buildButtonsPanel(), BorderLayout.CENTER); // run button

		return panel;
	}

	private JPanel buildAlgorithmsPanel() {

		JPanel checkBoxPanel = new JPanel(new GridLayout(0, 1));
		checkBoxPanel.setBorder(BorderFactory.createTitledBorder("Discovered Algorithms"));
		checkBoxes = new GCheckBox[discoveredAlgorithms.size()];
		for (int i = 0; i < discoveredAlgorithms.size(); i++) {
			checkBoxes[i] = new GCheckBox(discoveredAlgorithms.get(i).getName());
			checkBoxPanel.add(checkBoxes[i]);
		}

		return checkBoxPanel;
	}

	private JPanel buildButtonsPanel() {
		JPanel buttonPanel = new JPanel(new BorderLayout());

		String defaultOuptutFilePath =
			System.getProperty("user.home") + File.separator + "SampleTablePluginOutput.txt";
		String preferencesKey = "sample.table.plugin.output.file";
		fileChooserPanel = new GhidraFileChooserPanel("Output File", preferencesKey,
			defaultOuptutFilePath, true, GhidraFileChooserPanel.OUTPUT_MODE);

		JButton runButton = new JButton("Run Algorithms");
		runButton.addActionListener(e -> model.reload());

		JPanel runButtonPanel = new JPanel(new MiddleLayout());
		runButtonPanel.add(runButton);

		buttonPanel.add(fileChooserPanel, BorderLayout.NORTH);
		buttonPanel.add(runButtonPanel, BorderLayout.CENTER);
		return buttonPanel;
	}

	private List<FunctionAlgorithm> findAlgorithms() {
		return new ArrayList<>(ClassSearcher.getInstances(FunctionAlgorithm.class));
	}

	private Component buildTablePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

		model = new SampleTableModel(plugin);
		filterTable = new GFilterTable<>(model);
		panel.add(filterTable);

		return panel;
	}

	private void createActions() {
		DockingAction optionsAction = new DockingAction("Sample Table Options", plugin.getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				OptionsService service = tool.getService(OptionsService.class);
				service.showOptionsDialog(OPTIONS_TITLE, "Sample");
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return tool.getService(OptionsService.class) != null;
			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/table.png");
		optionsAction.setToolBarData(new ToolBarData(icon));

		DockingAction saveTableDataAction = new DockingAction("Save Table Data", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				StringBuilder buffer = new StringBuilder();
				buffer.append("Writing the following objects to file: ");
				buffer.append(HTMLUtilities.escapeHTML(fileChooserPanel.getFileName()));

				List<FunctionStatsRowObject> selectedObjects = filterTable.getSelectedRowObjects();
				for (FunctionStatsRowObject stats : selectedObjects) {
					buffer.append("\nData: " + stats.getAlgorithmName());
				}

				Msg.showInfo(this, filterTable, "Example Dialog",
					HTMLUtilities.toHTML(buffer.toString()));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return filterTable.getSelectedRowObjects().size() > 0;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object sourceObject = context.getSourceObject();
				if (sourceObject instanceof JTable) {
					return true;
				}

				return SwingUtilities.isDescendingFrom((Component) sourceObject, filterTable);
			}
		};
		icon = ResourceManager.loadImage("images/disk.png");
		saveTableDataAction.setToolBarData(new ToolBarData(icon));
		saveTableDataAction.setPopupMenuData(new MenuData(new String[] { "Save Data" }));

		addLocalAction(optionsAction);
		addLocalAction(saveTableDataAction);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	public List<FunctionAlgorithm> getAlgorithms() {

		List<FunctionAlgorithm> list = new ArrayList<>();
		for (int i = 0; i < checkBoxes.length; i++) {
			JCheckBox checkBox = checkBoxes[i];
			if (checkBox.isSelected()) {
				list.add(discoveredAlgorithms.get(i));
			}
		}

		return list;
	}

	public boolean resetExistingTableData() {
		return resetTableData;
	}

//==================================================================================================
// Options Methods
//==================================================================================================

	private void initializeOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		HelpLocation help = new HelpLocation("SampleTablePlugin", "Reset_Options");

		opt.registerOption(RESET_TABLE_DATA_OPTION, true, help,
			"When toggled on the sample table will clear " +
				"any existing data before showing algorithm results");

		resetTableData = opt.getBoolean(RESET_TABLE_DATA_OPTION, true);

		opt.addOptionsChangeListener(this);
	}

	// Options changed callback
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (RESET_TABLE_DATA_OPTION.equals(optionName)) {
			resetTableData = (Boolean) newValue;
		}
	}

}
