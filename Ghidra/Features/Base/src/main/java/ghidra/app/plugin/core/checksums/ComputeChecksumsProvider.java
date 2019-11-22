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
package ghidra.app.plugin.core.checksums;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.label.GDLabel;
import ghidra.app.context.ProgramContextAction;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskLauncher;
import resources.Icons;
import resources.ResourceManager;

/**
 * Provider to invoke computation of various checksums and display them in a table.
 */
public class ComputeChecksumsProvider extends ComponentProviderAdapter {

	private ComputeChecksumsPlugin plugin;

	private DockingAction computeAction;
	private ToggleDockingAction selectionAction;
	private ToggleDockingAction showHexAction;
	private ToggleDockingAction xorAction;
	private ToggleDockingAction carryAction;
	private ToggleDockingAction onesCompAction;
	private ToggleDockingAction twosCompAction;
	private GhidraTable table;
	private ChecksumTableModel model;
	private List<ChecksumAlgorithm> checksums = new ArrayList<>();
	private boolean hasResults;

	private JPanel mainPanel;
	private JLabel errorStatus;

	/**
	 * Constructor for the provider.
	 * @param plugin The plugin that created the provider.
	 */
	public ComputeChecksumsProvider(ComputeChecksumsPlugin plugin) {
		super(plugin.getTool(), "Checksum Generator", plugin.getName(), ProgramContextAction.class);

		setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "Generate_Checksum_Help"));
		List<ChecksumAlgorithm> algorithms = ClassSearcher.getInstances(ChecksumAlgorithm.class);
		checksums.addAll(algorithms);

		this.plugin = plugin;
		this.mainPanel = createWorkPanel();

		addToTool();
		createActions();

		setSelection(false);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private JPanel createWorkPanel() {
		initializeTable();
		JPanel main = new JPanel();

		main.setLayout(new BorderLayout());
		JPanel resultsMainPanel = new JPanel(new BorderLayout());
		resultsMainPanel.setBorder(BorderFactory.createTitledBorder("Checksum Results"));
		JPanel tablePanel = new JPanel(new BorderLayout());
		JScrollPane scroll = new JScrollPane(table);
		tablePanel.add(scroll);
		resultsMainPanel.add(tablePanel);
		main.add(resultsMainPanel, BorderLayout.CENTER);

		errorStatus = new GDLabel(" ");
		errorStatus.setName("message");
		errorStatus.setHorizontalAlignment(SwingConstants.CENTER);
		errorStatus.setForeground(Color.RED);
		errorStatus.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
		main.add(errorStatus, BorderLayout.SOUTH);

		return main;
	}

	/*
	 * Starts new task every time the generate button is clicked so that the tool would not 
	 * be hosed up if checksumming takes a long time
	 */
	private void generate() {
		if (plugin.getProgram() == null || !isVisible()) {
			return;
		}

		ComputeChecksumTask task = new ComputeChecksumTask(this, plugin.getProgram().getMemory(),
			doOnSelection() ? plugin.getSelection() : null);
		new TaskLauncher(task, mainPanel); // this launches the launcher

		if (task.hasError()) {
			setErrorMessage(task.getErrorMessage());
		}
	}

	/*
	 * Once checksumming has completed, method will display results depending on the options 
	 * that are selected in window
	 */
	void generateChecksumCompleted() {
		hasResults = true;
		updateFields();
	}

	/*
	 * Lets the tool know if a selection is made and which buttons to set active
	 */
	void setSelection(boolean state) {
		setErrorMessage("");

		selectionAction.setSelected(state);
		selectionAction.setEnabled(state);
		if (state) {
			generate();
		}
		else {
			clearFields();
		}
	}

	private boolean doOnSelection() {
		return selectionAction.isEnabled() && plugin.hasSelection() && selectionAction.isSelected();
	}

	/**
	 * Returns true if the toggle action for 'one's complement' is selected.
	 * @return true if the toggle action for 'one's complement' is selected.
	 */
	public boolean isOnes() {
		return onesCompAction.isSelected();
	}

	/**
	 * Returns true if the toggle action for 'two's complement' is selected.
	 * @return true if the toggle action for 'two's complement' is selected.
	 */
	public boolean isTwos() {
		return twosCompAction.isSelected();
	}

	/**
	 * Returns true if the toggle action for 'xor' is selected.
	 * @return true if the toggle action for 'xor' is selected.
	 */
	public boolean isXor() {
		return xorAction.isSelected();
	}

	/**
	 * Returns true if the toggle action for 'carry' is selected.
	 * @return true if the toggle action for 'carry' is selected.
	 */
	public boolean isCarry() {
		return carryAction.isSelected();
	}

	ChecksumTableModel getModel() {
		return model;
	}

	/**
	 * Returns a list of the checksums currently being used by the table model
	 * @return a list of the checksums currently being used by the table model
	 */
	List<ChecksumAlgorithm> getChecksums() {
		// send out a copy so that nobody can modify the list while it is being used
		return new ArrayList<>(checksums);
	}

	/**
	 * Creates a new table for the checksums.
	 */
	private void initializeTable() {
		model = new ChecksumTableModel(tool, checksums);
		table = new GhidraTable(model);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	}

	private void updateFields() {
		if (!hasResults) {
			return;
		}

		model.setFormatOptions(showHexAction.isSelected());
		model.fireTableDataChanged();
	}

	private void clearFields() {
		checksums.forEach(checkResult -> checkResult.reset());
		model.fireTableDataChanged();
	}

	private void createActions() {
		computeAction = new DockingAction("Compute Checksum", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		computeAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "compute"));
		computeAction.setEnabled(true);
		computeAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		computeAction.setDescription("Refreshes checksums");

		selectionAction = new ToggleDockingAction("On Selection", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateFields();
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		selectionAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "On_Selection"));
		selectionAction.setEnabled(plugin.hasSelection());
		selectionAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/NextSelectionBlock16.gif"), null));
		selectionAction.setDescription("When toggled, generates checksums on " +
			"selection. Otherwise checksums are generated over the entire program");

		showHexAction = new ToggleDockingAction("Show Hex Values", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateFields();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		showHexAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "As_Hex"));
		showHexAction.setEnabled(true);
		showHexAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/hexData.png"), null));
		showHexAction.setDescription("Toggle to show the hex values instead of decimal values.");

		xorAction = new ToggleDockingAction("XOR Checksum Values", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (xorAction.isSelected() && carryAction.isSelected()) {
					carryAction.setSelected(false);
				}
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		xorAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "xor"));
		xorAction.setEnabled(true);
		xorAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/xor.png"), null));
		xorAction.setDescription("Toggle to recompute values with a xor operation.");

		carryAction = new ToggleDockingAction("Carry Checksum Values", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (carryAction.isSelected() && xorAction.isSelected()) {
					xorAction.setSelected(false);
				}
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}

		};
		carryAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "carry"));
		carryAction.setEnabled(true);
		carryAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/carry.png"), null));
		carryAction.setDescription("Toggle to recompute values with a carry operation.");

		onesCompAction = new ToggleDockingAction("Ones Complement", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (onesCompAction.isSelected() && twosCompAction.isSelected()) {
					twosCompAction.setSelected(false);
				}
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		onesCompAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "ones_comp"));
		onesCompAction.setEnabled(true);
		onesCompAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/onesComplement.png"), null));
		onesCompAction.setDescription("Toggle to recompute values with a one's complement.");

		twosCompAction = new ToggleDockingAction("Twos Complement", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (onesCompAction.isSelected() && twosCompAction.isSelected()) {
					onesCompAction.setSelected(false);
				}
				generate();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isVisible();
			}
		};
		twosCompAction.setHelpLocation(new HelpLocation("ComputeChecksumsPlugin", "twos_comp"));
		twosCompAction.setEnabled(true);
		twosCompAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/twosComplement.png"), null));
		twosCompAction.setDescription("Toggle to recompute values with a two's complement.");

		tool.addLocalAction(this, onesCompAction);
		tool.addLocalAction(this, twosCompAction);
		tool.addLocalAction(this, xorAction);
		tool.addLocalAction(this, carryAction);
		tool.addLocalAction(this, selectionAction);
		tool.addLocalAction(this, showHexAction);
		tool.addLocalAction(this, computeAction);
	}

	void dispose() {
		table.dispose();
	}

	String getErrorStatus() {
		return errorStatus.getText();
	}

	private void setErrorMessage(String text) {
		errorStatus.setText(text);
	}
}
