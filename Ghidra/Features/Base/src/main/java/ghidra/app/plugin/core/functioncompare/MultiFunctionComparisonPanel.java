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
package ghidra.app.plugin.core.functioncompare;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Iterator;
import java.util.Set;

import javax.swing.*;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.services.FunctionComparisonModel;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

/**
 * Extends the basic {@link FunctionComparisonPanel one-to-one comparison panel}
 * to allow a many-to-many relationship. The panel provides a pair of combo
 * boxes above the function display area that allows users to select which 
 * functions are to be compared.
 * <p>
 * Throughout this class the terms <code>source</code> and <code>target</code>
 * are used when referencing functions. This is because the model that backs 
 * this panel maintains a relationship between the functions being compared
 * such that each source function can only be compared to a specific set
 * of target functions. For all practical purposes, the source functions
 * appear in the left-side panel and targets appear on the right.
 *    
 */
public class MultiFunctionComparisonPanel extends FunctionComparisonPanel {

	/** Functions that will show up on the left side of the panel */
	private JComboBox<Function> sourceFunctionsCB;

	/** Functions that will show up on the right side of the panel */
	private JComboBox<Function> targetFunctionsCB;

	/** Data models backing the source and target combo boxes */
	private DefaultComboBoxModel<Function> sourceFunctionsCBModel;
	private DefaultComboBoxModel<Function> targetFunctionsCBModel;

	protected static final HelpService help = Help.getHelpService();
	public static final String HELP_TOPIC = "FunctionComparison";

	/**
	 * Constructor
	 * 
	 * @param provider the comparison provider associated with this panel
	 * @param tool the active plugin tool
	 */
	public MultiFunctionComparisonPanel(MultiFunctionComparisonProvider provider,
			PluginTool tool) {
		super(provider, tool, null, null);

		JPanel choicePanel = new JPanel(new GridLayout(1, 2));
		choicePanel.add(createSourcePanel());
		choicePanel.add(createTargetPanel());
		add(choicePanel, BorderLayout.NORTH);

		// For the multi-panels we don't need to show the title of each
		// comparison panel because the name of the function/data being shown 
		// is already visible in the combo box
		getComparisonPanels().forEach(p -> p.setShowTitles(false));
	}

	/**
	 * Clears out the source and targets lists and reloads them to 
	 * ensure that they reflect the current state of the data model. Any
	 * currently-selected list items will be restored after the lists
	 * are reloaded.
	 */
	@Override
	public void reload() {

		reloadSourceList();
		Function selectedSource = (Function) sourceFunctionsCBModel.getSelectedItem();
		reloadTargetList(selectedSource);
		loadFunctions(selectedSource, (Function) targetFunctionsCBModel.getSelectedItem());
		updateTabText();

		// Fire a notification to update the UI state; without this the 
		// actions would not be properly enabled/disabled
		tool.contextChanged(provider);
		tool.setStatusInfo("function comparisons updated");
	}

	/**
	 * Returns the combo box (source or target) which has focus
	 * 
	 * @return the focused component
	 */
	public JComboBox<Function> getFocusedComponent() {
		CodeComparisonPanel<? extends FieldPanelCoordinator> currentComponent =
			getCurrentComponent();
		boolean sourceHasFocus = currentComponent.leftPanelHasFocus();
		return sourceHasFocus ? sourceFunctionsCB : targetFunctionsCB;
	}

	/**
	 * Returns the source combo box
	 * 
	 * @return the source combo box
	 */
	public JComboBox<Function> getSourceComponent() {
		return sourceFunctionsCB;
	}

	/**
	 * Returns the target combo box
	 * 
	 * @return the target combo box
	 */
	public JComboBox<Function> getTargetComponent() {
		return targetFunctionsCB;
	}

	/**
	 * Clears out and reloads the source function list. Any selection currently
	 * made on the list will be reestablished.
	 */
	private void reloadSourceList() {

		// Save off any selected item so we can restore if it later
		Function selection = (Function) sourceFunctionsCBModel.getSelectedItem();

		// Remove all functions
		sourceFunctionsCBModel.removeAllElements();

		// Reload the functions
		FunctionComparisonModel model = ((FunctionComparisonProvider) provider).getModel();
		Iterator<FunctionComparison> compIter = model.getComparisons().iterator();
		while (compIter.hasNext()) {
			FunctionComparison fc = compIter.next();
			sourceFunctionsCBModel.addElement(fc.getSource());
		}

		restoreSelection(sourceFunctionsCB, selection);
	}

	/**
	 * Clears out and reloads the target function list with functions 
	 * associated with the given source function. Any selection currently made 
	 * on the list will be reestablished.
	 * 
	 * @param source the selected source function
	 */
	private void reloadTargetList(Function source) {

		// Save off any selected item so we can restore if it later
		Function selection = (Function) targetFunctionsCBModel.getSelectedItem();

		// Remove all functions
		targetFunctionsCBModel.removeAllElements();

		// Find all target functions associated with the given source function
		// and add them to the combo box model
		FunctionComparisonModel model = ((FunctionComparisonProvider) provider).getModel();
		Iterator<FunctionComparison> compIter = model.getComparisons().iterator();
		while (compIter.hasNext()) {
			FunctionComparison fc = compIter.next();
			if (fc.getSource().equals(source)) {
				Set<Function> targets = fc.getTargets();
				targetFunctionsCBModel.addAll(targets);
			}
		}

		restoreSelection(targetFunctionsCB, selection);
	}

	/**
	 * Sets the text on the current tab to match whatever is displayed in the
	 * comparison panels
	 */
	private void updateTabText() {
		String tabText = getDescription();
		provider.setTabText(tabText);
		provider.setTitle(tabText);
	}

	/**
	 * Sets a given function to be the selected item in a given combo
	 * box. If the function isn't found, the first item in the box is
	 * set.
	 * 
	 * @param cb the combo box
	 * @param selection the function to set
	 */
	private void restoreSelection(JComboBox<Function> cb, Function selection) {
		ComboBoxModel<Function> model = cb.getModel();

		boolean found = false;
		for (int i = 0; i < model.getSize(); i++) {
			Function f = model.getElementAt(i);
			if (f.equals(selection)) {
				model.setSelectedItem(f);
				found = true;
				break;
			}
		}

		if (!found && model.getSize() > 0) {
			cb.setSelectedIndex(0);
		}
	}

	/**
	 * Creates the panel displaying the source combo box
	 * <p>
	 * Note: The custom renderer is used so the name of the program associated
	 * with each function can be displayed in the combo box; this is necessary
	 * since a combo box may show functions from any number of programs, and
	 * the default is to simply show the function name<br>
	 * eg: "init (notepad)"<br>
	 * 
	 * @return the source panel
	 */
	private JPanel createSourcePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		sourceFunctionsCB = new JComboBox<>();
		sourceFunctionsCBModel = new DefaultComboBoxModel<>();
		sourceFunctionsCB.setModel(sourceFunctionsCBModel);
		sourceFunctionsCB.setRenderer(new FunctionListCellRenderer());
		sourceFunctionsCB.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() != ItemEvent.SELECTED) {
					return;
				}

				Function selected = (Function) sourceFunctionsCBModel.getSelectedItem();
				loadFunctions(selected, null);

				// Each time a source function is selected we need
				// to load the targets associated with it
				reloadTargetList((Function) sourceFunctionsCBModel.getSelectedItem());

				updateTabText();

				// Fire a notification to update the UI state; without this the 
				// actions would not be properly enabled/disabled
				tool.contextChanged(provider);
			}
		});

		panel.add(sourceFunctionsCB, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Creates the panel for the target functions selection components
	 * <p>
	 * Note: The custom renderer is used so the name of the program associated
	 * with each function can be displayed in the combo box; this is necessary
	 * since a combo box may show functions from any number of programs, and
	 * the default is to simply show the function name<br>
	 * eg: "init (notepad)"<br>
	 * 
	 * @return the target panel
	 */
	private JPanel createTargetPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		targetFunctionsCB = new JComboBox<>();
		targetFunctionsCBModel = new DefaultComboBoxModel<>();
		targetFunctionsCB.setModel(targetFunctionsCBModel);
		targetFunctionsCB.setRenderer(new FunctionListCellRenderer());
		targetFunctionsCB.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() != ItemEvent.SELECTED) {
					return;
				}

				Function selected = (Function) targetFunctionsCBModel.getSelectedItem();
				loadFunctions((Function) sourceFunctionsCBModel.getSelectedItem(), selected);

				updateTabText();

				// Fire a notification to update the UI state; without this the 
				// actions would not be properly enabled/disabled
				tool.contextChanged(provider);
			}
		});

		panel.add(targetFunctionsCB, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Cell renderer for combo boxes that changes the default display to show
	 * both the function name and the program it comes from
	 */
	private class FunctionListCellRenderer extends DefaultListCellRenderer {

		@Override
		public Component getListCellRendererComponent(JList<?> list, Object value, int index,
				boolean isSelected, boolean cellHasFocus) {

			if (value == null) {
				// It's possible during a close program operation to have this 
				// renderer called with a null value. If so, we can't get the 
				// function so just use the default renderer.
				return super.getListCellRendererComponent(list, value, index, isSelected,
					cellHasFocus);
			}

			Function f = (Function) value;

			String functionName = f.getName();
			String functionPathToProgram = f.getProgram().getDomainFile().getPathname();
			String functionAddress = f.getBody().getMinAddress().toString();
			String text = functionName + "@" + functionAddress + " (" + functionPathToProgram + ")";

			return super.getListCellRendererComponent(list, text, index, isSelected,
				cellHasFocus);
		}
	}

}
