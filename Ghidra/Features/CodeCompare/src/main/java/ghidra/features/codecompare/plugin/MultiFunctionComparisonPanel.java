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
package ghidra.features.codecompare.plugin;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;

import docking.widgets.list.GComboBoxCellRenderer;
import ghidra.features.base.codecompare.model.FunctionComparisonModel;
import ghidra.features.base.codecompare.model.FunctionComparisonModelListener;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.base.codecompare.panel.FunctionComparisonPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * Extends the basic {@link FunctionComparisonPanel one-to-one comparison panel}
 * to allow a many-to-many relationship. The panel provides a pair of combo
 * boxes above the function display area that allows users to select which 
 * functions are to be compared.
 * <P>
 * This behavior of this class is driven by the given {@link FunctionComparisonModel}. The default
 * model displays the same set of functions on both sides. But the model interface allows for
 * other behaviors such as having different sets of function on each side and even changing the
 * set of functions on one side base on what is selected on the other side.
 */
public class MultiFunctionComparisonPanel extends FunctionComparisonPanel
		implements FunctionComparisonModelListener {

	public static final String HELP_TOPIC = "FunctionComparison";

	private FunctionComparisonModel model;
	private Duo<JComboBox<Function>> comboBoxes;
	private Duo<ItemListener> comboListeners;

	/**
	 * Constructor
	 * 
	 * @param provider the comparison provider associated with this panel
	 * @param tool the active plugin tool
	 * @param model the comparison data model
	 */
	public MultiFunctionComparisonPanel(FunctionComparisonProvider provider, PluginTool tool,
			FunctionComparisonModel model) {
		super(tool, provider.getName());
		this.model = model;
		model.addFunctionComparisonModelListener(this);

		buildComboPanels();

		getComparisonPanels().forEach(p -> p.setShowDataTitles(false));
		setPreferredSize(new Dimension(1200, 600));
		modelDataChanged();
	}

	@Override
	public void activeFunctionChanged(Side side, Function function) {
		updateComboBoxSelectIfNeeded(side, function);
		loadFunctions(model.getActiveFunction(LEFT), model.getActiveFunction(RIGHT));
	}

	@Override
	public void modelDataChanged() {
		intializeComboBox(LEFT);
		intializeComboBox(RIGHT);
		loadFunctions(model.getActiveFunction(LEFT), model.getActiveFunction(RIGHT));
	}

	@Override
	public void dispose() {
		model.removeFunctionComparisonModelListener(this);
		super.dispose();
	}

	Side getActiveSide() {
		CodeComparisonPanel currentComponent = getCurrentComponent();
		return currentComponent.getActiveSide();
	}

	boolean canCompareNextFunction() {
		Side activeSide = getActiveSide();
		JComboBox<Function> combo = comboBoxes.get(activeSide);
		int index = combo.getSelectedIndex();
		return index < combo.getModel().getSize() - 1;
	}

	boolean canComparePreviousFunction() {
		Side activeSide = getActiveSide();
		JComboBox<Function> combo = comboBoxes.get(activeSide);
		int index = combo.getSelectedIndex();
		return index > 0;
	}

	void compareNextFunction() {
		Side activeSide = getActiveSide();
		JComboBox<Function> combo = comboBoxes.get(activeSide);
		int index = combo.getSelectedIndex();
		combo.setSelectedIndex(index + 1);
	}

	void comparePreviousFunction() {
		Side activeSide = getActiveSide();
		JComboBox<Function> combo = comboBoxes.get(activeSide);
		int index = combo.getSelectedIndex();
		combo.setSelectedIndex(index - 1);
	}

	boolean canRemoveActiveFunction() {
		Side activeSide = getActiveSide();
		return model.getActiveFunction(activeSide) != null;
	}

	void removeActiveFunction() {
		Side activeSide = getActiveSide();
		model.removeFunction(model.getActiveFunction(activeSide));
	}

	private void buildComboPanels() {
		JPanel choicePanel = new JPanel(new GridLayout(1, 2));
		createComboBoxes();
		choicePanel.add(createPanel(LEFT));
		choicePanel.add(createPanel(RIGHT));
		add(choicePanel, BorderLayout.NORTH);
	}

	private void intializeComboBox(Side side) {
		JComboBox<Function> comboBox = comboBoxes.get(side);
		comboBox.removeItemListener(comboListeners.get(side));

		DefaultComboBoxModel<Function> comboModel =
			(DefaultComboBoxModel<Function>) comboBox.getModel();
		comboModel.removeAllElements();
		comboModel.addAll(model.getFunctions(side));

		Function activeFunction = model.getActiveFunction(side);
		if (activeFunction != null) {
			comboBox.setSelectedItem(activeFunction);
		}

		comboBox.addItemListener(comboListeners.get(side));
	}

	private void createComboBoxes() {
		createComboBoxListeners();
		JComboBox<Function> leftComboBox = buildComboBox(LEFT);
		JComboBox<Function> rightComboBox = buildComboBox(RIGHT);
		comboBoxes = new Duo<>(leftComboBox, rightComboBox);
	}

	private void createComboBoxListeners() {
		ItemListener leftListener = e -> comboChanged(e, LEFT);
		ItemListener rightListener = e -> comboChanged(e, RIGHT);
		comboListeners = new Duo<>(leftListener, rightListener);
	}

	private void comboChanged(ItemEvent e, Side side) {
		if (e.getStateChange() == ItemEvent.DESELECTED) {
			return;		// only care when a function is selected
		}
		model.setActiveFunction(side, (Function) e.getItem());
	}

	private JComboBox<Function> buildComboBox(Side side) {
		DefaultComboBoxModel<Function> leftModel = new DefaultComboBoxModel<>();
		JComboBox<Function> comboBox = new JComboBox<>(leftModel);
		comboBox.setName(side + "FunctionComboBox");
		comboBox.setRenderer(new FunctionListCellRenderer());
		comboBox.addItemListener(comboListeners.get(side));
		return comboBox;
	}

	private JPanel createPanel(Side side) {
		JPanel panel = new JPanel(new BorderLayout());
		JComboBox<Function> comboBox = comboBoxes.get(side);
		panel.add(comboBox, BorderLayout.CENTER);
		return panel;
	}

	private void updateComboBoxSelectIfNeeded(Side side, Function function) {
		JComboBox<Function> combo = comboBoxes.get(side);
		if (combo.getSelectedItem() == function) {
			return;
		}
		combo.removeItemListener(comboListeners.get(side));
		combo.setSelectedItem(function);
		combo.addItemListener(comboListeners.get(side));
	}

	/**
	 * Cell renderer for combo boxes that changes the default display to show
	 * both the function name and the program it comes from
	 */
	private class FunctionListCellRenderer extends GComboBoxCellRenderer<Object> {

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
			Address functionAddress = f.getEntryPoint();
			String text = functionName + "@" + functionAddress + " (" + functionPathToProgram + ")";

			return super.getListCellRendererComponent(list, text, index, isSelected, cellHasFocus);
		}
	}
}
