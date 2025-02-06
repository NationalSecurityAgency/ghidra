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
package ghidra.feature.vt.gui.wizard.add;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GButton;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.list.GList;
import generic.theme.GIcon;
import ghidra.feature.vt.gui.wizard.add.AddToSessionData.AddressSetChoice;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.MiddleLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for manually adjusting address sets. 
 */
public class ChooseAddressSetEditorPanel extends JPanel {

	private static Icon ADD_ICON = new GIcon("icon.version.tracking.add");
	private static Icon SUBTRACT_ICON = new GIcon("icon.version.tracking.subtract");

	private PluginTool tool;
	private final String name;
	private final Program program;
	private boolean hasSelection = false;
	private AddressSet myCurrentAddressSet;
	private AddressSetChoice currentAddressSetChoice;
	private JRadioButton entireProgramButton;
	private JRadioButton toolSelectionButton;
	private JRadioButton myRangesButton;
	private JButton addRangeButton;
	private JButton subtractRangeButton;
	private JButton removeRangeButton;
	private JPanel bottomButtons;
	private AddressSetListModel listModel;
	private GList<AddressRange> list;
	private Set<ChangeListener> listeners = new HashSet<>();

	public ChooseAddressSetEditorPanel(final PluginTool tool, final String name,
			final Program program, final AddressSetView selectionAddressSet,
			final AddressSetView myInitialAddressSet,
			final AddressSetChoice initialAddressSetChoice) {

		super(new BorderLayout());

		this.tool = tool;
		this.name = name;
		this.program = program;

		if (selectionAddressSet != null && !selectionAddressSet.isEmpty()) {
			hasSelection = true;
		}

		if (myInitialAddressSet != null && !myInitialAddressSet.isEmpty()) {
			myCurrentAddressSet = new AddressSet(myInitialAddressSet);
		}
		else {
			if (hasSelection) {
				myCurrentAddressSet = new AddressSet(selectionAddressSet);
			}
			else {
				myCurrentAddressSet = new AddressSet(program.getMemory());
			}
		}

		setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), name));

		add(createChooseSourcePanel(), BorderLayout.NORTH);
		add(createRangeListPanel(), BorderLayout.CENTER);
		switch (initialAddressSetChoice) {
			case SELECTION:
				toolSelectionButton.setSelected(true);
				choseToolSelection();
				break;
			case MANUALLY_DEFINED:
				myRangesButton.setSelected(true);
				choseMyRanges();
				break;
			case ENTIRE_PROGRAM:
			default:
				entireProgramButton.setSelected(true);
				choseEntireProgram();
				break;
		}
	}

	private JPanel createChooseSourcePanel() {
		JPanel chooseSourcePanel = new JPanel(new VerticalLayout(5));

		ButtonGroup originGroup = new ButtonGroup();
		entireProgramButton = new GRadioButton("Use Entire " + name + " Program", false);
		toolSelectionButton = new GRadioButton("Use " + name + " Tool's Selection", false);
		myRangesButton = new GRadioButton("Specify My Own Address Ranges", false);
		originGroup.add(entireProgramButton);
		originGroup.add(toolSelectionButton);
		originGroup.add(myRangesButton);

		entireProgramButton.setToolTipText(
			"Don't limit the address ranges. Use all addresses in the " + name + " program.");
		toolSelectionButton.setToolTipText("Limit the address ranges from the " + name +
			" program to those that are selected in the " + name + " Tool.");
		myRangesButton.setToolTipText("Limit the address ranges from the " + name +
			" program to those that I am specifying here.");

		entireProgramButton.addActionListener(ev -> choseEntireProgram());
		toolSelectionButton.addActionListener(ev -> choseToolSelection());
		myRangesButton.addActionListener(ev -> choseMyRanges());

		chooseSourcePanel.add(entireProgramButton);
		chooseSourcePanel.add(toolSelectionButton);
		chooseSourcePanel.add(myRangesButton);

		toolSelectionButton.setEnabled(hasSelection);

		return chooseSourcePanel;
	}

	protected void choseEntireProgram() {
		currentAddressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;
		validateAddRemoveButton();
		list.setEnabled(false);
		validateRemoveButton();
	}

	protected void choseToolSelection() {
		currentAddressSetChoice = AddressSetChoice.SELECTION;
		validateAddRemoveButton();
		list.setEnabled(false);
		validateRemoveButton();
	}

	protected void choseMyRanges() {
		currentAddressSetChoice = AddressSetChoice.MANUALLY_DEFINED;
		validateAddRemoveButton();
		list.setEnabled(true);
		validateRemoveButton();
	}

	protected void setAddressSet(AddressSet addressSet) {
		listModel.setData(addressSet.toList());
		list.clearSelection();
		notifyListeners();
	}

	private Component createRemoveRangePanel() {
		bottomButtons = new JPanel();
		bottomButtons.setLayout(new MiddleLayout());

		removeRangeButton = new GButton("Remove Selected Range(s)");
		removeRangeButton.addActionListener(e -> removeRange());

		bottomButtons.add(removeRangeButton);
		return bottomButtons;
	}

	private Component createRangeListPanel() {

		addRangeButton = new GButton(ADD_ICON);
		addRangeButton.addActionListener(e -> showAddRangeDialog());
		addRangeButton.setToolTipText("Add the range to the set of included addresses");

		subtractRangeButton = new GButton(SUBTRACT_ICON);
		subtractRangeButton.addActionListener(e -> showSubtractRangeDialog());
		subtractRangeButton.setToolTipText("Remove the range from the set of included addresses");

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(addRangeButton);
		buttonPanel.add(subtractRangeButton);
		JPanel headerPanel = new JPanel(new BorderLayout());
		headerPanel.add(new GLabel("Address Ranges:"), BorderLayout.WEST);
		headerPanel.add(buttonPanel, BorderLayout.EAST);

		listModel = new AddressSetListModel(myCurrentAddressSet.toList());
		list = new GList<>(listModel);
		list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		list.getSelectionModel().addListSelectionListener(e -> validateRemoveButton());
		JScrollPane scrollPane = new JScrollPane(list);

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		panel.add(headerPanel, BorderLayout.NORTH);
		panel.add(scrollPane, BorderLayout.CENTER);
		panel.add(createRemoveRangePanel(), BorderLayout.SOUTH);

		return panel;
	}

	protected void showAddRangeDialog() {
		AddRemoveAddressRangeDialog addRangeDialog =
			new AddRemoveAddressRangeDialog("Add", name, program, r -> addRange(r));
		tool.showDialog(addRangeDialog, this.getRootPane());
	}

	protected void showSubtractRangeDialog() {
		AddRemoveAddressRangeDialog removeRangeDialog =
			new AddRemoveAddressRangeDialog("Remove", name, program, r -> subtractRange(r));
		tool.showDialog(removeRangeDialog, this.getRootPane());
	}

	public synchronized AddressSetView getAddressSetView() {
		return new AddressSet(myCurrentAddressSet);
	}

	public synchronized boolean isUsingSelection() {
		return toolSelectionButton.isSelected();
	}

	private synchronized void removeRange() {
		int[] selectedIndices = list.getSelectedIndices();
		AddressSet removeRanges = new AddressSet();
		for (int selectedIndex : selectedIndices) {
			AddressRange addressRange = listModel.getElementAt(selectedIndex);
			removeRanges.add(addressRange);
		}
		myCurrentAddressSet.delete(removeRanges);
		listModel.setData(myCurrentAddressSet.toList());
		list.clearSelection();
		notifyListeners();
	}

	private synchronized void addRange(AddressRange range) {
		myCurrentAddressSet.add(range);
		listModel.setData(myCurrentAddressSet.toList());
		notifyListeners();
	}

	private synchronized void subtractRange(AddressRange range) {
		myCurrentAddressSet.delete(range);
		listModel.setData(myCurrentAddressSet.toList());
		notifyListeners();
	}

	private void notifyListeners() {
		ChangeEvent e = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			listener.stateChanged(e);
		}
	}

	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void validateRemoveButton() {
		int selectedIndex = list.getSelectedIndex();
		boolean enabled = (selectedIndex != -1) && myRangesButton.isSelected();
		removeRangeButton.setEnabled(enabled);
	}

	private void validateAddRemoveButton() {
		boolean isUsingMyRanges = myRangesButton.isSelected();
		addRangeButton.setEnabled(isUsingMyRanges);
		subtractRangeButton.setEnabled(isUsingMyRanges);
	}

	public AddressSetChoice getAddressSetChoice() {
		return currentAddressSetChoice;
	}

	static class AddressSetListModel extends AbstractListModel<AddressRange> {
		private List<AddressRange> addressList;

		AddressSetListModel(List<AddressRange> list) {
			this.addressList = list;
		}

		public void setData(List<AddressRange> list) {
			this.addressList = list;
			fireContentsChanged(this, 0, list.size());
		}

		@Override
		public AddressRange getElementAt(int index) {
			return addressList.get(index);
		}

		@Override
		public int getSize() {
			return addressList.size();
		}

	}
}
