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
package ghidra.app.util;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashSet;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;

import docking.widgets.label.GDLabel;
import ghidra.program.model.address.*;
import ghidra.util.layout.MiddleLayout;
import resources.ResourceManager;

public class AddressSetEditorPanel extends JPanel {
	private static Icon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private static Icon SUBTRACT_ICON = ResourceManager.loadImage("images/list-remove.png");

	private AddressInput minAddressField;
	private AddressInput maxAddressField;
	private JButton addRangeButton;
	private JPanel bottomButtons;
	private JButton removeRangeButton;
	private AddressSetListModel listModel;
	private JList<AddressRange> list;
	private HashSet<ChangeListener> listeners = new HashSet<>();
	private JButton subtractRangeButton;
	private final AddressSet addressSet;
	private final AddressFactory addressFactory;

	public AddressSetEditorPanel(AddressFactory addressFactory, AddressSetView addressSet) {

		super(new BorderLayout());
		this.addressFactory = addressFactory;
		this.addressSet = new AddressSet(addressSet);

		setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 0));
		add(createAddRangePanel(), BorderLayout.NORTH);
		add(createRangeListPanel(), BorderLayout.CENTER);
		add(createRemoveRangePanel(), BorderLayout.SOUTH);
		validateAddRemoveButton();
		validateRemoveButton();

	}

	private JPanel createAddRangePanel() {
		JPanel minAddressPanel = new JPanel();
		minAddressPanel.setLayout(new BorderLayout());
		JLabel minLabel = new GDLabel("Min:");
		minLabel.setToolTipText("Enter minimum address to add or remove");
		minAddressPanel.add(minLabel, BorderLayout.WEST);
		minAddressField = new AddressInput();
		minAddressField.setAddressFactory(addressFactory);
		ChangeListener listener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				validateAddRemoveButton();
			}
		};
		minAddressField.addChangeListener(listener);
		minAddressPanel.add(minAddressField, BorderLayout.CENTER);

		JPanel maxAddressPanel = new JPanel();
		maxAddressPanel.setLayout(new BorderLayout());
		JLabel maxLabel = new GDLabel("Max:");
		maxLabel.setToolTipText("Enter maximum address to add or remove");
		maxAddressPanel.add(maxLabel, BorderLayout.WEST);
		maxAddressField = new AddressInput();
		maxAddressField.setAddressFactory(addressFactory);
		maxAddressField.addChangeListener(listener);
		maxAddressPanel.add(maxAddressField, BorderLayout.CENTER);
		maxAddressPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		addRangeButton = new JButton(ADD_ICON);
		addRangeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				addRange();
			}
		});
		addRangeButton.setToolTipText("Add the range to the set of included addresses");
		subtractRangeButton = new JButton(SUBTRACT_ICON);
		subtractRangeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				subtractRange();
			}
		});
		subtractRangeButton.setToolTipText("Remove the range from the set of included addresses");

		JPanel addressPanel = new JPanel();
		addressPanel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEmptyBorder(10, 10, 20, 10), "Add/Remove Address Range"));

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.weightx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		addressPanel.setLayout(new GridBagLayout());
		addressPanel.add(minAddressPanel, gbc);

		gbc.gridx = 1;
		addressPanel.add(maxAddressPanel, gbc);

		gbc.gridx = 2;
		gbc.weightx = 0;
		gbc.fill = GridBagConstraints.NONE;
		addressPanel.add(addRangeButton, gbc);

		gbc.gridx = 3;
		addressPanel.add(subtractRangeButton, gbc);

		return addressPanel;
	}

	private Component createRemoveRangePanel() {
		bottomButtons = new JPanel();
		bottomButtons.setLayout(new MiddleLayout());

		removeRangeButton = new JButton("Remove Selected Range(s)");
		removeRangeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				removeRange();
			}
		});

		bottomButtons.add(removeRangeButton);
		return bottomButtons;
	}

	private Component createRangeListPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		listModel = new AddressSetListModel(addressSet.toList());
		list = new JList<>(listModel);
		list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		list.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				validateRemoveButton();
			}
		});
		JScrollPane scrollPane = new JScrollPane(list);
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEmptyBorder(10, 10, 10, 10), "Included Address Ranges:"));
		panel.add(scrollPane);

		return panel;
	}

	public synchronized AddressSetView getAddressSetView() {
		return new AddressSet(addressSet);
	}

	private synchronized void removeRange() {
		int[] selectedIndices = list.getSelectedIndices();
		AddressSet removeRanges = new AddressSet();
		for (int selectedIndice : selectedIndices) {
			AddressRange addressRange = listModel.getElementAt(selectedIndice);
			removeRanges.add(addressRange);
		}
		addressSet.delete(removeRanges);
		listModel.setData(addressSet.toList());
		list.clearSelection();
		notifyListeners();
	}

	private synchronized void addRange() {
		Address minAddress = getMinAddress();
		Address maxAddress = getMaxAddress();
		addressSet.addRange(minAddress, maxAddress);
		listModel.setData(addressSet.toList());
		notifyListeners();
		minAddressField.clear();
		maxAddressField.clear();
		minAddressField.requestFocus();
	}

	private synchronized void subtractRange() {
		Address minAddress = getMinAddress();
		Address maxAddress = getMaxAddress();
		addressSet.deleteRange(minAddress, maxAddress);
		listModel.setData(addressSet.toList());
		notifyListeners();
		minAddressField.clear();
		maxAddressField.clear();
		minAddressField.requestFocus();
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

	private Address getMinAddress() {
		return minAddressField.getAddress();
	}

	private Address getMaxAddress() {
		return maxAddressField.getAddress();
	}

	private void validateRemoveButton() {
		int selectedIndex = list.getSelectedIndex();
		boolean enabled = selectedIndex != -1;
		removeRangeButton.setEnabled(enabled);
	}

	private void validateAddRemoveButton() {
		boolean valid = hasValidMinMax();
		addRangeButton.setEnabled(valid);
		subtractRangeButton.setEnabled(valid);
	}

	private boolean hasValidMinMax() {
		Address maxAddress = getMaxAddress();
		if (maxAddress == null) {
			return false;
		}
		Address minAddress = getMinAddress();
		if (minAddress == null) {
			return false;
		}
		if (!minAddress.getAddressSpace().equals(maxAddress.getAddressSpace())) {
			return false;
		}
		if (minAddress.compareTo(maxAddress) > 0) {
			return false;
		}
		return true;
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
