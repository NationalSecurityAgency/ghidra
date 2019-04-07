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
package ghidra.app.plugin.core.memory;

import java.awt.BorderLayout;
import java.awt.CardLayout;

import javax.swing.*;
import javax.swing.event.*;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.plugin.core.misc.RegisterField;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * <CODE>AddBlockDialog</CODE> manages the dialog for adding and
 * editing MemoryBlocks.
 */

class AddBlockDialog extends DialogComponentProvider implements ChangeListener {

	private JTextField nameField;
	private AddressInput addrField;
	private RegisterField lengthField;
	private JTextField commentField;

	private JPanel viewPanel;
	private CardLayout cardLayout;
	private JPanel initializedPanel;
	private JPanel bottomPanel;
	private JRadioButton initializedRB;
	private JRadioButton uninitializedRB;

	private JCheckBox readCB;
	private JCheckBox writeCB;
	private JCheckBox executeCB;
	private JCheckBox volatileCB;
	private RegisterField initialValueField;
	private JLabel initialValueLabel;
	private AddressFactory addrFactory;
	private AddressInput baseAddrField; // used for BitMemoryBlocks
	private Address baseAddress;
	private AddBlockModel model;
	private GhidraComboBox<MemoryBlockType> comboBox;
	private boolean updatingInitializedRB;

	private final static String MAPPED = "Mapped";
	private final static String OTHER = "Other";

	AddBlockDialog(AddBlockModel model) {
		super("Add Memory Block", true, true, true, false);
		init(model);
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		setStatusText(model.getMessage());
		setOkEnabled(model.isValidInfo());
		readCB.setEnabled(model.isReadEnabled());
		writeCB.setEnabled(model.isWriteEnabled());
		executeCB.setEnabled(model.isExecuteEnabled());
		volatileCB.setEnabled(model.isVolatileEnabled());
		if (initializedRB != null) {
			updatingInitializedRB = true;
			try {
				initializedRB.setSelected(model.getInitializedState());
			}
			finally {
				updatingInitializedRB = false;
			}
		}
	}

	private void init(AddBlockModel blockModel) {
		this.model = blockModel;
		blockModel.setChangeListener(this);
		create();
		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP, "Add Block"));
	}

	/**
	 * Define the Main panel for the dialog here.
	 */
	private void create() {
		cardLayout = new CardLayout();
		viewPanel = new JPanel(cardLayout);

		nameField = new JTextField();
		nameField.setName("Block Name");

		addrField = new AddressInput();
		addrField.setName("Start Addr");

		lengthField = new RegisterField(32, null, false);
		lengthField.setName("Length");

		commentField = new JTextField();
		commentField.setName("Comment");

		addrFactory = model.getProgram().getAddressFactory();
		addrField.setAddressFactory(addrFactory, true);

		nameField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				nameChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				nameChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				nameChanged();
			}
		});

		lengthField.setChangeListener(e -> lengthChanged());
		addrField.addChangeListener(ev -> addrChanged());

		JLabel readLabel = new JLabel("Read");
		readCB = new JCheckBox();
		readCB.setName("Read");

		JLabel writeLabel = new JLabel("Write");
		writeCB = new JCheckBox();
		writeCB.setName("Write");

		JLabel executeLabel = new JLabel("Execute");
		executeCB = new JCheckBox();
		executeCB.setName("Execute");

		JLabel volatileLabel = new JLabel("Volatile");
		volatileCB = new JCheckBox();
		volatileCB.setName("Volatile");

		JPanel topPanel = new JPanel(new PairLayout(4, 10, 150));
		topPanel.setBorder(BorderFactory.createEmptyBorder(5, 7, 4, 5));
		topPanel.add(new JLabel("Block Name:", SwingConstants.RIGHT));
		topPanel.add(nameField);
		topPanel.add(new JLabel("Start Addr:", SwingConstants.RIGHT));
		topPanel.add(addrField);
		topPanel.add(new JLabel("Length:", SwingConstants.RIGHT));
		topPanel.add(lengthField);
		topPanel.add(new JLabel("Comment:", SwingConstants.RIGHT));
		topPanel.add(commentField);

		JPanel execPanel = new JPanel();
		BoxLayout bl = new BoxLayout(execPanel, BoxLayout.X_AXIS);
		execPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		execPanel.setLayout(bl);
		execPanel.add(Box.createHorizontalStrut(10));
		execPanel.add(readLabel);
		execPanel.add(readCB);
		execPanel.add(Box.createHorizontalStrut(10));

		execPanel.add(writeLabel);
		execPanel.add(writeCB);
		execPanel.add(Box.createHorizontalStrut(10));

		execPanel.add(executeLabel);
		execPanel.add(executeCB);
		execPanel.add(Box.createHorizontalStrut(10));

		execPanel.add(volatileLabel);
		execPanel.add(volatileCB);

		JPanel panel = new JPanel();
		panel.add(execPanel);

		JPanel outerTopPanel = new JPanel(new BorderLayout());
		outerTopPanel.add(topPanel, BorderLayout.NORTH);
		outerTopPanel.add(panel, BorderLayout.CENTER);

		bottomPanel = new JPanel();
		BoxLayout layout = new BoxLayout(bottomPanel, BoxLayout.Y_AXIS);
		bottomPanel.setLayout(layout);
		bottomPanel.setBorder(BorderFactory.createEmptyBorder(0, 7, 4, 5));
		bottomPanel.add(createComboBoxPanel());
		bottomPanel.add(viewPanel);

		JPanel mainPanel = new JPanel();
		layout = new BoxLayout(mainPanel, BoxLayout.Y_AXIS);
		mainPanel.setLayout(layout);
		mainPanel.add(outerTopPanel);
		mainPanel.add(bottomPanel);
		mainPanel.validate();

		JPanel mainPanel2 = new JPanel(new BorderLayout());
		mainPanel2.add(mainPanel, BorderLayout.NORTH);
		mainPanel2.add(new JPanel(), BorderLayout.CENTER);

		createCardPanels();

		addWorkPanel(mainPanel2);
		addOKButton();
		addCancelButton();
	}

	/**
	 * Display the dialog filled with default values.
	 * Used to enter a new MemoryBlock.
	 * @param nlines default value displayed in the text field.
	 */
	void showDialog(PluginTool tool) {

		nameField.setText("");
		addrField.setAddress(model.getStartAddress());

		lengthField.setValue(new Long(0));
		model.setLength(0);
		commentField.setText("");

		readCB.setSelected(true);
		writeCB.setSelected(true);
		executeCB.setSelected(false);
		volatileCB.setSelected(false);

		initialValueField.setValue(new Long(0));
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setIsInitialized(initializedRB.isSelected());
		model.setInitialValue(0);

		setOkEnabled(false);
		tool.showDialog(this, tool.getComponentProvider(PluginConstants.MEMORY_MAP));
	}

	public void dispose() {
		close();
		model.dispose();
	}

	/**
	 * Called when user selects OK button
	 */
	@Override
	protected void okCallback() {

		if (model.execute(commentField.getText(), readCB.isSelected(), writeCB.isSelected(),
			executeCB.isSelected(), volatileCB.isSelected())) {
			close();
		}
		else {
			setStatusText(model.getMessage());
			setOkEnabled(false);
		}
	}

	private void initializeRBChanged() {
		if (updatingInitializedRB) {
			return;
		}
		boolean selected = initializedRB.isSelected();
		model.setIsInitialized(selected);
		initialValueField.setEnabled(selected);
		initialValueLabel.setEnabled(selected);
		if (!selected) {
			initialValueField.setValue(new Long(0));
			model.setInitialValue(0);
		}
	}

	private void uninitializedRBChanged() {
		if (updatingInitializedRB) {
			return;
		}
		boolean selected = uninitializedRB.isSelected();
		model.setIsInitialized(!selected);
		initialValueField.setEnabled(!selected);
		initialValueLabel.setEnabled(!selected);
		if (!selected) {
			initialValueField.setValue(new Long(0));
			model.setInitialValue(0);
		}
	}

	/**
	 * Method initialValueChanged.
	 */
	private void initialValueChanged() {
		int initialValue = -1;
		Long val = initialValueField.getValue();
		if (val != null) {
			initialValue = val.intValue();
		}
		model.setInitialValue(initialValue);
	}

	private void nameChanged() {
		String name = nameField.getText().trim();
		model.setBlockName(name);
	}

	private void lengthChanged() {
		int length = 0;
		Long val = lengthField.getValue();
		if (val != null) {
			length = val.intValue();
		}
		model.setLength(length);
	}

	private void addrChanged() {
		Address addr = null;
		try {
			addr = addrField.getAddress();
		}
		catch (IllegalArgumentException e) {
		}
		model.setStartAddress(addr);
	}

	private void baseAddressChanged() {
		baseAddress = baseAddrField.getAddress();
		model.setBaseAddress(baseAddress);
	}

	private JPanel createComboBoxPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Block Types"));

		MemoryBlockType[] items = new MemoryBlockType[] { MemoryBlockType.DEFAULT,
			MemoryBlockType.OVERLAY, MemoryBlockType.BIT_MAPPED, MemoryBlockType.BYTE_MAPPED };

		comboBox = new GhidraComboBox<>(items);
		comboBox.addItemListener(e -> blockTypeSelected());
		panel.add(comboBox);
		return panel;
	}

	private void blockTypeSelected() {

		MemoryBlockType blockType = (MemoryBlockType) comboBox.getSelectedItem();
		model.setBlockType(blockType);
		if (blockType == MemoryBlockType.DEFAULT) {
			cardLayout.show(viewPanel, OTHER);
		}
		else if (blockType == MemoryBlockType.OVERLAY) {
			cardLayout.show(viewPanel, OTHER);
		}
		else if (blockType == MemoryBlockType.BIT_MAPPED) {
			cardLayout.show(viewPanel, MAPPED);
		}
		else {
			// type is Byte mapped
			cardLayout.show(viewPanel, MAPPED);
		}
	}

	private JPanel createRadioPanel() {
		JPanel panel = new JPanel();
		BoxLayout bl = new BoxLayout(panel, BoxLayout.X_AXIS);
		panel.setLayout(bl);

		ButtonGroup radioGroup = new ButtonGroup();
		initializedRB = new JRadioButton("Initialized", false);
		initializedRB.setName(initializedRB.getText());
		initializedRB.addActionListener(ev -> initializeRBChanged());

		uninitializedRB = new JRadioButton("Uninitialized", true);
		uninitializedRB.setName(uninitializedRB.getText());
		uninitializedRB.addActionListener(ev -> uninitializedRBChanged());

		radioGroup.add(initializedRB);
		radioGroup.add(uninitializedRB);

		panel.add(initializedRB);
		panel.add(uninitializedRB);

		JPanel outerPanel = new JPanel();
		BoxLayout bl2 = new BoxLayout(outerPanel, BoxLayout.Y_AXIS);
		outerPanel.setLayout(bl2);
		outerPanel.add(panel);
		createInitializedPanel();
		outerPanel.add(initializedPanel);
		outerPanel.setBorder(BorderFactory.createEtchedBorder());
		return outerPanel;
	}

	private void createCardPanels() {
		viewPanel.add(createAddressPanel(), MAPPED);
		viewPanel.add(createRadioPanel(), OTHER);
		cardLayout.show(viewPanel, OTHER);
	}

	private void createInitializedPanel() {
		initialValueLabel = new JLabel("Initial Value");
		initialValueField = new RegisterField(8, null, false);
		initialValueField.setName("Initial Value");
		initialValueField.setEnabled(false);

		initialValueField.setChangeListener(e -> initialValueChanged());

		initializedPanel = new JPanel(new PairLayout(4, 10));
		initializedPanel.setBorder(BorderFactory.createEmptyBorder(5, 7, 4, 5));
		initializedPanel.add(initialValueLabel);
		initializedPanel.add(initialValueField);
	}

	private JPanel createAddressPanel() {
		JPanel addressPanel = new JPanel(new PairLayout());

		JLabel addrToAddLabel = new JLabel("Source Addr:");
		baseAddrField = new AddressInput();
		baseAddrField.setAddressFactory(addrFactory);
		baseAddrField.setName("Source Addr");

		baseAddrField.addChangeListener(ev -> baseAddressChanged());

		Program program = model.getProgram();
		Address minAddr = program.getMinAddress();
		if (minAddr == null) {
			minAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		}
		baseAddrField.setAddress(minAddr);
		model.setBaseAddress(minAddr);
		addressPanel.add(addrToAddLabel);
		addressPanel.add(baseAddrField);
		addressPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		return addressPanel;
	}

}
