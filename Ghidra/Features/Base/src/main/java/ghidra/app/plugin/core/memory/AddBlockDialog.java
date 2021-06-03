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

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.plugin.core.memory.AddBlockModel.InitializedType;
import ghidra.app.plugin.core.misc.RegisterField;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.HelpLocation;
import ghidra.util.layout.HorizontalLayout;
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
	private CardLayout typeCardLayout;
	private JRadioButton initializedRB;
	private GRadioButton initializedFromFileBytesRB;
	private JRadioButton uninitializedRB;

	private JCheckBox readCB;
	private JCheckBox writeCB;
	private JCheckBox executeCB;
	private JCheckBox volatileCB;
	private JCheckBox overlayCB;
	private RegisterField initialValueField;
	private JLabel initialValueLabel;
	private AddressFactory addrFactory;
	private AddressInput baseAddrField; // used for Bit and Byte mapped blocks
	private IntegerTextField schemeDestByteCountField; // used for Byte mapped blocks
	private IntegerTextField schemeSrcByteCountField; // used for Byte mapped blocks
	
	private AddBlockModel model;
	private GhidraComboBox<MemoryBlockType> comboBox;
	private boolean updatingInitializedRB;
	private CardLayout initializedTypeCardLayout;

	private final static String MAPPED = "Mapped";
	private final static String UNMAPPED = "Unmapped";
	private static final String UNITIALIZED = "UNITIALIZED";
	private static final String INITIALIZED = "INITIALIZED";
	private static final String FILE_BYTES = "FILE_BYTES";
	private JPanel inializedTypePanel;
	private RegisterField fileOffsetField;
	private GhidraComboBox<FileBytes> fileBytesComboBox;

	AddBlockDialog(AddBlockModel model) {
		super("Add Memory Block", true, true, true, false);
		this.model = model;
		model.setChangeListener(this);
		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP, "Add Block"));
		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		setStatusText(model.getMessage());
		setOkEnabled(model.isValidInfo());
		readCB.setSelected(model.isRead());
		writeCB.setSelected(model.isWrite());
		executeCB.setSelected(model.isExecute());
		volatileCB.setSelected(model.isVolatile());
		overlayCB.setSelected(model.isOverlay());
	}

	/**
	 * Define the Main panel for the dialog here.
	 */
	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		panel.add(buildMainPanel(), BorderLayout.NORTH);
		panel.add(buildVariablePanel(), BorderLayout.CENTER);
		return panel;
	}

	private Component buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildBasicInfoPanel(), BorderLayout.NORTH);
		panel.add(buildPermissionsPanel(), BorderLayout.CENTER);
		panel.add(buildTypesPanel(), BorderLayout.SOUTH);

		return panel;
	}

	private Component buildBasicInfoPanel() {
		JPanel panel = new JPanel(new PairLayout(4, 10, 150));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 7, 4, 5));

		panel.add(new GLabel("Block Name:", SwingConstants.RIGHT));
		panel.add(buildNameField());
		panel.add(new GLabel("Start Addr:", SwingConstants.RIGHT));
		panel.add(buildAddressField());
		panel.add(new GLabel("Length:", SwingConstants.RIGHT));
		panel.add(buildLengthField());
		panel.add(new GLabel("Comment:", SwingConstants.RIGHT));
		panel.add(buildCommentField());

		return panel;
	}

	private Component buildPermissionsPanel() {

		readCB = new GCheckBox("Read");
		readCB.setName("Read");
		readCB.setSelected(model.isRead());
		readCB.addActionListener(e -> model.setRead(readCB.isSelected()));

		writeCB = new GCheckBox("Write");
		writeCB.setName("Write");
		writeCB.setSelected(model.isWrite());
		writeCB.addActionListener(e -> model.setWrite(writeCB.isSelected()));

		executeCB = new GCheckBox("Execute");
		executeCB.setName("Execute");
		executeCB.setSelected(model.isExecute());
		executeCB.addActionListener(e -> model.setExecute(executeCB.isSelected()));

		volatileCB = new GCheckBox("Volatile");
		volatileCB.setName("Volatile");
		volatileCB.setSelected(model.isVolatile());
		volatileCB.addActionListener(e -> model.setVolatile(volatileCB.isSelected()));

		overlayCB = new GCheckBox("Overlay");
		overlayCB.setName("Overlay");
		overlayCB.setSelected(model.isOverlay());
		overlayCB.addActionListener(e -> model.setOverlay(overlayCB.isSelected()));

		JPanel panel = new JPanel(new HorizontalLayout(10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 30, 20, 30));
		panel.add(readCB);
		panel.add(writeCB);
		panel.add(executeCB);
		panel.add(volatileCB);
		panel.add(overlayCB);

		return panel;
	}

	private Component buildTypesPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Block Types"));

		MemoryBlockType[] items = new MemoryBlockType[] { MemoryBlockType.DEFAULT,
			MemoryBlockType.BIT_MAPPED, MemoryBlockType.BYTE_MAPPED };

		comboBox = new GhidraComboBox<>(items);
		comboBox.addItemListener(e -> blockTypeSelected());
		panel.add(comboBox);
		return panel;
	}

	private Component buildVariablePanel() {
		typeCardLayout = new CardLayout();
		viewPanel = new JPanel(typeCardLayout);
		viewPanel.setBorder(BorderFactory.createEtchedBorder());

		viewPanel.add(buildMappedPanel(), MAPPED);
		viewPanel.add(buildUnmappedPanel(), UNMAPPED);
		typeCardLayout.show(viewPanel, UNMAPPED);
		return viewPanel;
	}

	private Component buildUnmappedPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildInitializedRadioButtonPanel(), BorderLayout.NORTH);
		panel.add(buildVariableInitializedPanel());
		return panel;
	}

	private Component buildInitializedRadioButtonPanel() {
		JPanel panel = new JPanel(new HorizontalLayout(10));

		ButtonGroup radioGroup = new ButtonGroup();
		initializedRB = new GRadioButton("Initialized", false);
		initializedRB.setName(initializedRB.getText());
		initializedRB.addActionListener(ev -> initializeRBChanged());

		initializedFromFileBytesRB = new GRadioButton("File Bytes", false);
		initializedFromFileBytesRB.setName(initializedRB.getText());
		initializedFromFileBytesRB.addActionListener(ev -> initializeRBChanged());

		uninitializedRB = new GRadioButton("Uninitialized", true);
		uninitializedRB.setName(uninitializedRB.getText());
		uninitializedRB.addActionListener(ev -> initializeRBChanged());

		radioGroup.add(initializedRB);
		radioGroup.add(initializedFromFileBytesRB);
		radioGroup.add(uninitializedRB);

		panel.add(initializedRB);
		panel.add(initializedFromFileBytesRB);
		panel.add(uninitializedRB);

		return panel;
	}

	private Component buildVariableInitializedPanel() {
		initializedTypeCardLayout = new CardLayout();

		inializedTypePanel = new JPanel(initializedTypeCardLayout);
		inializedTypePanel.add(new JPanel(), UNITIALIZED);
		inializedTypePanel.add(buildInitalValuePanel(), INITIALIZED);
		inializedTypePanel.add(buildFileBytesPanel(), FILE_BYTES);
		return inializedTypePanel;
	}

	private Component buildInitalValuePanel() {
		initialValueLabel = new GDLabel("Initial Value");
		initialValueField = new RegisterField(8, null, false);
		initialValueField.setName("Initial Value");

		initialValueField.setChangeListener(e -> initialValueChanged());

		JPanel panel = new JPanel(new PairLayout(4, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 7, 4, 5));
		panel.add(initialValueLabel);
		panel.add(initialValueField);
		return panel;
	}

	private Component buildFileBytesPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 7, 4, 5));

		panel.add(new GLabel("File Bytes:"));
		panel.add(buildFileBytesCombo());
		panel.add(new GLabel("File Offset:"));
		panel.add(buildFileOffsetField());

		return panel;
	}

	private Component buildFileBytesCombo() {
		Memory memory = model.getProgram().getMemory();
		List<FileBytes> allFileBytes = memory.getAllFileBytes();
		FileBytes[] fileBytes = allFileBytes.toArray(new FileBytes[allFileBytes.size()]);

		fileBytesComboBox = new GhidraComboBox<>(fileBytes) {
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = 100;
				return preferredSize;
			}
		};
		fileBytesComboBox.addItemListener(e -> fileBytesChanged());
		if (!allFileBytes.isEmpty()) {
			model.setFileBytes(allFileBytes.get(0));
		}
		return fileBytesComboBox;
	}

	/**
	 * Display the dialog filled with default values.
	 * Used to enter a new MemoryBlock.
	 * @param tool the tool that owns this dialog
	 */
	void showDialog(PluginTool tool) {

		nameField.setText("");
		addrField.setAddress(model.getStartAddress());

		lengthField.setValue(Long.valueOf(0));
		model.setLength(0);
		commentField.setText("");
		initialValueField.setValue(Long.valueOf(0));
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setInitializedType(AddBlockModel.InitializedType.UNITIALIZED);
		model.setInitialValue(0);

		readCB.setSelected(model.isRead());
		writeCB.setSelected(model.isWrite());
		executeCB.setSelected(model.isExecute());
		volatileCB.setSelected(model.isVolatile());
		overlayCB.setSelected(model.isOverlay());

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
		if (model.execute()) {
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
		if (initializedRB.isSelected()) {
			model.setInitializedType(InitializedType.INITIALIZED_FROM_VALUE);
			initializedTypeCardLayout.show(inializedTypePanel, INITIALIZED);
		}
		else if (uninitializedRB.isSelected()) {
			model.setInitializedType(InitializedType.UNITIALIZED);
			initializedTypeCardLayout.show(inializedTypePanel, UNITIALIZED);
		}
		else if (initializedFromFileBytesRB.isSelected()) {
			model.setInitializedType(InitializedType.INITIALIZED_FROM_FILE_BYTES);
			initializedTypeCardLayout.show(inializedTypePanel, FILE_BYTES);
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

	private void commentChanged() {
		String comment = commentField.getText().trim();
		model.setComment(comment);
	}

	private void lengthChanged() {
		long length = 0;
		Long val = lengthField.getValue();
		if (val != null) {
			length = val.longValue();
		}
		model.setLength(length);
	}

	private void fileOffsetChanged() {
		long fileOffset = -1;
		Long val = fileOffsetField.getValue();
		if (val != null) {
			fileOffset = val.longValue();
		}
		model.setFileOffset(fileOffset);
	}

	private void fileBytesChanged() {
		model.setFileBytes((FileBytes) fileBytesComboBox.getSelectedItem());
	}

	private void addrChanged() {
		Address addr = null;
		try {
			addr = addrField.getAddress();
		}
		catch (IllegalArgumentException e) {
			// just let it be null
		}
		model.setStartAddress(addr);
	}

	private void baseAddressChanged() {
		Address addr = null;
		try {
			addr = baseAddrField.getAddress();
		}
		catch (IllegalArgumentException e) {
			// just let it be null
		}
		model.setBaseAddress(addr);
	}
	
	private void schemeSrcByteCountChanged() {
		int value = schemeSrcByteCountField.getIntValue();
		model.setSchemeSrcByteCount(value);
	}

	private void schemeDestByteCountChanged() {
		int value = schemeDestByteCountField.getIntValue();
		model.setSchemeDestByteCount(value);
	}

	private void blockTypeSelected() {
		MemoryBlockType blockType = (MemoryBlockType) comboBox.getSelectedItem();
		model.setBlockType(blockType);
		if (blockType == MemoryBlockType.DEFAULT) {
			typeCardLayout.show(viewPanel, UNMAPPED);
		}
		else {
			enableByteMappingSchemeControls(blockType == MemoryBlockType.BYTE_MAPPED);
			schemeDestByteCountField.setValue(model.getSchemeDestByteCount());
			schemeSrcByteCountField.setValue(model.getSchemeSrcByteCount());
			typeCardLayout.show(viewPanel, MAPPED);
		}
	}

	private void enableByteMappingSchemeControls(boolean b) {
		schemeDestByteCountField.setValue(1);
		schemeDestByteCountField.setEnabled(b);
		schemeSrcByteCountField.setValue(1);
		schemeSrcByteCountField.setEnabled(b);
	}

	private JPanel buildMappedPanel() {
		JPanel panel = new JPanel(new PairLayout());

		baseAddrField = new AddressInput();
		baseAddrField.setAddressFactory(addrFactory);
		baseAddrField.setName("Source Addr");
		baseAddrField.addChangeListener(ev -> baseAddressChanged());
		
		JPanel schemePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		
		schemeDestByteCountField = new IntegerTextField(4, 1);
		schemeDestByteCountField.setAllowNegativeValues(false);
		schemeDestByteCountField.setAllowsHexPrefix(false);
		schemeDestByteCountField.setDecimalMode();
		schemeDestByteCountField.addChangeListener(ev -> schemeDestByteCountChanged());
		
		schemeSrcByteCountField = new IntegerTextField(4, 1);
		schemeSrcByteCountField.setAllowNegativeValues(false);
		schemeSrcByteCountField.setAllowsHexPrefix(false);
		schemeSrcByteCountField.setDecimalMode();
		schemeSrcByteCountField.addChangeListener(ev -> schemeSrcByteCountChanged());
		
		schemePanel.add(schemeDestByteCountField.getComponent());
		schemePanel.add(new GLabel(" : "));
		schemePanel.add(schemeSrcByteCountField.getComponent());

		Program program = model.getProgram();
		Address minAddr = program.getMinAddress();
		if (minAddr == null) {
			minAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		}
		baseAddrField.setAddress(minAddr);
		model.setBaseAddress(minAddr);
		panel.add(new GLabel("Source Address:"));
		panel.add(baseAddrField);
		
		panel.add(new GLabel("Mapping Ratio:"));
		panel.add(schemePanel);
		
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		return panel;
	}

	private Component buildCommentField() {
		commentField = new JTextField();
		commentField.setName("Comment");
		commentField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				commentChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				commentChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				commentChanged();
			}
		});
		return commentField;
	}

	private Component buildLengthField() {
		lengthField = new RegisterField(36, null, false);
		lengthField.setName("Length");
		lengthField.setChangeListener(e -> lengthChanged());
		return lengthField;
	}

	private Component buildFileOffsetField() {
		fileOffsetField = new RegisterField(60, null, false);
		fileOffsetField.setName("File Offset");
		fileOffsetField.setChangeListener(e -> fileOffsetChanged());
		return fileOffsetField;
	}

	private Component buildAddressField() {
		addrField = new AddressInput();
		addrField.setName("Start Addr");
		addrFactory = model.getProgram().getAddressFactory();
		addrField.setAddressFactory(addrFactory, true, true);
		addrField.addChangeListener(ev -> addrChanged());
		return addrField;
	}

	private Component buildNameField() {
		nameField = new JTextField();
		nameField.setName("Block Name");
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
		return nameField;
	}

}
