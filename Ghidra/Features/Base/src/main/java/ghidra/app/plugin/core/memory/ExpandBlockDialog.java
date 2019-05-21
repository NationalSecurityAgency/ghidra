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
import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.misc.RegisterField;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * 
 * Dialog to expand the size of a block; uses a model to validate
 * the fields and expand the block. 
 * 
 */
class ExpandBlockDialog extends DialogComponentProvider implements ChangeListener {

	final static int EXPAND_UP = 0;
	final static int EXPAND_DOWN = 1;

	private final static String EXPAND_UP_TITLE = "Expand Block Up";
	private final static String EXPAND_DOWN_TITLE = "Expand Block Down";
	private int dialogType;
	private AddressFactory addrFactory;
	private AddressInput startAddressInput;
	private AddressInput endAddressInput;
	private JTextField startField;
	private JTextField endField;
	private RegisterField lengthField;
	private ExpandBlockModel model;
	private boolean isChanging;
	private PluginTool tool;

	/**
	 * Constructor
	 * @param parent
	 * @param block
	 * @param af
	 * @param dialogType
	 */
	ExpandBlockDialog(PluginTool tool, ExpandBlockModel model, MemoryBlock block, AddressFactory af,
			int dialogType) {
		super(dialogType == EXPAND_UP ? EXPAND_UP_TITLE : EXPAND_DOWN_TITLE, true);
		this.tool = tool;
		this.model = model;
		this.dialogType = dialogType;
		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP,
			dialogType == EXPAND_UP ? EXPAND_UP_TITLE : EXPAND_DOWN_TITLE));
		addrFactory = af;
		model.setChangeListener(this);
		addWorkPanel(create(block));
		addOKButton();
		addCancelButton();
		setOkEnabled(false);
		addListeners();

	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {

		Runnable doExpand = new Runnable() {
			@Override
			public void run() {
				if (model.execute()) {
					close();
				}
				else {
					setStatusText(model.getMessage());
					setOkEnabled(false);
				}
				rootPanel.setCursor(Cursor.getDefaultCursor());
			}
		};

		rootPanel.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		SwingUtilities.invokeLater(doExpand);
	}

	/**
	 * Create the main work panel.
	 * @return JPanel
	 */
	private JPanel create(MemoryBlock block) {
		JPanel panel = new JPanel(new PairLayout(5, 5, 150));
		startAddressInput = new AddressInput();
		startAddressInput.setName("NewStartAddress");
		startAddressInput.setAddressFactory(addrFactory);
		endAddressInput = new AddressInput();
		endAddressInput.setName("EndAddress");
		endAddressInput.setAddressFactory(addrFactory);
		Address start = block.getStart();
		Address end = block.getEnd();

		startAddressInput.setAddress(start);
		startAddressInput.setAddressSpaceEditable(false);
		endAddressInput.setAddress(end);
		endAddressInput.setAddressSpaceEditable(false);

		boolean isExpandUp = dialogType == EXPAND_UP;

		startField = new JTextField(10);
		startField.setName("StartAddress");
		startField.setEnabled(isExpandUp);
		startField.setText(start.toString());

		endField = new JTextField(10);
		endField.setName("EndAddress");
		endField.setEnabled(!isExpandUp);
		endField.setText(end.toString());

		lengthField = new RegisterField(32, null, false);
		lengthField.setName("BlockLength");
		lengthField.setValue(Long.valueOf(model.getLength()));

		panel.add(
			new GLabel(isExpandUp ? "New Start Address:" : "Start Address:", SwingConstants.RIGHT));
		panel.add(isExpandUp ? (JComponent) startAddressInput : startField);
		panel.add(
			new GLabel(isExpandUp ? "End Address:" : "New End Address:", SwingConstants.RIGHT));
		panel.add(isExpandUp ? (JComponent) endField : endAddressInput);
		panel.add(new GLabel("Block Length:", SwingConstants.RIGHT));
		panel.add(lengthField);

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(panel, BorderLayout.CENTER);
		return mainPanel;
	}

	private void addListeners() {

		startAddressInput.addChangeListener(new AddressChangeListener());
		endAddressInput.addChangeListener(new AddressChangeListener());
		lengthField.setChangeListener(new LengthChangeListener());

		ActionListener al = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setStatusText("");
			}
		};
		startField.addActionListener(al);
		endField.addActionListener(al);
		lengthField.addActionListener(al);
		startAddressInput.addActionListener(al);
		endAddressInput.addActionListener(al);
	}

	/**
	 * Listener on the length text fields; update other fields
	 * according to the entered value.
	 */
	private class LengthChangeListener implements ChangeListener {

		@Override
		public void stateChanged(ChangeEvent e) {
			if (isChanging) {
				return;
			}
			setStatusText("");
			lengthChanged();
		}

		private void lengthChanged() {
			long length = 0;
			Long val = lengthField.getValue();
			if (val == null) {
				setOkEnabled(false);
			}
			else {
				length = val.longValue();
			}
			model.setLength(length);
		}
	}

	/**
	 * Listener on the AddressInput field; update length field when the 
	 * address input field changes.
	 */
	private class AddressChangeListener implements ChangeListener {

		@Override
		public void stateChanged(ChangeEvent event) {
			if (isChanging) {
				return;
			}
			setStatusText("");
			addressChanged();
		}

		private void addressChanged() {
			if (dialogType == EXPAND_UP) {
				Address startAddr = startAddressInput.getAddress();
				if (startAddr == null) {
					if (startAddressInput.hasInput()) {
						setStatusText("Invalid Address");
					}
					setOkEnabled(false);
				}
				model.setStartAddress(startAddr);
			}
			else {
				Address endAddr = endAddressInput.getAddress();
				if (endAddr == null) {
					if (endAddressInput.hasInput()) {
						setStatusText("Invalid Address");
					}
					setOkEnabled(false);
				}
				model.setEndAddress(endAddr);
			}
		}
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {

		String message = model.getMessage();
		setStatusText(message);
		setOkEnabled(message.length() == 0);
		lengthField.setValue(new Long(model.getLength()));
		Address startAddr = model.getStartAddress();
		Address endAddr = model.getEndAddress();
		isChanging = true;
		if (dialogType == EXPAND_UP && startAddr != null) {
			startAddressInput.setAddress(startAddr);
		}
		else if (endAddr != null) {
			endAddressInput.setAddress(endAddr);
		}
		isChanging = false;

		if (!isVisible()) {
			setOkEnabled(false);
			ComponentProvider provider = tool.getComponentProvider(PluginConstants.MEMORY_MAP);
			tool.showDialog(this, provider);// this blocks, so dispose model when dialog is dismissed.
			model.dispose();
		}
	}

}
