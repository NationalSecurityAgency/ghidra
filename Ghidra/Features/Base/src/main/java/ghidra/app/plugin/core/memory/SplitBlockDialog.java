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

import java.awt.Cursor;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.misc.RegisterField;
import ghidra.app.util.AddressInput;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HelpLocation;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;

/**
 * 
 *
 * Dialog to split a memory block.
 */
class SplitBlockDialog extends DialogComponentProvider {

	private JTextField blockOneNameField;
	private JTextField blockOneStartField;
	private AddressInput blockOneEnd;
	private RegisterField blockOneLengthField;
	private JTextField blockTwoNameField;
	private AddressInput blockTwoStart;
	private JTextField blockTwoEndField;
	private RegisterField blockTwoLengthField;
	private MemoryBlock block;
	private MemoryMapPlugin plugin;

	SplitBlockDialog(MemoryMapPlugin plugin, MemoryBlock block, Program program) {
		super("Split Block");
		this.plugin = plugin;
		this.block = block;
		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP, "Split Block"));
		addWorkPanel(create(program));
		addOKButton();
		addCancelButton();
		setOkEnabled(false);
		setFields();
		addListeners();
	}

	@Override
	protected void okCallback() {
		// call plugin to do the work
		String newBlockName = blockTwoNameField.getText();
		if (newBlockName.length() == 0) {
			newBlockName = block.getName() + ".split";
			blockTwoNameField.setText(newBlockName);
		}
		if (!Memory.isValidMemoryBlockName(newBlockName)) {
			setStatusText("Invalid Block Name: " + newBlockName);
			return;
		}
		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		plugin.getMemoryMapManager().splitBlock(block, blockTwoStart.getAddress(), newBlockName);
		close();
	}

	/////////////////////////////////////////////////////////////////////////
	/**
	 * Create the work panel.
	 * @return JPanel
	 */
	private JPanel create(Program program) {
		JPanel panelOne = new JPanel(new PairLayout(5, 10, 150));
		panelOne.setBorder(BorderFactory.createTitledBorder("Block to Split"));
		blockOneNameField = new JTextField(10);
		blockOneNameField.setName("BlockOneName");
		blockOneNameField.getAccessibleContext().setAccessibleName("Name of Block To Split");
		blockOneStartField = new JTextField(10);
		blockOneStartField.setName("BlockOneStart");
		blockOneStartField.getAccessibleContext().setAccessibleName("Address of Block To Split");

		blockOneEnd = new AddressInput(program, this::blockOneEndChanged);
		blockOneEnd.setName("BlockOneEnd");
		blockOneEnd.setAccessibleName("New Block End Adddress");

		blockOneLengthField = new RegisterField(32, null, false);
		blockOneLengthField.setName("BlockOneLength");
		blockOneLengthField.getAccessibleContext().setAccessibleName("New Block Length");

		panelOne.add(new GLabel("Block Name:", SwingConstants.RIGHT));
		panelOne.add(blockOneNameField);
		panelOne.add(new GLabel("Start Address:", SwingConstants.RIGHT));
		panelOne.add(blockOneStartField);
		panelOne.add(new GLabel("End Address:", SwingConstants.RIGHT));
		panelOne.add(blockOneEnd);
		panelOne.add(new GLabel("Block Length:", SwingConstants.RIGHT));
		panelOne.add(blockOneLengthField);

		JPanel panelTwo = new JPanel(new PairLayout(5, 5, 150));
		panelTwo.setBorder(BorderFactory.createTitledBorder("New Block"));
		blockTwoNameField = new JTextField(10);
		blockTwoNameField.setName("BlockTwoName");
		blockTwoNameField.getAccessibleContext().setAccessibleName("Name of New Block");
		blockTwoStart = new AddressInput(program, this::blockTwoStartChanged);
		blockTwoStart.setName("BlockTwoStart");
		blockTwoStart.setAccessibleName("New Block Start Address");
		blockTwoEndField = new JTextField(10);
		blockTwoEndField.setName("BlockTwoEnd");

		blockTwoLengthField = new RegisterField(32, null, false);
		blockTwoLengthField.setName("BlockTwoLength");
		blockTwoLengthField.getAccessibleContext().setAccessibleName("New Block Size");

		panelTwo.add(new GLabel("Block Name:", SwingConstants.RIGHT));
		panelTwo.add(blockTwoNameField);
		panelTwo.add(new GLabel("Start Address:", SwingConstants.RIGHT));
		panelTwo.add(blockTwoStart);
		panelTwo.add(new GLabel("End Address:", SwingConstants.RIGHT));
		panelTwo.add(blockTwoEndField);
		panelTwo.add(new GLabel("Block Length:", SwingConstants.RIGHT));
		panelTwo.add(blockTwoLengthField);

		JPanel mainPanel = new JPanel();
		mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
		BoxLayout bl = new BoxLayout(mainPanel, BoxLayout.Y_AXIS);
		mainPanel.setLayout(bl);
		mainPanel.add(panelOne);
		mainPanel.add(Box.createVerticalStrut(20));
		mainPanel.add(panelTwo);

		return mainPanel;
	}

	/**
	 * Set the fields according to the block that is to be split.
	 */
	private void setFields() {
		String name = block.getName();

		blockOneNameField.setText(name);
		blockOneNameField.setEnabled(false);

		Address startAddr = block.getStart();
		Address endAddr = block.getEnd();

		blockOneStartField.setText(startAddr.toString());
		blockOneStartField.setEnabled(false);

		blockOneEnd.setAddress(endAddr);
		blockOneEnd.setAddressSpaceEditable(false);

		blockOneLengthField.setValue(Long.valueOf(block.getSize()));

		blockTwoNameField.setText(name + ".split");

		blockTwoStart.setAddress(startAddr);
		blockTwoStart.setAddressSpaceEditable(false);

		blockTwoEndField.setText(endAddr.toString());
		blockTwoEndField.setEnabled(false);
	}

	/**
	 * Add listeners to the fields.
	 */
	private void addListeners() {

		blockOneLengthField.setChangeListener(new LengthChangeListener(blockOneLengthField));
		blockTwoLengthField.setChangeListener(new LengthChangeListener(blockTwoLengthField));

		ActionListener al = e -> setStatusText("");
		blockOneLengthField.addActionListener(al);
		blockTwoLengthField.addActionListener(al);
		blockOneEnd.addActionListener(al);
		blockTwoStart.addActionListener(al);
		blockTwoNameField.addActionListener(al);
	}

	////////////////////////////////////////////////////////////////////////

	/**
	 * Listener on the RegisterField inputs; update other fields when either
	 * of these fields change.
	 */
	private class LengthChangeListener implements ChangeListener {

		RegisterField source;

		public LengthChangeListener(RegisterField source) {
			this.source = source;
		}

		@Override
		public void stateChanged(ChangeEvent event) {
			setStatusText("");
			boolean ok = false;
			if (source == blockOneLengthField) {
				ok = blockOneLengthChanged();
			}
			else if (source == blockTwoLengthField) {
				ok = blockTwoLengthChanged();
			}
			setOkEnabled(ok);
		}

		private int getLength() throws InvalidInputException {

			Long val = source.getValue();
			if (val == null) {
				throw new InvalidInputException();
			}
			int length = val.intValue();

			long blockSize = block.getSize();
			if (length <= 0 || length >= blockSize) {
				if (length != 0) {
					setStatusText("Length must be less than original block size (0x" +
						Long.toHexString(blockSize) + ")");
				}
				throw new InvalidInputException();
			}
			return length;
		}

		private boolean blockOneLengthChanged() {

			int length = 0;
			try {
				length = getLength();
			}
			catch (InvalidInputException e) {
				return false;
			}

			// update blockOneEnd, blockTwoStart, blockTwoLength
			try {

				Address end = block.getStart().addNoWrap(length - 1);
				Address b2Start = end.addNoWrap(1);
				blockOneEnd.setAddress(end);
				blockTwoStart.setAddress(b2Start);
				long b2Length = block.getEnd().subtract(b2Start) + 1;

				blockTwoLengthField.setValue(Long.valueOf(b2Length));

			}
			catch (Exception e) {
				if (e instanceof AddressOverflowException) {
					setStatusText("Could not create new start address");
				}
				return false;
			}
			return true;
		}

		private boolean blockTwoLengthChanged() {

			int length = 0;
			try {
				length = getLength();
			}
			catch (InvalidInputException e) {
				return false;
			}

			// update blockTwoStart, BlockOneEnd, blockOneLength
			try {

				Address end = block.getEnd();
				Address b2Start = end.subtractNoWrap(length - 1);
				blockTwoStart.setAddress(b2Start);
				Address b1End = b2Start.subtractNoWrap(1);
				blockOneEnd.setAddress(b1End);
				length = (int) b1End.subtract(block.getStart()) + 1;

				blockOneLengthField.setValue(Long.valueOf(length));

			}
			catch (Exception e) {
				return false;
			}
			return true;
		}
	}

	private void blockOneEndChanged(Address end) {
		setStatusText("");
		boolean isValid = checkBlockOneEndAddress(end);
		setOkEnabled(isValid);
	}

	private void blockTwoStartChanged(Address start) {
		setStatusText("");
		boolean isValid = checkBlockTwoStartChanged(start);
		setOkEnabled(isValid);
	}

	private boolean checkBlockOneEndAddress(Address end) {

		if (end == null) {
			setStatusText("Invalid Address");
			return false;
		}

		Address start = block.getStart();

		if (end.compareTo(start) < 0) {
			setStatusText("End address must be greater than start");
			return false;
		}
		if (end.compareTo(block.getEnd()) == 0) {
			return false;
		}
		// change block One length and blockTwoStart, blockTwoLength
		long length = 0;
		try {
			length = end.subtract(start) + 1;
		}
		catch (IllegalArgumentException e) {
			setStatusText(e.getMessage());
			return false;
		}
		long blockSize = block.getSize();
		if (length > blockSize) {
			setStatusText(
				"End address must be less than original block end (" + block.getEnd() + ")");
			return false;
		}
		blockOneLengthField.setValue(Long.valueOf(length));

		try {
			Address b2Start = end.addNoWrap(1);
			blockTwoStart.setAddress(b2Start);
			length = block.getEnd().subtract(b2Start) + 1;
			blockTwoLengthField.setValue(Long.valueOf(length));
		}
		catch (Exception e) {
			if (e instanceof AddressOverflowException) {
				setStatusText("Could not create new start address");
			}
			return false;
		}
		return true;

	}

	private boolean checkBlockTwoStartChanged(Address start) {
		if (start == null) {
			setStatusText("Invalid Address");
			return false;
		}
		Address end = block.getEnd();
		if (start == null) {
			return false;
		}
		else if (start.compareTo(end) > 0) {
			setStatusText("Start address must not be greater than end");
			return false;
		}
		else if (start.compareTo(block.getStart()) <= 0) {
			setStatusText("Start address must be greater than original block start (" +
				block.getStart() + ")");
			return false;
		}

		// change block Two length, blockOneEnd, block One length
		long length = end.subtract(start) + 1;
		blockTwoLengthField.setValue(Long.valueOf(length));
		try {
			Address b1End = start.subtractNoWrap(1);
			blockOneEnd.setAddress(b1End);
			length = b1End.subtract(block.getStart()) + 1;
			blockOneLengthField.setValue(Long.valueOf(length));
		}
		catch (Exception e) {
			if (e instanceof AddressOverflowException) {
				setStatusText("Could not create end address for split block");
			}
			return false;
		}
		return true;
	}
}
