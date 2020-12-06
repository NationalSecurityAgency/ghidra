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
package ghidra.app.plugin.core.disassembler;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

public class ProcessorStateDialog extends DialogComponentProvider {

	private JPanel mainPanel;

	private final static String TITLE = "Specify Processor Disassembly Options";

	private FixedBitSizeValueField[] fields;
	private java.util.List<Register> registerList;
	private ProgramContext programContext;

	public ProcessorStateDialog(ProgramContext programContext) {
		super(TITLE, true, false, true, false);
		this.programContext = programContext;

		registerList = new ArrayList<>();
		for (Register register : programContext.getContextRegisters()) {
			if (!register.isBaseRegister()) {
				registerList.add(register);
			}
		}
		RegisterValue currentContext = programContext.getDefaultDisassemblyContext();
		addOKButton();
		addCancelButton();

		JPanel workPanel = new JPanel(new PairLayout(4, 4));
		workPanel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		fields = new FixedBitSizeValueField[registerList.size()];
		for (int i = 0; i < fields.length; i++) {
			Register register = registerList.get(i);
			int numbits = register.getBitLength();
			JLabel label = new GLabel(register.getName() + " [ " + register.getBitLength() +
				" bit" + ((numbits == 1) ? "" : "s") + " ] :");
			label.setHorizontalAlignment(SwingConstants.TRAILING);
			label.setToolTipText(register.getDescription());
			workPanel.add(label);
			fields[i] = new FixedBitSizeValueField(register.getBitLength(), false, false);
			fields[i].setValue(currentContext.getRegisterValue(register).getUnsignedValue());
			workPanel.add(fields[i]);
		}
		mainPanel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(workPanel);
		mainPanel.add(scrollPane, BorderLayout.CENTER);
		JPanel radioPanel = new JPanel(new FlowLayout());
		mainPanel.add(radioPanel, BorderLayout.SOUTH);
		GRadioButton hexButton = new GRadioButton("Hex");
		GRadioButton decimalButton = new GRadioButton("Decimal");
		hexButton.setSelected(true);
		ButtonGroup group = new ButtonGroup();
		group.add(hexButton);
		group.add(decimalButton);
		radioPanel.add(hexButton);
		radioPanel.add(decimalButton);
		hexButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setRadix(16);
			}
		});
		decimalButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setRadix(10);
			}
		});

		addWorkPanel(mainPanel);
		setHelpLocation(new HelpLocation("DisassemblerPlugin", "ProcessorOptions"));
		setRememberSize(false);

	}

	protected void setRadix(int radix) {
		for (FixedBitSizeValueField field : fields) {
			field.setFormat(radix, false);
		}
	}

	private RegisterValue setRegisterValue(RegisterValue registerValue, Register register,
			BigInteger value) {
		RegisterValue newValue = new RegisterValue(register, value);
		return registerValue.combineValues(newValue);
	}

	/**
	 * The callback method for when the "OK" button is pressed.
	 */
	@Override
	public void okCallback() {
		RegisterValue newValue = new RegisterValue(programContext.getBaseContextRegister());
		for (int i = 0; i < fields.length; i++) {
			BigInteger value = fields[i].getValue();
			if (value != null) {
				newValue = setRegisterValue(newValue, registerList.get(i), value);
			}
		}
		programContext.setDefaultDisassemblyContext(newValue);
		close();
	}

	public void dispose() {
		close();
	}
}
