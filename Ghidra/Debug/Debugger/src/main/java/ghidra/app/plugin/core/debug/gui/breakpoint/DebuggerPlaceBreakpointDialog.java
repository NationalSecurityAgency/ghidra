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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSetBreakpointAction;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.CommonSet;
import ghidra.util.MessageType;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;

public class DebuggerPlaceBreakpointDialog extends DialogComponentProvider {
	private DebuggerLogicalBreakpointService service;
	private Program program;
	private Address address;
	private long length;
	private CommonSet kind;
	private String name;

	private JTextField fieldAddress;
	private JTextField fieldLength;
	private JComboBox<CommonSet> fieldKind;
	private JTextField fieldName;
	private PluginTool tool;
	private String statusText = null;

	public DebuggerPlaceBreakpointDialog() {
		super(AbstractSetBreakpointAction.NAME, true, true, true, false);

		populateComponents();
	}

	protected boolean validateAddress() {
		address = program.getAddressFactory().getAddress(fieldAddress.getText());
		if (address == null) {
			setStatusText("Invalid address: " + fieldAddress.getText());
			return false;
		}
		Instruction instruction = program.getListing().getInstructionContaining(address);
		if (instruction != null && !address.equals(instruction.getAddress())) {
			setStatusText("Warning: breakpoint is offset within an instruction.");
		}
		else {
			clearStatusText();
		}
		return true;
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new PairLayout(5, 5));

		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		JLabel labelAddress = new JLabel("Address");
		fieldAddress = new JTextField();
		labelAddress.getAccessibleContext().setAccessibleName("Address");
		fieldAddress.getAccessibleContext().setAccessibleName("Address");
		panel.add(labelAddress);
		panel.add(fieldAddress);

		fieldAddress.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				return validateAddress();
			}
		});
		fieldAddress.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				validateAddress();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				validateAddress();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				validateAddress();
			}
		});

		JLabel labelLength = new JLabel("Length");
		fieldLength = new JTextField();
		labelLength.getAccessibleContext().setAccessibleName("Length");
		fieldLength.getAccessibleContext().setAccessibleName("Length");
		panel.add(labelLength);
		panel.add(fieldLength);

		JLabel labelKind = new JLabel("Kind");
		labelKind.getAccessibleContext().setAccessibleName("Kind");
		DefaultComboBoxModel<CommonSet> kindModel = new DefaultComboBoxModel<>();
		kindModel.addAll(CommonSet.VALUES);
		fieldKind = new JComboBox<CommonSet>(kindModel);
		fieldKind.setEditable(false);
		fieldKind.getAccessibleContext().setAccessibleName("Kind");
		panel.add(labelKind);
		panel.add(fieldKind);

		JLabel labelName = new JLabel("Name");
		fieldName = new JTextField();
		labelName.getAccessibleContext().setAccessibleName("Name");
		fieldName.getAccessibleContext().setAccessibleName("Name");
		panel.add(labelName);
		panel.add(fieldName);
		panel.getAccessibleContext().setAccessibleName("Place Debugger Breakpoint");
		addWorkPanel(panel);

		addOKButton();
		addCancelButton();
	}

	public void prompt(PluginTool tool, DebuggerLogicalBreakpointService service, String title,
			ProgramLocation loc, long length, CommonSet kind, String name) {
		this.service = service;
		this.program = loc.getProgram();
		this.address = DebuggerLogicalBreakpointService.addressFromLocation(loc);
		this.length = length;
		this.kind = kind;
		this.name = name;

		this.fieldAddress.setText(address.toString());
		this.fieldLength.setText(Long.toUnsignedString(length));
		this.fieldKind.setSelectedItem(kind);
		this.fieldName.setText("");
		this.tool = tool;

		validateAddress();

		setTitle(title);
		statusText = null;
		tool.showDialog(this);
	}

	@Override
	protected void okCallback() {
		if (!validateAddress()) {
			return;
		}
		try {
			length = Long.parseUnsignedLong(fieldLength.getText());
		}
		catch (NumberFormatException e) {
			setStatusText("Invalid length: " + e);
			return;
		}

		kind = ((CommonSet) fieldKind.getSelectedItem());
		name = fieldName.getText();

		ProgramLocation loc = new ProgramLocation(program, address);
		service.placeBreakpointAt(loc, length, kind.kinds(), name).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			statusText = ex.getMessage(); // will be set when dialog is shown later
			tool.showDialog(this);
			return null;
		});
		close();
	}

	@Override
	protected void dialogShown() {
		if (statusText != null) {
			setStatusText(statusText, MessageType.ERROR, true);
		}
	}

	/* testing */
	void setName(String name) {
		this.name = name;
		Swing.runNow(() -> this.fieldName.setText(name));
	}
}
