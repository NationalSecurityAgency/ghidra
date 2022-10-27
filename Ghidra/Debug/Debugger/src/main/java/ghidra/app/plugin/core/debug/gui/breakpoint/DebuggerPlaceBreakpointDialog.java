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

import static ghidra.trace.model.breakpoint.TraceBreakpointKind.*;

import java.util.Collection;
import java.util.Set;

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
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.util.MessageType;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;

public class DebuggerPlaceBreakpointDialog extends DialogComponentProvider {
	private DebuggerLogicalBreakpointService service;
	private Program program;
	private Address address;
	private long length;
	private Set<TraceBreakpointKind> kinds;
	private String name;

	private JTextField fieldAddress;
	private JTextField fieldLength;
	private JComboBox<String> fieldKinds;
	private JTextField fieldName;

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
		panel.add(labelLength);
		panel.add(fieldLength);

		JLabel labelKinds = new JLabel("Kinds");
		DefaultComboBoxModel<String> kindModel = new DefaultComboBoxModel<>();
		// TODO: Let user select whatever combo?
		kindModel.addElement(TraceBreakpointKindSet.encode(Set.of(SW_EXECUTE)));
		kindModel.addElement(TraceBreakpointKindSet.encode(Set.of(HW_EXECUTE)));
		kindModel.addElement(TraceBreakpointKindSet.encode(Set.of(READ)));
		kindModel.addElement(TraceBreakpointKindSet.encode(Set.of(WRITE)));
		kindModel.addElement(TraceBreakpointKindSet.encode(Set.of(READ, WRITE)));
		fieldKinds = new JComboBox<String>(kindModel);
		fieldKinds.setEditable(true);
		panel.add(labelKinds);
		panel.add(fieldKinds);

		JLabel labelName = new JLabel("Name");
		fieldName = new JTextField();
		panel.add(labelName);
		panel.add(fieldName);

		addWorkPanel(panel);

		addOKButton();
		addCancelButton();
	}

	public void prompt(PluginTool tool, DebuggerLogicalBreakpointService service, String title,
			ProgramLocation loc, long length, Collection<TraceBreakpointKind> kinds, String name) {
		this.service = service;
		this.program = loc.getProgram();
		this.address = DebuggerLogicalBreakpointService.addressFromLocation(loc);
		this.length = length;
		this.kinds = Set.copyOf(kinds);
		this.name = name;

		this.fieldAddress.setText(address.toString());
		this.fieldLength.setText(Long.toUnsignedString(length));
		this.fieldKinds.setSelectedItem(TraceBreakpointKindSet.encode(kinds));
		this.fieldName.setText("");

		validateAddress();

		setTitle(title);
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

		try {
			kinds = TraceBreakpointKindSet.decode((String) fieldKinds.getSelectedItem(), true);
		}
		catch (IllegalArgumentException e) {
			setStatusText("Invalid kinds: " + e);
			return;
		}

		name = fieldName.getText();

		ProgramLocation loc = new ProgramLocation(program, address);
		service.placeBreakpointAt(loc, length, kinds, name).thenAccept(__ -> {
			close();
		}).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			setStatusText(ex.getMessage(), MessageType.ERROR, true);
			return null;
		});
	}

	/* testing */
	void setName(String name) {
		this.name = name;
		Swing.runNow(() -> this.fieldName.setText(name));
	}
}
