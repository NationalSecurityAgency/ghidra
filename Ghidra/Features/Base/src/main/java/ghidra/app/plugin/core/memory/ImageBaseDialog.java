/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.HelpTopics;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.HelpLocation;
import ghidra.util.layout.MiddleLayout;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;

class ImageBaseDialog extends DialogComponentProvider {
	private JTextField textField;
	private Address addr;
	private Address currentAddr;
	private Program program;
	private PluginTool tool;
	
	ImageBaseDialog(PluginTool tool, Program program, Address currentAddr) {
		super("Base Image Address", true, true, true, false);
		this.program = program;
		this.currentAddr = currentAddr;
		this.tool = tool;
		addr = currentAddr;
		
		addWorkPanel(createWorkPanel());
		addOKButton();
		addCancelButton();
		rootPanel.setPreferredSize(new Dimension(240, 120));

		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP, "Set Image Base"));
		setFocusComponent(textField);
	}
	
	public void dispose() {
		super.close();
		tool = null;
		program = null;
	}
		
	private JComponent createWorkPanel() {
		JPanel panel = new JPanel(new MiddleLayout());
		textField = new JTextField(20);
		textField.setText(currentAddr.toString());
		textField.selectAll();
		textField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (addr != null) {
					okCallback();
				}
			}
		});
		panel.add(textField);
		
		textField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateAddress();
			}
			public void insertUpdate(DocumentEvent e) {
				updateAddress();
			}
			public void removeUpdate(DocumentEvent e) {
				updateAddress();
			}
		});
		return panel;
	}
	
	private void updateAddress() {
		clearStatusText();
		String addrString = textField.getText();
		addr = null;
		try {
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addrString);
		} catch (AddressFormatException e) {
		}
		if (addr == null) {
			setStatusText("Invalid Address");
		}
		setOkEnabled(addr != null);
	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
    protected void okCallback() {
		if (addr != null && !addr.equals(currentAddr)) {
			Msg.info(this, "old base = "+program.getImageBase());
			Command cmd = new SetBaseCommand(addr);
			if (!tool.execute(cmd, program)) {
				setStatusText(cmd.getStatusMsg());
				return;
			}
			Msg.info(this, "new base = "+((ProgramDB)program).getImageBase());
		}
		close();
	}
	
}
class SetBaseCommand implements Command {
	private Address addr;
	private String msg;
	
	SetBaseCommand(Address addr) {
		this.addr = addr;
	}
	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		ProgramDB p = (ProgramDB)obj;
		try {
			p.setImageBase(addr, true);
		}
		catch (IllegalStateException e) {
			msg = e.getMessage();
			return false;
		}
		catch(AddressOverflowException e) {
			msg = "Image base of "+addr.toString()+ " not allowed; change causes " + e.getMessage();
			return false;
		}
		catch(LockException e) {
			msg = "Must have exclusive checkout to set the image base";
			return false;
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return msg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	public String getName() {
		return "Set Image Base";
	}
}
