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
package ghidra.framework.main;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.*;

import docking.widgets.label.GDLabel;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.util.MessageType;
import ghidra.util.StatusListener;
import ghidra.util.layout.PairLayout;

/**
 * Component that allows the user to specify the host name and port
 * number for the remote repository server.
 */
public class ServerInfoComponent extends JPanel {

	private JTextField nameField;
	private JTextField portNumberField;
	private int portNumber = -1;
	private DocumentListener portDocListener;
	private DocumentListener nameDocListener;
	private StatusListener statusListener;
	private ChangeListener listener;

	public ServerInfoComponent() {
		super(new BorderLayout(10, 10));
		buildMainPanel();
	}

	/**
	 * Set the status listener
	 * @param statusListener
	 */
	public void setStatusListener(StatusListener statusListener) {
		this.statusListener = statusListener;
	}

	/**
	 * Set the change listener for this component
	 * @param listener
	 */
	public void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}

	/**
	 * Get the server name. 
	 */
	public String getServerName() {
		return nameField.getText();
	}

	/**
	 * Get the port number.
	 */
	public int getPortNumber() {
		return portNumber;
	}

	/**
	 * Set the field values using the given server info.
	 */
	public void setServerInfo(ServerInfo info) {
		if (info != null) {
			nameField.setText(info.getServerName());
			portNumberField.setText(Integer.toString(info.getPortNumber()));
		}
		else {
			nameField.setText("");
			portNumberField.setText(Integer.toString(GhidraServerHandle.DEFAULT_PORT));
		}
	}

	private void buildMainPanel() {
		JLabel nameLabel = new GDLabel("Server Name:", SwingConstants.RIGHT);
		nameField = new JTextField(20);
		nameField.setName("Server Name");
		nameField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				nameField.transferFocus();
			}
		});
		nameDocListener = new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				notifyChange();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				notifyChange();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				notifyChange();
			}
		};
		nameField.getDocument().addDocumentListener(nameDocListener);

		JLabel portLabel = new GDLabel("Port Number:", SwingConstants.RIGHT);
		portNumberField = new JTextField(20);
		portNumberField.setName("Port Number");

		portNumberField.setText(Integer.toString(GhidraServerHandle.DEFAULT_PORT));
		portNumberField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				portNumberField.transferFocus();
			}
		});

		portDocListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				notifyChange();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				notifyChange();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				notifyChange();
			}
		};
		portNumberField.getDocument().addDocumentListener(portDocListener);

		portNumberField.setToolTipText("Enter port number");
		JPanel panel = new JPanel(new PairLayout(5, 10));
		panel.add(nameLabel);
		panel.add(nameField);
		panel.add(portLabel);
		panel.add(portNumberField);

		add(panel, BorderLayout.CENTER);
	}

	private void setStatus(String text) {
		if (statusListener == null) {
			return;
		}
		if (text == null || text.length() == 0) {
			statusListener.clearStatusText();
		}
		else {
			statusListener.setStatusText(text, MessageType.ERROR);
		}
	}

	private void notifyChange() {
		if (listener != null) {
			listener.stateChanged(new ChangeEvent(this));
		}
	}

	private boolean checkPortNumber() {
		portNumber = -1;
		String portStr = portNumberField.getText();
		String msg = null;
		try {
			portNumber = Integer.parseInt(portStr);
			if (portNumber < 0 || portNumber > 65536) {
				portNumber = -1;
				msg = "Port number must in range of 0 to 65536";
			}
		}
		catch (NumberFormatException e) {
			msg = "Invalid port number entered";
		}
		setStatus(msg);
		return msg == null;
	}

	private boolean checkServerName() {
		String name = nameField.getText();
		String msg = null;
		if (name.length() == 0) {
			msg = "Enter the server name";
		}
		setStatus(msg);
		return msg == null;
	}

	/**
	 * Return whether the fields on this panel have valid information.
	 */
	public boolean isValidInformation() {
		return checkServerName() && checkPortNumber();
	}
}
