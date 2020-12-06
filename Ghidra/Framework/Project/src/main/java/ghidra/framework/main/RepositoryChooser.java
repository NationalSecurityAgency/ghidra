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
import java.awt.CardLayout;
import java.awt.event.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.*;
import javax.swing.event.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.list.GList;
import ghidra.framework.client.*;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.layout.MiddleLayout;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;

class RepositoryChooser extends DialogComponentProvider {

	static final Icon REFRESH_ICON = ResourceManager.loadImage("images/view-refresh.png");

	private static final String SERVER_INFO = "ServerInfo";
	private static final String GHIDRA_URL = "GhidraURL";

	private JRadioButton serverInfoChoice;
	private JRadioButton urlChoice;

	private JPanel cardPanel;
	private CardLayout cardLayout;

	private ServerInfoComponent serverInfoComponent;
	private JButton queryButton;
	private GList<String> nameList;
	private DefaultListModel<String> listModel;

	private JTextField urlTextField;

	private boolean okPressed;

	RepositoryChooser(String title) {
		super(title);
		setRememberLocation(false);
		buildMainPanel();
	}

	private JPanel buildServerInfoPanel() {
		JPanel serverInfoPanel = new JPanel(new BorderLayout(10, 10));

		JPanel topPanel = new JPanel(new BorderLayout(10, 10));

		serverInfoComponent = new ServerInfoComponent();
		serverInfoComponent.setStatusListener(this);
		serverInfoComponent.setChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				serverInfoChanged();
			}
		});
		topPanel.add(serverInfoComponent, BorderLayout.CENTER);

		queryButton = new JButton(REFRESH_ICON);
		queryButton.setToolTipText("Refresh Repository Names List");
		setDefaultButton(queryButton);
		queryButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				queryServer();
			}
		});
		JPanel buttonPanel = new JPanel(new MiddleLayout());
		buttonPanel.add(queryButton);
		topPanel.add(buttonPanel, BorderLayout.EAST);

		serverInfoPanel.add(topPanel, BorderLayout.NORTH);

		JPanel lowerPanel = new JPanel(new BorderLayout());
		JLabel label = new GDLabel("Repository Names", SwingConstants.LEFT);
		label.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 5));
		lowerPanel.add(label, BorderLayout.NORTH);

		listModel = new DefaultListModel<>();
		nameList = new GList<>(listModel);
		nameList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		nameList.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				selectionChanged();
			}
		});

		nameList.addMouseListener(new MouseInputAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() != MouseEvent.BUTTON1 || e.getClickCount() != 2) {
					return;
				}
				if (nameList.getSelectedValue() != null) {
					e.consume();
					okCallback();
				}
			}
		});

		JScrollPane sp = new JScrollPane(nameList);
		lowerPanel.add(sp);

		serverInfoPanel.add(lowerPanel, BorderLayout.CENTER);

		return serverInfoPanel;
	}

	private JPanel buildURLPanel() {
		JPanel urlPanel = new JPanel(new BorderLayout(10, 10));

		urlTextField = new JTextField("ghidra:");

		JPanel panel = new JPanel(new PairLayout());
		panel.add(new GLabel("URL:"));
		panel.add(urlTextField);

		urlPanel.add(panel, BorderLayout.NORTH);

		return urlPanel;
	}

	private void choiceActivated(JRadioButton choiceButton) {
		if (choiceButton == urlChoice) {
			cardLayout.show(cardPanel, GHIDRA_URL);
		}
		else {
			cardLayout.show(cardPanel, SERVER_INFO);
		}
		cardPanel.requestFocus();
		choiceChanged();
	}

	private void choiceChanged() {
		setStatusText("");
		if (urlChoice.isSelected()) {
			urlInfoChanged();
		}
		else {
			serverInfoChanged();
		}
	}

	private void buildMainPanel() {

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JPanel radioButtonPanel = new JPanel(new PairLayout(5, 5));
		radioButtonPanel.setBorder(BorderFactory.createTitledBorder("Repository Specification"));

		ChangeListener choiceListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				Object src = e.getSource();
				if (src instanceof JRadioButton) {
					JRadioButton choiceButton = (JRadioButton) src;
					if (choiceButton.isSelected()) {
						choiceActivated(choiceButton);
					}
				}
			}
		};

		serverInfoChoice = new GRadioButton("Ghidra Server");
		serverInfoChoice.setSelected(true);
		serverInfoChoice.addChangeListener(choiceListener);
		radioButtonPanel.add(serverInfoChoice);

		urlChoice = new GRadioButton("Ghidra URL");
		urlChoice.addChangeListener(choiceListener);
		radioButtonPanel.add(urlChoice);

		ButtonGroup panelChoices = new ButtonGroup();
		panelChoices.add(serverInfoChoice);
		panelChoices.add(urlChoice);

		panel.add(radioButtonPanel, BorderLayout.NORTH);

		cardLayout = new CardLayout();
		cardPanel = new JPanel(cardLayout);

		cardPanel.add(buildServerInfoPanel(), SERVER_INFO);

		cardPanel.add(buildURLPanel(), GHIDRA_URL);

		panel.add(cardPanel, BorderLayout.CENTER);
		cardLayout.show(cardPanel, SERVER_INFO);

		addWorkPanel(panel);

		addCancelButton();
		addOKButton();
		setOkButtonText("Select Repository");
		setOkEnabled(false);
	}

	private void selectionChanged() {
		String name = nameList.getSelectedValue();
		setOkEnabled(name != null);
	}

	private void queryServer() {

		listModel.clear();

		RepositoryServerAdapter repositoryServer = ClientUtil.getRepositoryServer(
			serverInfoComponent.getServerName(), serverInfoComponent.getPortNumber(), true);

		if (repositoryServer == null) {
			return;
		}

		try {
			for (String name : repositoryServer.getRepositoryNames()) {
				listModel.addElement(name);
			}
		}
		catch (NotConnectedException e) {
			return;
		}
		catch (IOException e) {
			Msg.showError(this, null, "Server Error",
				"Failed to query list of repositories: " + e.getMessage());
		}

		if (listModel.size() == 0) {
			setStatusText("No repositories found");
		}
	}

	private void urlInfoChanged() {
		setStatusText("");
		setOkEnabled(false);

		try {
			URL url = new URL(urlTextField.getText());
			if (!GhidraURL.PROTOCOL.equals(url.getProtocol())) {
				setStatusText("URL must specify 'ghidra:' protocol", MessageType.ERROR);
			}
			else {
				setOkEnabled(true);
			}
		}
		catch (MalformedURLException e) {
			setStatusText(e.getMessage(), MessageType.ERROR);
		}

	}

	private void serverInfoChanged() {
		setStatusText("");
		setOkEnabled(false);
		listModel.clear();
		queryButton.setEnabled(serverInfoComponent.isValidInformation());
	}

	URL getSelectedRepository(FrontEndTool tool, URL initURL) {

		init(initURL);

		tool.showDialog(this);

		if (!okPressed) {
			return null;
		}

		if (serverInfoChoice.isSelected()) {
			return GhidraURL.makeURL(serverInfoComponent.getServerName(),
				serverInfoComponent.getPortNumber(), nameList.getSelectedValue());
		}

		// TODO: How do we restrict URL to repository only - not sure we can

		try {
			return new URL(urlTextField.getText());
		}
		catch (MalformedURLException e) {
			Msg.error(this, e.getMessage());
		}
		return null;
	}

	@Override
	protected void okCallback() {
		if (serverInfoChoice.isSelected()) {
			// Server info specified
			if (nameList.getSelectedValue() != null) {
				okPressed = true;
				close();
			}
		}
		else {
			// URL specified
			okPressed = true;
			close();
		}
	}

	private void init(URL initURL) {

		okPressed = false;

		if (initURL != null) {
			String url = initURL.toExternalForm();
			String ghidraProtocol = GhidraURL.PROTOCOL + ":";
			if (url.startsWith(ghidraProtocol)) {
				if (!url.startsWith(ghidraProtocol + "//")) {
					// non-standard URL
					urlTextField.setText(url);
					urlChoice.setSelected(true);
					return;
				}
			}
			else {
				initURL = null; // ignore
			}
		}

		ServerInfo serverInfo = null;
		if (initURL != null) {
			String host = initURL.getHost();
			int port = initURL.getPort();
			if (port <= 0) {
				port = GhidraServerHandle.DEFAULT_PORT;
			}
			serverInfo = new ServerInfo(host, port);
		}
		serverInfoComponent.setServerInfo(serverInfo);
		// TODO: serverInfoChanged should get called.

		serverInfoChoice.setSelected(true);

	}

}
