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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.JFormattedTextField.AbstractFormatterFactory;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.DefaultFormatter;
import javax.swing.text.DefaultFormatterFactory;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.button.BrowseButton;
import docking.widgets.button.GRadioButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.textfield.GFormattedTextField;
import docking.widgets.textfield.GFormattedTextField.Status;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.framework.client.ClientUtil;
import ghidra.util.HelpLocation;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.*;

/**
 * Dialog for entering new BSim database server definition
 */
public class CreateBsimServerInfoDialog extends DialogComponentProvider {
	protected static final String FILE_DB_EXT = ".mv.db";

	private static final String POSTGRES = "Postgres";
	private static final String ELASTIC = "Elastic";
	private static final String FILE_H2 = "File";

	private static final AbstractFormatterFactory FORMATTER_FACTORY =
		new DefaultFormatterFactory(new DefaultFormatter() {
			@Override
			public Object stringToValue(String text) {
				return text;
			}
		});

	private GRadioButton postgresButton;
	private GRadioButton elasticButton;
	private GRadioButton fileButton;

	private JPanel cardPanel;

	private DbPanel postgresPanel;
	private DbPanel elasticPanel;
	private FilePanel filePanel;

	private ServerPanel activePanel;
	private BSimServerInfo result;

	public CreateBsimServerInfoDialog() {
		super("Add BSim Server");
		addWorkPanel(buildMainPanel());

		addOKButton();
		addCancelButton();
		setOkEnabled(false);
		setHelpLocation(new HelpLocation("BSimSearchPlugin", "Add_Server_Definition_Dialog"));
	}

	BSimServerInfo getBsimServerInfo() {
		return result;
	}

	@Override
	protected void okCallback() {
		BSimServerInfo serverInfo = activePanel.getServerInfo();
		// FIXME: serverInfo may be null - seems like OK button should have been disabled 
		if (acceptServer(serverInfo)) {
			result = serverInfo;
			close();
		}
	}

	private boolean acceptServer(BSimServerInfo serverInfo) {
		// FIXME: Use task to correct dialog parenting issue caused by password prompt
		String errorMessage = null;
		try (FunctionDatabase database = BSimClientFactory.buildClient(serverInfo, true)) {
			if (database.initialize()) {
				return true;
			}
			errorMessage = database.getLastError().toString();
		}
		catch (Exception e) {
			errorMessage = e.getMessage();
		}
		int answer = OptionDialog.showYesNoDialog(null, "Connection Test Failed!",
			"Can't connect to server: " + errorMessage +
				"\nDo you want to proceed with creation anyway?");
		return answer == OptionDialog.YES_OPTION;
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildTypePanel(), BorderLayout.NORTH);
		panel.add(buildCardPanel(), BorderLayout.CENTER);
		return panel;
	}

	private Component buildCardPanel() {
		postgresPanel = new DbPanel(DBType.postgres);
		elasticPanel = new DbPanel(DBType.elastic);
		filePanel = new FilePanel();

		cardPanel = new JPanel(new CardLayout());
		cardPanel.add(postgresPanel, POSTGRES);
		cardPanel.add(elasticPanel, ELASTIC);
		cardPanel.add(filePanel, FILE_H2);
		activePanel = postgresPanel;
		return cardPanel;
	}

	private Component buildTypePanel() {
		JPanel panel = new JPanel(new MiddleLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 10, 10, 10));
		JPanel innerPanel = new JPanel(new HorizontalLayout(20));
		ButtonGroup group = new ButtonGroup();
		postgresButton = new GRadioButton(POSTGRES);
		elasticButton = new GRadioButton(ELASTIC);
		fileButton = new GRadioButton(FILE_H2);

		postgresButton.setSelected(true);

		ActionListener actionListener = e -> radioChanged();
		postgresButton.addActionListener(actionListener);
		elasticButton.addActionListener(actionListener);
		fileButton.addActionListener(actionListener);

		group.add(postgresButton);
		group.add(elasticButton);
		group.add(fileButton);

		innerPanel.add(postgresButton);
		innerPanel.add(elasticButton);
		innerPanel.add(fileButton);
		panel.add(innerPanel);

		return panel;
	}

	private void radioChanged() {
		CardLayout cardLayout = (CardLayout) cardPanel.getLayout();
		if (postgresButton.isSelected()) {
			cardLayout.show(cardPanel, POSTGRES);
			activePanel = postgresPanel;

		}
		else if (elasticButton.isSelected()) {
			cardLayout.show(cardPanel, ELASTIC);
			activePanel = elasticPanel;
		}
		else if (fileButton.isSelected()) {
			cardLayout.show(cardPanel, FILE_H2);
			activePanel = filePanel;
		}
		checkForValidDialog();
	}

	private int getPort(String portString) {
		try {
			return Integer.parseInt(portString);
		}
		catch (Throwable t) {
			return -1;
		}
	}

	private abstract class ServerPanel extends JPanel {
		ServerPanel(LayoutManager layout) {
			super(layout);
			setBorder(BorderFactory.createEmptyBorder(20, 10, 10, 10));
		}

		abstract BSimServerInfo getServerInfo();
	}

	private void checkForValidDialog() {
		BSimServerInfo serverInfo = activePanel.getServerInfo();
		setOkEnabled(serverInfo != null);
	}

	private class DbPanel extends ServerPanel {
		private GFormattedTextField nameField;
		private GFormattedTextField userField;
		private GFormattedTextField hostField;
		private JTextField portField;
		private DBType type;

		private DbPanel(DBType type) {
			super(new PairLayout(10, 10));
			this.type = type;

			createDBNameField();
			createUserField();
			createHostField();
			int defaultPort = -1;
			if (type == BSimServerInfo.DBType.postgres) {
				defaultPort = BSimServerInfo.DEFAULT_POSTGRES_PORT;
			}
			else if (type == BSimServerInfo.DBType.elastic) {
				defaultPort = BSimServerInfo.DEFAULT_ELASTIC_PORT;
			}
			portField = new NotifyingTextField(Integer.toString(defaultPort));

			JLabel nameLabel = new JLabel("DB Name:", SwingConstants.RIGHT);
			JLabel userLabel = new JLabel("User (optional):", SwingConstants.RIGHT);
			JLabel hostLabel = new JLabel("Host:", SwingConstants.RIGHT);
			JLabel portLabel = new JLabel("Port:", SwingConstants.RIGHT);
			nameLabel.setLabelFor(nameField);
			hostLabel.setLabelFor(hostField);
			portLabel.setLabelFor(portField);

			add(nameLabel);
			add(nameField);
			add(userLabel);
			add(userField);
			add(hostLabel);
			add(hostField);
			add(portLabel);
			add(portField);
		}

		private void setStatus(String msg) {
			CreateBsimServerInfoDialog.this.setStatusText(msg);
		}

		private void createDBNameField() {

			nameField = new GFormattedTextField(FORMATTER_FACTORY, "");
			nameField.setName("Name");
			nameField.setText("");
			nameField.setDefaultValue("");
			nameField.setIsError(true);
			nameField.setEditable(true);

			nameField.setInputVerifier(new InputVerifier() {
				@Override
				public boolean verify(JComponent input) {
					setStatus("");
					String dbName = nameField.getText().trim();
					if (dbName.length() == 0) {
						setStatus("");
						return false;
					}
					// Naming restrictions based upon PostgreSQL and its allowance of unicode chars
					for (int i = 0; i < dbName.length(); i++) {
						char c = dbName.charAt(i);
						if (Character.isLetter(c)) {
							continue;
						}
						if (i == 0 || (!Character.isDigit(c) && c != '_')) {
							setStatus("Unsupported database name");
							return false;
						}
					}
					return true;
				}

				@Override
				public boolean shouldYieldFocus(JComponent source, JComponent target) {
					return true;
				}
			});

			nameField.addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
						e.consume();
						nameField.setText("");
						nameField.setDefaultValue("");
						nameField.setIsError(true);
					}
					checkForValidDialog();
				}
			});

			nameField.addTextEntryStatusListener(f -> checkForValidDialog());
		}

		private static final String HOSTNAME_IP_REGEX =
			"^[a-zA-Z0-9]+(\\-[a-zA-Z0-9]+)*(\\.[a-zA-Z0-9]+(\\-[a-zA-Z0-9]+)*)*$";
		private static final Pattern HOSTNAME_IP_PATTERN = Pattern.compile(HOSTNAME_IP_REGEX);

		private void createHostField() {

			hostField = new GFormattedTextField(FORMATTER_FACTORY, "");
			hostField.setName("Host");
			hostField.setText("");
			hostField.setDefaultValue("");
			hostField.setIsError(true);
			hostField.setEditable(true);

			hostField.setInputVerifier(new InputVerifier() {
				@Override
				public boolean verify(JComponent input) {
					setStatus("");
					String hostname = hostField.getText().trim();
					if (hostname.length() == 0) {
						setStatus("");
						return false;
					}
					Matcher hostMatch = HOSTNAME_IP_PATTERN.matcher(hostname);
					if (!hostMatch.matches()) {
						setStatus("Unsupported host name or IP address");
						return false;
					}
					return true;
				}

				@Override
				public boolean shouldYieldFocus(JComponent source, JComponent target) {
					return true;
				}
			});

			hostField.addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
						e.consume();
						hostField.setText("");
						hostField.setDefaultValue("");
						hostField.setIsError(true);
					}
					checkForValidDialog();
				}
			});

			hostField.addTextEntryStatusListener(f -> checkForValidDialog());
		}

		// NOTE: Username pattern based on PostgreSQL restrictions
		private static final String USERNAME_REGEX = "^[a-zA-Z_][a-zA-Z0-9_$]*$";
		private static final Pattern USERNAME_PATTERN = Pattern.compile(USERNAME_REGEX);

		private void createUserField() {

			userField = new GFormattedTextField(FORMATTER_FACTORY, "");
			userField.setName("User");
			userField.setText("");
			userField.setDefaultValue("");
			userField.setEditable(true);

			userField.setInputVerifier(new InputVerifier() {
				@Override
				public boolean verify(JComponent input) {
					setStatus("");
					String username = userField.getText().trim();
					if (username.length() == 0) {
						setStatus("");
						return true;
					}
					Matcher userMatch = USERNAME_PATTERN.matcher(username);
					if (!userMatch.matches()) {
						setStatus("Unsupported database user name");
						return false;
					}
					return true;
				}

				@Override
				public boolean shouldYieldFocus(JComponent source, JComponent target) {
					return true;
				}
			});

			userField.addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
						e.consume();
						userField.setText("");
						userField.setDefaultValue("");
						userField.setIsError(false);
					}
					checkForValidDialog();
				}
			});

			userField.addTextEntryStatusListener(f -> checkForValidDialog());
		}

		@Override
		BSimServerInfo getServerInfo() {
			if (nameField.getTextEntryStatus() == Status.INVALID ||
				userField.getTextEntryStatus() == Status.INVALID ||
				hostField.getTextEntryStatus() == Status.INVALID) {
				return null;
			}

			String user = userField.getText().trim();
			if (ClientUtil.getUserName().equals(user)) {
				user = null;
			}

			String name = nameField.getText().trim();
			String host = hostField.getText().trim();

			int port = getPort(portField.getText().trim());
			if (name.isBlank() || host.isBlank() || port < 0) {
				return null;
			}

			return new BSimServerInfo(type, user, host, port, name);
		}
	}

	private class FilePanel extends ServerPanel {
		private JTextField fileField;

		FilePanel() {
			super(new PairLayout());
			add(new JLabel("File: "));
			add(buildFileField());
		}

		private JPanel buildFileField() {
			JPanel panel = new JPanel(new BorderLayout());
			fileField = new NotifyingTextField();
			fileField.setEditable(false);
			panel.add(fileField, BorderLayout.CENTER);
			JPanel subpanel = new JPanel(new MiddleLayout());
			subpanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
			BrowseButton browseButton = new BrowseButton();
			browseButton.addActionListener(e -> showFileChooser());
			subpanel.add(browseButton);
			panel.add(subpanel, BorderLayout.EAST);
			return panel;
		}

		private void showFileChooser() {
			GhidraFileChooser chooser = new GhidraFileChooser(this);
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setFileFilter(new GhidraFileFilter() {

				@Override
				public String getDescription() {
					return "*" + FILE_DB_EXT;
				}

				@Override
				public boolean accept(File file, GhidraFileChooserModel chooserModel) {
					return file.isDirectory() || file.getName().endsWith(FILE_DB_EXT);
				}
			});

			File selectedFile = chooser.getSelectedFile();
			if (selectedFile != null) {
				fileField.setText(selectedFile.getAbsolutePath());
			}
		}

		@Override
		BSimServerInfo getServerInfo() {
			String path = fileField.getText().trim();
			if (path.isBlank()) {
				return null;
			}
			File file = new File(path);
			if (file.isDirectory()) {
				return null;
			}
			return new BSimServerInfo(path);
		}
	}

	class NotifyingTextField extends JTextField {
		public NotifyingTextField() {
			this("");
		}

		public NotifyingTextField(String initialText) {
			super(20);
			setText(initialText);
			getDocument().addDocumentListener(new MyFieldListener());
		}
	}

	class MyFieldListener implements DocumentListener {
		@Override
		public void insertUpdate(DocumentEvent e) {
			checkForValidDialog();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			checkForValidDialog();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			checkForValidDialog();
		}
	}

}
