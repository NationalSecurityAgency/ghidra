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
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.button.BrowseButton;
import docking.widgets.button.GRadioButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
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

	public BSimServerInfo getBsimServerInfo() {
		return result;
	}

	@Override
	public void setHelpLocation(HelpLocation helpLocation) {
		// TODO Auto-generated method stub
		super.setHelpLocation(helpLocation);
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

	public boolean acceptServer(BSimServerInfo serverInfo) {
		// FIXME: Use task to correct dialog parenting issue caused by password prompt
		String errorMessage = null;
		try {
			FunctionDatabase database = BSimClientFactory.buildClient(serverInfo, true);
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
		private JTextField nameField;
		private JTextField hostField;
		private JTextField portField;
		private DBType type;

		private DbPanel(DBType type) {
			super(new PairLayout(10, 10));
			this.type = type;

			nameField = new NotifyingTextField();
			hostField = new NotifyingTextField();
			portField =
				new NotifyingTextField(Integer.toString(BSimServerInfo.DEFAULT_POSTGRES_PORT));

			JLabel nameLabel = new JLabel("DB Name:", SwingConstants.RIGHT);
			JLabel hostLabel = new JLabel("Host:", SwingConstants.RIGHT);
			JLabel portLabel = new JLabel("Port:", SwingConstants.RIGHT);
			nameLabel.setLabelFor(nameField);
			hostLabel.setLabelFor(hostField);
			portLabel.setLabelFor(portField);

			add(nameLabel);
			add(nameField);
			add(hostLabel);
			add(hostField);
			add(portLabel);
			add(portField);
		}

		@Override
		BSimServerInfo getServerInfo() {
			String name = nameField.getText().trim();
			String host = hostField.getText().trim();
			int port = getPort(portField.getText().trim());
			if (name.isBlank() || host.isBlank() || port < 0) {
				return null;
			}
			return new BSimServerInfo(type, host, port, name);
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
			return new BSimServerInfo(DBType.file, null, -1, path);
		}
	}

	class NotifyingTextField extends JTextField {
		public NotifyingTextField() {
			this("");
		}

		public NotifyingTextField(String initialText) {
			super(20);
			setText(initialText);
			getDocument().addDocumentListener(new DocumentListener() {

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

			});
		}
	}

}
