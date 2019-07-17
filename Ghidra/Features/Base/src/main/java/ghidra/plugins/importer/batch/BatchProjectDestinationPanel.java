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
package ghidra.plugins.importer.batch;

import java.awt.*;

import javax.swing.*;

import docking.options.editor.ButtonPanelFactory;
import docking.widgets.label.GDLabel;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;

class BatchProjectDestinationPanel extends JPanel {

	private JComponent parent;
	private JTextField folderNameTextField;
	private DataTreeDialog dataTreeDialog;
	private DomainFolder selectedDomainFolder;

	public BatchProjectDestinationPanel(JComponent parent, DomainFolder defaultFolder) {
		this.parent = parent;
		build();
		setFolder(defaultFolder != null ? defaultFolder : getProjectRootFolder());
	}

	public void onProjectDestinationChange(DomainFolder newDomainFolder) {
		// override this
	}

	private void build() {
		setLayout(new BorderLayout());

		folderNameTextField = new JTextField();
		folderNameTextField.setEditable(false);
		folderNameTextField.setFocusable(false);
		folderNameTextField.setText(getProjectRootFolder().toString());

		JLabel folderLabel = new GDLabel("Destination Folder");
		folderLabel.setLabelFor(folderNameTextField);

		JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.addActionListener(e -> browseFolders());
		//ImporterUtils.changeFontToBold(browseButton);

		JPanel savePanel = new JPanel();
		GridBagLayout gbl = new GridBagLayout();
		savePanel.setLayout(gbl);

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.insets.top = 0;
		gbc.insets.left = 0;
		gbc.insets.right = 0;

		gbc.anchor = GridBagConstraints.EAST;
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbl.setConstraints(folderLabel, gbc);
		savePanel.add(folderLabel);

		gbc.anchor = GridBagConstraints.WEST;
		gbc.weightx = 1.0;
		gbc.gridx = 1;
		gbc.gridy = 0;

		gbl.setConstraints(folderNameTextField, gbc);
		savePanel.add(folderNameTextField);

		// add the button to browse the project data tree
		gbc.insets.right = 0;
		gbc.weightx = 0.0;
		gbc.gridx = 2;
		gbc.gridy = 0;
		gbl.setConstraints(browseButton, gbc);
		savePanel.add(browseButton);

		Box box = Box.createVerticalBox();
		box.add(savePanel);
		add(box, BorderLayout.CENTER);
	}

	private void browseFolders() {
		dataTreeDialog =
			new DataTreeDialog(parent, "Choose a project folder", DataTreeDialog.CHOOSE_FOLDER);
		dataTreeDialog.addOkActionListener(e -> {
			dataTreeDialog.close();
			setFolder(dataTreeDialog.getDomainFolder());
		});
		dataTreeDialog.setSelectedFolder(selectedDomainFolder);
		dataTreeDialog.showComponent();
	}

	public void setFolder(DomainFolder folder) {
		if (dataTreeDialog != null) {
			dataTreeDialog.setSelectedFolder(folder);
		}
		folderNameTextField.setText(folder != null ? folder.toString() : "< Choose a folder >");
		this.selectedDomainFolder = folder;
		onProjectDestinationChange(selectedDomainFolder);
	}

	public DomainFolder getFolder() {
		return this.selectedDomainFolder;
	}

	private static DomainFolder getProjectRootFolder() {
		Project project = AppInfo.getActiveProject();
		ProjectData projectData = project.getProjectData();
		return projectData.getRootFolder();
	}
}
