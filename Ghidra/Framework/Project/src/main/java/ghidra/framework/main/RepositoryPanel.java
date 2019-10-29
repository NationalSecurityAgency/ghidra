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

import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GList;
import docking.wizard.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.util.HelpLocation;
import ghidra.util.NamingUtilities;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel that shows a list of existing repositories, or allows the user
 * to enter the name of a new repository to be created.
 * 
 */
public class RepositoryPanel extends AbstractWizardJPanel {

	private String serverName;
	private JRadioButton existingRepButton;
	private JRadioButton createRepButton;
	private ButtonGroup buttonGroup;
	private GList<String> nameList;
	private DefaultListModel<String> listModel;
	private JTextField nameField;
	private JLabel nameLabel;
	private PanelManager panelManager;
	private HelpLocation helpLoc;

	public RepositoryPanel(PanelManager panelManager, String serverName, String[] repositoryNames,
			boolean readOnlyServerAccess) {
		super(new BorderLayout(5, 10));
		setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		this.panelManager = panelManager;
		this.serverName = serverName;
		buildMainPanel(repositoryNames, readOnlyServerAccess);
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getTitle()
	 */
	@Override
	public String getTitle() {
		return "Specify Repository Name on " + serverName;
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#initialize()
	 */
	@Override
	public void initialize() {
		existingRepButton.setSelected(true);
		nameList.clearSelection();
		nameField.setText("");
	}

	/**
	 * Return whether the user entry is valid
	 */
	@Override
	public boolean isValidInformation() {
		if (createRepButton.isSelected()) {
			String name = nameField.getText();
			if (name.length() == 0) {
				return false;
			}
			if (!NamingUtilities.isValidProjectName(name)) {
				panelManager.getWizardManager().setStatusMessage("Invalid project repository name");
				return false;
			}
			//
			return !listModel.contains(name);
		}
		if (nameList.getSelectedValue() != null) {
			return true;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		if (helpLoc != null) {
			return helpLoc;
		}
		return new HelpLocation(GenericHelpTopics.FRONT_END, "SelectRepository");
	}

	void setHelpLocation(HelpLocation helpLoc) {
		this.helpLoc = helpLoc;
	}

	boolean createRepository() {
		return createRepButton.isSelected();
	}

	/**
	 * Get the name of the repository; it either one selected from the list,
	 * or the name that the user entered to create a new repository.
	 */
	String getRepositoryName() {
		if (createRepButton.isSelected()) {
			return nameField.getText();
		}
		return nameList.getSelectedValue();
	}

	private void buildMainPanel(String[] repositoryNames, boolean readOnlyServerAccess) {
		buttonGroup = new ButtonGroup();

		add(createListPanel(repositoryNames), BorderLayout.CENTER);
		add(createNamePanel(), BorderLayout.SOUTH);
		addListeners();

		if (readOnlyServerAccess) {
			createRepButton.setEnabled(false);
			createRepButton.setSelected(false);
			nameField.setEnabled(false);
			nameLabel.setEnabled(false);
		}
	}

	private JPanel createListPanel(String[] repositoryNames) {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createTitledBorder("Choose Existing Repository"));
		existingRepButton = new GRadioButton("Existing Repository", (repositoryNames.length > 0));
		existingRepButton.setEnabled(repositoryNames.length > 0);
		buttonGroup.add(existingRepButton);

		JPanel innerPanel = new JPanel(new BorderLayout());
		JLabel label = new GDLabel("Repository Names", SwingConstants.LEFT);
		label.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 5));
		innerPanel.add(label, BorderLayout.NORTH);

		listModel = new DefaultListModel<>();
		for (String repositoryName : repositoryNames) {
			listModel.addElement(repositoryName);
		}
		nameList = new GList<>(listModel);
		nameList.setEnabled(existingRepButton.isSelected());
		JScrollPane sp = new JScrollPane(nameList);
		innerPanel.add(sp);

		panel.add(existingRepButton);
		panel.add(innerPanel);

		return panel;
	}

	private JPanel createNamePanel() {
		JPanel namePanel = new JPanel();
		namePanel.setLayout(new VerticalLayout(5));
		namePanel.setBorder(BorderFactory.createTitledBorder("Create Repository"));

		createRepButton = new GRadioButton("Create Repository", !existingRepButton.isSelected());
		buttonGroup.add(createRepButton);

		nameLabel = new GDLabel("Repository Name:", SwingConstants.RIGHT);
		nameLabel.setEnabled(createRepButton.isSelected());

		nameField = new JTextField(20);
		DocumentListener dl = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				validateName();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				validateName();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				validateName();
			}
		};
		nameField.getDocument().addDocumentListener(dl);
		nameField.setEnabled(createRepButton.isSelected());

		JPanel innerPanel = new JPanel();
		innerPanel.add(nameLabel);
		innerPanel.add(nameField);

		namePanel.add(createRepButton);
		namePanel.add(innerPanel);
		return namePanel;
	}

	private void validateName() {
		WizardManager wm = panelManager.getWizardManager();
		String msg = null;
		if (createRepButton.isSelected()) {
			String name = nameField.getText();
			if (name.length() != 0) {
				if (!NamingUtilities.isValidProjectName(name)) {
					msg = "Invalid project repository name";
				}
				else if (listModel.contains(name)) {
					msg = name + " already exists";
				}
			}
		}
		wm.validityChanged();
		if (msg != null) {
			wm.setStatusMessage(msg);
		}
	}

	private void addListeners() {
		ActionListener listener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				boolean existingRepSelected = existingRepButton.isSelected();
				nameList.setEnabled(existingRepSelected);
				if (!existingRepSelected) {
					nameList.clearSelection();
				}
				boolean createRepSelected = createRepButton.isSelected();
				nameField.setEnabled(createRepSelected);
				nameLabel.setEnabled(createRepSelected);
				if (!createRepSelected) {
					nameField.setText("");
				}
				validateName();
			}
		};
		existingRepButton.addActionListener(listener);
		createRepButton.addActionListener(listener);

		ListSelectionModel selModel = nameList.getSelectionModel();
		selModel.addListSelectionListener(new ListSelectionListener() {
			/* (non Javadoc)
			 * @see javax.swing.event.ListSelectionListener#valueChanged(javax.swing.event.ListSelectionEvent)
			 */
			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}
				panelManager.getWizardManager().validityChanged();
			}
		});
	}
}
