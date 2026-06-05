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
package ghidra.framework.main.wizard.project;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.*;

import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GList;
import ghidra.util.layout.VerticalLayout;
import utility.function.Callback;

/**
 * Panel that shows a list of existing repositories, or allows the user
 * to enter the name of a new repository to be created. Used by the {@link RepositoryStep} of
 * either the new project wizard, the "convert to shared" wizard, or the "change repository"
 * wizard.
 */
public class RepositoryPanel extends JPanel {

	private JRadioButton existingRepButton;
	private JRadioButton createRepButton;
	private ButtonGroup buttonGroup;
	private GList<String> nameList;
	private DefaultListModel<String> listModel;
	private JTextField nameField;
	private JLabel nameLabel;
	private Callback statusChangedCallback;

	public RepositoryPanel(Callback statusChangedCallback, String[] repositoryNames,
			boolean readOnlyServerAccess) {
		super(new BorderLayout(5, 10));
		this.statusChangedCallback = Callback.dummyIfNull(statusChangedCallback);
		setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		buildMainPanel(repositoryNames, readOnlyServerAccess);
	}

	public boolean isCreateRepositorySelected() {
		return createRepButton.isSelected();
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
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Choose Existing Repository"));

		panel.add(createExistingRepoButton(repositoryNames), BorderLayout.NORTH);
		panel.add(createScrollableRepoList(repositoryNames), BorderLayout.CENTER);

		return panel;
	}

	private JPanel createScrollableRepoList(String[] repositoryNames) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		listModel = new DefaultListModel<>();
		for (String repositoryName : repositoryNames) {
			listModel.addElement(repositoryName);
		}
		nameList = new GList<>(listModel);
		nameList.setEnabled(existingRepButton.isSelected());
		JScrollPane sp = new JScrollPane(nameList);
		panel.add(sp);
		return panel;
	}

	private JComponent createExistingRepoButton(String[] repositoryNames) {
		existingRepButton = new GRadioButton("Existing Repository", (repositoryNames.length > 0));
		existingRepButton.setEnabled(repositoryNames.length > 0);
		buttonGroup.add(existingRepButton);
		return existingRepButton;
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
				statusChangedCallback.call();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				statusChangedCallback.call();
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
				statusChangedCallback.call();
			}
		};
		existingRepButton.addActionListener(listener);
		createRepButton.addActionListener(listener);

		ListSelectionModel selModel = nameList.getSelectionModel();
		selModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}
				statusChangedCallback.call();
			}
		});
	}

	public String getRepositoryName() {
		if (isCreateRepositorySelected()) {
			return nameField.getText().trim();
		}
		return nameList.getSelectedValue();
	}

}
