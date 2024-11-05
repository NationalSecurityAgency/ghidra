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
package ghidra.app.plugin.core.search;

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

import docking.ReusableDialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;

/**
 * A dialog to gather input for performing a search over decompiled text.
 */
public class DecompilerTextFinderDialog extends ReusableDialogComponentProvider {

	private GhidraComboBox<String> textCombo;

	private JButton searchButton;
	private JCheckBox regexCb;
	private JCheckBox searchSelectionCb;

	private String searchText;
	private boolean isCancelled;

	public DecompilerTextFinderDialog() {
		super("Decompiled Function Search");

		addWorkPanel(buildMainPanel());
		buildButtons();

		setHelpLocation(new HelpLocation("DecompilerTextFinderPlugin", "Search_Decompiled_Text"));
	}

	private void buildButtons() {
		searchButton = new JButton("Search");
		searchButton.addActionListener(ev -> doSearch());
		addButton(searchButton);
		setDefaultButton(searchButton);

		addCancelButton();
	}

	private JPanel buildMainPanel() {

		regexCb = new GCheckBox("Regular Expression", false);
		regexCb.setName("Regular Expression Search");

		regexCb.addItemListener(e -> clearStatusText());

		searchSelectionCb = new JCheckBox("Search Selection");
		searchSelectionCb.setName("Search Selection");

		textCombo = new GhidraComboBox<>();
		textCombo.setEditable(true);
		textCombo.addActionListener(e -> doSearch());

		textCombo.setColumns(20);
		textCombo.addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				handleDocumentUpdate();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				handleDocumentUpdate();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				handleDocumentUpdate();
			}

			private void handleDocumentUpdate() {
				String text = textCombo.getText();
				searchButton.setEnabled(!StringUtils.isBlank(text));
				clearStatusText();
			}
		});

		JLabel findLabel = new GLabel("Find: ");

		// associate this label with a mnemonic key that activates the text field
		findLabel.setDisplayedMnemonic(KeyEvent.VK_N);
		textCombo.associateLabel(findLabel);

		JPanel mainPanel = new JPanel(new BorderLayout());
		JPanel textPanel = new JPanel();
		textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.LINE_AXIS));
		textPanel.add(findLabel);
		textPanel.add(textCombo);
		mainPanel.add(textPanel, BorderLayout.NORTH);
		mainPanel.add(buildOptionsPanel(), BorderLayout.SOUTH);
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return mainPanel;
	}

	private JPanel buildOptionsPanel() {
		JPanel optionsPanel = new JPanel();
		optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.LINE_AXIS));
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Options"));

		optionsPanel.add(regexCb);
		optionsPanel.add(Box.createHorizontalGlue());
		optionsPanel.add(searchSelectionCb);

		return optionsPanel;
	}

	@Override
	public void close() {
		textCombo.setText("");
		super.close();
	}

	private void doSearch() {

		searchText = null;
		clearStatusText();
		if (!searchButton.isEnabled()) {
			return;  // don't search while disabled
		}

		String text = textCombo.getText();
		if (!validateRegex(text)) {
			return; // leave the dialog open so the user can see the error text
		}

		isCancelled = false;
		searchText = text;
		updateSearchHistory(searchText);
		close();
	}

	private boolean validateRegex(String text) {

		if (!isRegex()) {
			return true;
		}

		try {
			Pattern.compile(text);
			return true;
		}
		catch (PatternSyntaxException e) {
			setStatusText("Invalid regex: " + e.getMessage(), MessageType.ERROR);
			return false;
		}
	}

	@Override
	protected void dialogShown() {
		searchButton.setEnabled(false);
		clearStatusText();
		searchText = null;

		// To track cancelled, assume that the dialog is always in a cancelled state unless the 
		// user actually performed a search.
		isCancelled = true;
	}

	public void setSearchText(String text) {
		textCombo.setText(text);
	}

	public String getSearchText() {
		return searchText;
	}

	public boolean isSearchSelection() {
		return searchSelectionCb.isSelected();
	}

	public void setSearchSelectionEnabled(boolean b) {
		if (!b) {
			searchSelectionCb.setEnabled(false);
			searchSelectionCb.setSelected(false);
		}
		else {
			searchSelectionCb.setEnabled(true);
		}
	}

	public boolean isRegex() {
		return regexCb.isSelected();
	}

	public boolean isCancelled() {
		return isCancelled;
	}

	private void updateSearchHistory(String text) {

		MutableComboBoxModel<String> model = (MutableComboBoxModel<String>) textCombo.getModel();
		model.insertElementAt(text, 0);

		int size = model.getSize();
		for (int i = 1; i < size; i++) {
			String element = model.getElementAt(i);
			if (element.equals(text)) { // already in the list, remove it
				model.removeElementAt(i);
				break;
			}
		}

		// do this last since removing items may change the selected item
		model.setSelectedItem(text);
	}
}
