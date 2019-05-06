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
package docking.widgets;

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;

public class FindDialog extends DialogComponentProvider {

	private JTextField textField;
	private GhidraComboBox<String> comboBox;

	private FindDialogSearcher searcher;
	private JButton nextButton;
	private JButton previousButton;
	private JRadioButton stringRadioButton;
	private JRadioButton regexRadioButton;

	public FindDialog(String title, FindDialogSearcher searcher) {
		super(title, false, true, true, true);
		this.searcher = searcher;

		addWorkPanel(buildMainPanel());
		buildButtons();
	}

	private void buildButtons() {
		nextButton = new JButton("Next");
		nextButton.setMnemonic('N');
		nextButton.addActionListener(ev -> doSearch(true));
		addButton(nextButton);
		setDefaultButton(nextButton);

		previousButton = new JButton("Previous");
		previousButton.setMnemonic('P');
		previousButton.addActionListener(ev -> doSearch(false));
		addButton(previousButton);

		addDismissButton();
	}

	private JPanel buildMainPanel() {

		ButtonGroup formatGroup = new ButtonGroup();
		stringRadioButton = new GRadioButton("String", true);
		regexRadioButton = new GRadioButton("Regular Expression", false);
		formatGroup.add(stringRadioButton);
		formatGroup.add(regexRadioButton);

		comboBox = new GhidraComboBox<>();
		comboBox.setEditable(true);
		comboBox.addActionListener(e -> doSearch(true));

		ComboBoxEditor editor = comboBox.getEditor();
		textField = (JTextField) editor.getEditorComponent();

		textField.setColumns(20);
		textField.getDocument().addDocumentListener(new DocumentListener() {
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
				String text = textField.getText();
				enableButtons(text.length() != 0);
			}
		});

		JLabel findLabel = new GLabel("Find: ");

		// associate this label with a mnemonic key that activates the text field
		findLabel.setDisplayedMnemonic(KeyEvent.VK_N);
		findLabel.setLabelFor(textField);

		JPanel mainPanel = new JPanel(new BorderLayout());
		JPanel textPanel = new JPanel();
		textPanel.add(findLabel);
		textPanel.add(comboBox);
		mainPanel.add(textPanel, BorderLayout.NORTH);
		mainPanel.add(buildFormatPanel(), BorderLayout.SOUTH);
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return mainPanel;
	}

	private void enableButtons(boolean b) {
		nextButton.setEnabled(b);
		previousButton.setEnabled(b);
	}

	private JPanel buildFormatPanel() {
		JPanel formatPanel = new JPanel();
		formatPanel.setBorder(BorderFactory.createTitledBorder("Format"));
		formatPanel.setLayout(new BoxLayout(formatPanel, BoxLayout.Y_AXIS));
		formatPanel.add(stringRadioButton);
		formatPanel.add(regexRadioButton);
		return formatPanel;
	}

	@Override
	protected void dialogClosed() {
		textField.setText("");
	}

	private void doSearch(boolean forward) {

		if (!nextButton.isEnabled()) {
			return;  // don't search while disabled
		}

		clearStatusText();
		boolean useRegex = regexRadioButton.isSelected();
		String searchText = textField.getText();

		CursorPosition cursorPosition = searcher.getCursorPosition();
		SearchLocation searchLocation =
			searcher.search(searchText, cursorPosition, forward, useRegex);

		// 
		// First, just search in the current direction.
		//
		if (searchLocation != null) {
			notifySearchHit(searchLocation);
			return;
		}

		// 
		// Did not find the text in the current direction.  Wrap and try one more time.
		//
		String wrapMessage;
		if (forward) {
			wrapMessage = "Reached the bottom, continued from top";
			cursorPosition = searcher.getStart();
		}
		else {
			wrapMessage = "Reached the top, continued from the bottom";
			cursorPosition = searcher.getEnd();
		}

		searchLocation = searcher.search(searchText, cursorPosition, forward, useRegex);
		if (searchLocation != null) {
			notifySearchHit(searchLocation);
			notifyUser(wrapMessage);
			return;
		}

		// 
		// At this point, we wrapped our search and did *not* find a match.  This can only 
		// happen if there is no matching text anywhere in the document, as after wrapping 
		// will will again find the previous match, if it exists.
		//
		notifyUser("Not found");
	}

	private void notifySearchHit(SearchLocation location) {
		searcher.setCursorPosition(location.getCursorPosition());
		storeSearchText(location.getSearchText());
		searcher.highlightSearchResults(location);
	}

	private void notifyUser(String message) {
		setStatus(message);

		// -don't allow searching again while notifying
		// -make sure the user can see it
		enableButtons(false);
		alertMessage(() -> enableButtons(true));
	}

	@Override
	protected void dialogShown() {
		clearStatusText();
	}

	String getText() {
		if (isVisible()) {
			return textField.getText();
		}
		return null;
	}

	void setStatus(String statusText) {
		setStatusText(statusText);
	}

	public void setSearchText(String text) {
		String searchText = text == null ? textField.getText() : text;
		textField.setText(searchText);
		textField.setSelectionStart(0);
		textField.setSelectionEnd(searchText.length());
	}

	private void storeSearchText(String text) {

		MutableComboBoxModel<String> model = (MutableComboBoxModel<String>) comboBox.getModel();
		model.insertElementAt(text, 0);
		model.setSelectedItem(text);

		int size = model.getSize();
		for (int i = 1; i < size; i++) {
			String element = model.getElementAt(i);
			if (element.equals(text)) { // already in the list, remove it
				model.removeElementAt(i);
				break;
			}
		}

	}
}
