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
package ghidra.features.base.memsearch.gui;

import static ghidra.features.base.memsearch.combiner.Combiner.*;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.*;

import docking.DockingUtils;
import docking.menu.ButtonState;
import docking.menu.MultiStateButton;
import docking.widgets.PopupWindow;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GComboBoxCellRenderer;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.features.base.memsearch.combiner.Combiner;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.InvalidByteMatcher;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 * Internal panel of the memory search window that manages the controls for the search feature. This
 * panel can be added or removed via a toolbar action. This panel is showing by default.
 */
class MemorySearchControlPanel extends JPanel {
	private MultiStateButton<Combiner> searchButton;
	private GhidraComboBox<ByteMatcher> searchInputField;
	private GDLabel hexSearchSequenceField;
	private boolean hasResults;
	private ByteMatcher currentMatcher = new InvalidByteMatcher("");
	private SearchHistory searchHistory;
	private SearchGuiModel model;
	private JCheckBox selectionCheckbox;
	private boolean isBusy;
	private MemorySearchProvider provider;
	private List<ButtonState<Combiner>> initialSearchButtonStates;
	private List<ButtonState<Combiner>> combinerSearchButtonStates;
	private JComboBox<SearchFormat> formatComboBox;

	private PopupWindow popup;
	private String errorMessage;
	private GTimerMonitor clearInputMonitor;

	MemorySearchControlPanel(MemorySearchProvider provider, SearchGuiModel model,
			SearchHistory history) {
		super(new BorderLayout());
		this.provider = provider;
		this.searchHistory = history;
		this.model = model;
		model.addChangeCallback(this::guiModelChanged);
		initialSearchButtonStates = createButtonStatesForInitialSearch();
		combinerSearchButtonStates = createButtonStatesForAdditionSearches();

		setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		add(buildLeftSearchInputPanel(), BorderLayout.CENTER);
		add(buildRightSearchInputPanel(), BorderLayout.EAST);
	}

	private JComponent buildRightSearchInputPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		searchButton = new MultiStateButton<Combiner>(initialSearchButtonStates);
		searchButton
				.setStateChangedListener(state -> model.setMatchCombiner(state.getClientData()));
		searchButton.addActionListener(e -> search());
		panel.add(searchButton, BorderLayout.WEST);
		selectionCheckbox = new JCheckBox("Selection Only");
		selectionCheckbox.setSelected(model.isSearchSelectionOnly());
		selectionCheckbox.setEnabled(model.hasSelection());
		selectionCheckbox
				.setToolTipText("If selected, search will be restricted to selected addresses");
		selectionCheckbox.addActionListener(
			e -> model.setSearchSelectionOnly(selectionCheckbox.isSelected()));
		panel.add(selectionCheckbox);
		searchButton.setEnabled(false);
		return panel;
	}

	private List<ButtonState<Combiner>> createButtonStatesForAdditionSearches() {
		List<ButtonState<Combiner>> states = new ArrayList<>();
		states.add(new ButtonState<Combiner>("New Search", "New Search",
			"Replaces the current results with the new search results", REPLACE));
		states.add(new ButtonState<Combiner>("Add To Search", "A union B",
			"Adds the results of the new search to the existing results", UNION));
		states.add(new ButtonState<Combiner>("Intersect Search", "A intersect B",
			"Keep results that in both the existing and new results", INTERSECT));
		states.add(new ButtonState<Combiner>("Xor Search", "A xor B",
			"Keep results that are in either existig or results, but not both", XOR));
		states.add(new ButtonState<Combiner>("A-B Search", "A - B",
			"Subtracts the new results from the existing results", A_MINUS_B));
		states.add(new ButtonState<Combiner>("B-A Search", "B - A",
			"Subtracts the existing results from the new results.", B_MINUS_A));
		return states;
	}

	private List<ButtonState<Combiner>> createButtonStatesForInitialSearch() {
		List<ButtonState<Combiner>> states = new ArrayList<>();
		states.add(new ButtonState<Combiner>("Search", "",
			"Perform a search for the entered values.", null));
		return states;
	}

	private void guiModelChanged(SearchSettings oldSettings) {
		SearchFormat searchFormat = model.getSearchFormat();
		if (!formatComboBox.getSelectedItem().equals(searchFormat)) {
			formatComboBox.setSelectedItem(searchFormat);
		}
		selectionCheckbox.setSelected(model.isSearchSelectionOnly());
		selectionCheckbox.setEnabled(model.hasSelection());
		searchInputField.setToolTipText(searchFormat.getToolTip());

		String text = searchInputField.getText();
		String convertedText = searchFormat.convertText(text, oldSettings, model.getSettings());
		searchInputField.setText(convertedText);
		ByteMatcher byteMatcher = searchFormat.parse(convertedText, model.getSettings());
		setByteMatcher(byteMatcher);
	}

	private JComponent buildLeftSearchInputPanel() {
		createSearchInputField();
		hexSearchSequenceField = new GDLabel();
		hexSearchSequenceField.setName("HexSequenceField");
		Border outerBorder = BorderFactory.createLoweredBevelBorder();
		Border innerBorder = BorderFactory.createEmptyBorder(0, 4, 0, 4);
		Border border = BorderFactory.createCompoundBorder(outerBorder, innerBorder);
		hexSearchSequenceField.setBorder(border);

		JPanel panel = new JPanel(new PairLayout(2, 10));
		panel.add(buildSearchFormatCombo());
		panel.add(searchInputField);
		JLabel byteSequenceLabel = new JLabel("Byte Sequence:", SwingConstants.RIGHT);
		byteSequenceLabel.setToolTipText(
			"This field shows the byte sequence that will be search (if applicable)");

		panel.add(byteSequenceLabel);
		panel.add(hexSearchSequenceField);
		return panel;
	}

	private void createSearchInputField() {
		searchInputField = new GhidraComboBox<>() {
			@Override
			public void setSelectedItem(Object obj) {
				if (obj instanceof String) {
					// this can happen when a user types a string and presses enter
					// our data model is ByteMatcher, not strings
					return;
				}
				ByteMatcher matcher = (ByteMatcher) obj;
				model.setSettings(matcher.getSettings());
				super.setSelectedItem(obj);
			}
		};
		updateCombo();
		searchInputField.setAutoCompleteEnabled(false); // this interferes with validation
		searchInputField.setEditable(true);
		searchInputField.setToolTipText(model.getSearchFormat().getToolTip());
		searchInputField.setDocument(new RestrictedInputDocument());
		searchInputField.addActionListener(ev -> search());
		JTextField searchTextField = searchInputField.getTextField();

		// add escape key listener to dismiss any error popup windows
		searchTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(java.awt.event.KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					clearInputError();
					e.consume();
				}
			}
		});

		// add focus lost listener to dismiss any error popup windows
		searchTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				clearInputError();
			}
		});
		searchInputField.setRenderer(new SearchHistoryRenderer());
	}

	private boolean canSearch() {
		return !isBusy && currentMatcher.isValidSearch();
	}

	private void search() {
		if (canSearch()) {
			provider.search();
			searchHistory.addSearch(currentMatcher);
			updateCombo();
		}
	}

	private JComponent buildSearchFormatCombo() {
		formatComboBox = new JComboBox<>(SearchFormat.ALL);
		formatComboBox.setSelectedItem(model.getSearchFormat());
		formatComboBox.addItemListener(this::formatComboChanged);
		formatComboBox.setToolTipText("The selected format will determine how to " +
			"interpret text typed into the input field");

		return formatComboBox;
	}

	private void formatComboChanged(ItemEvent e) {
		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}
		SearchFormat newFormat = (SearchFormat) e.getItem();
		SearchSettings oldSettings = model.getSettings();
		SearchSettings newSettings = oldSettings.withSearchFormat(newFormat);
		String newText = convertInput(oldSettings, newSettings);
		model.setSearchFormat(newFormat);
		searchInputField.setText(newText);
	}

	String convertInput(SearchSettings oldSettings, SearchSettings newSettings) {
		String text = searchInputField.getText();
		SearchFormat newFormat = newSettings.getSearchFormat();
		return newFormat.convertText(text, oldSettings, newSettings);
	}

	private void setByteMatcher(ByteMatcher byteMatcher) {
		clearInputError();
		currentMatcher = byteMatcher;
		String text = currentMatcher.getDescription();
		hexSearchSequenceField.setText(text);
		hexSearchSequenceField.setToolTipText(currentMatcher.getToolTip());
		updateSearchButton();
		provider.setByteMatcher(byteMatcher);
	}

	void setSearchStatus(boolean hasResults, boolean isBusy) {
		this.hasResults = hasResults;
		this.isBusy = isBusy;
		updateSearchButton();
	}

	private void updateSearchButton() {
		searchButton.setEnabled(canSearch());
		if (!hasResults) {
			searchButton.setButtonStates(initialSearchButtonStates);
			return;
		}
		Combiner combiner = model.getMatchCombiner();
		searchButton.setButtonStates(combinerSearchButtonStates);
		searchButton.setSelectedStateByClientData(combiner);
	}

	private void adjustLocationForCaretPosition(Point location) {
		JTextField textField = searchInputField.getTextField();
		Caret caret = textField.getCaret();
		Point p = caret.getMagicCaretPosition();
		if (p != null) {
			location.x += p.x;
		}
	}

	private void reportInputError(String message) {
		this.errorMessage = message;

		// Sometimes when user input is being processed we will get multiple events, with initial
		// events putting our model in a bad state, but with follow-up events correcting the state.
		// By showing the error message later, we give the follow-up events a change to fix the 
		// state and clear the error message which prevents the temporary bad state from actually
		// displaying an error message to the user.

		Swing.runLater(this::popupErrorMessage);
	}

	private void popupErrorMessage() {
		if (errorMessage == null) {
			return;
		}

		DockingUtils.setTipWindowEnabled(false);

		Point location = searchInputField.getLocation();
		adjustLocationForCaretPosition(location);
		location.y += searchInputField.getHeight() + 5;

		JToolTip tip = new JToolTip();
		tip.setTipText(errorMessage);
		errorMessage = null;

		if (popup != null) {
			popup.dispose();
			clearInputMonitor.cancel();
		}
		popup = new PopupWindow(tip);
		popup.showPopup(searchInputField.getParent(), location, true);
		clearInputMonitor = GTimer.scheduleRunnable(2000, this::clearInputError);
		Toolkit.getDefaultToolkit().beep();
	}

	private void clearInputError() {
		errorMessage = null;
		DockingUtils.setTipWindowEnabled(true);
		PopupWindow.hideAllWindows();
		if (popup != null) {
			popup.dispose();
			popup = null;
			clearInputMonitor.cancel();
			clearInputMonitor = null;
		}
	}

	private void updateCombo() {
		ByteMatcher[] historyArray = searchHistory.getHistoryAsArray();

		searchInputField.setModel(new DefaultComboBoxModel<>(historyArray));
	}

	/**
	 * Custom Document that validates user input on the fly.
	 */
	public class RestrictedInputDocument extends DefaultStyledDocument {

		/**
		 * Called before new user input is inserted into the entry text field.  The super
		 * method is called if the input is accepted.
		 */
		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
			// allow pasting numbers in forms like 0xABC or ABCh
			str = removeNumberBasePrefixAndSuffix(str);

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(offs, currentText.length());
			String proposedText = beforeOffset + str + afterOffset;

			ByteMatcher byteMatcher = model.parse(proposedText);
			if (!byteMatcher.isValidInput()) {
				reportInputError(byteMatcher.getDescription());
				return;
			}
			super.insertString(offs, str, a);

			setByteMatcher(byteMatcher);
		}

		/**
		 * Called before the user deletes some text.  If the result is valid, the super
		 * method is called.
		 */
		@Override
		public void remove(int offs, int len) throws BadLocationException {
			clearInputError();

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(len + offs, currentText.length());
			String proposedResult = beforeOffset + afterOffset;

			if (proposedResult.length() == 0) {
				super.remove(offs, len);
				setByteMatcher(new InvalidByteMatcher(""));
				return;
			}

			ByteMatcher byteMatcher = model.parse(proposedResult);
			if (!byteMatcher.isValidInput()) {
				reportInputError(byteMatcher.getDescription());
				return;
			}
			super.remove(offs, len);
			setByteMatcher(byteMatcher);
		}

		private String removeNumberBasePrefixAndSuffix(String str) {
			SearchFormat format = model.getSearchFormat();
			if (!(format == SearchFormat.HEX || format == SearchFormat.BINARY)) {
				return str;
			}

			String numMaybe = str.strip();
			String lowercase = numMaybe.toLowerCase();
			if (format == SearchFormat.HEX) {
				if (lowercase.startsWith("0x")) {
					numMaybe = numMaybe.substring(2);
				}
				else if (lowercase.startsWith("$")) {
					numMaybe = numMaybe.substring(1);
				}
				else if (lowercase.endsWith("h")) {
					numMaybe = numMaybe.substring(0, numMaybe.length() - 1);
				}
			}
			else {
				if (lowercase.startsWith("0b")) {
					numMaybe = numMaybe.substring(2);
				}
			}

			// check if the resultant number looks valid for insertion (i.e. not empty)
			if (!numMaybe.isEmpty()) {
				return numMaybe;
			}
			return str;
		}
	}

	void setSearchInput(String initialInput) {
		searchInputField.setText(initialInput);
	}

	private class SearchHistoryRenderer extends GComboBoxCellRenderer<ByteMatcher> {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends ByteMatcher> list,
				ByteMatcher matcher, int index,
				boolean isSelected, boolean cellHasFocus) {

			super.getListCellRendererComponent(list, matcher, index, isSelected, cellHasFocus);

			Font font = getFont();
			int formatSize = Math.max(font.getSize() - 3, 6);
			SearchFormat format = matcher.getSettings().getSearchFormat();
			String formatHint = HTMLUtilities.setFontSize(format.getName(), formatSize);
			if (!isSelected) {
				formatHint = HTMLUtilities.colorString(Messages.HINT, formatHint);
			}

			setText("<html>" + matcher.getInput() + " <I>" + formatHint + "</I>");
			return this;
		}
	}

}
