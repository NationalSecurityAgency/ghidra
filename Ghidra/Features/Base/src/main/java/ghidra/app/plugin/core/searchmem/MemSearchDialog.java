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
package ghidra.app.plugin.core.searchmem;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ItemListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;

import docking.*;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.VariableRowHeightGridLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.search.memory.CodeUnitSearchInfo;
import ghidra.util.search.memory.SearchInfo;
import ghidra.util.task.Task;

/**
 * Dialog for MemSearch Plugin.
 * Displays a set of formats for search string.
 * The user can type in a hex, ascii or decimal string to search
 * for among the memory bytes.  The user can indicate forward or
 * backward searching, proper endianness and whether to find just
 * the next occurrence or all of them in the program.
 */
class MemSearchDialog extends DialogComponentProvider {

	static final String ADVANCED_BUTTON_NAME = "mem.search.advanced";
	private static final String CODE_UNIT_SCOPE_NAME = "Code Unit Scope";
	private static final int DEFAULT_MAX_ENTRIES = 10;
	public static final String ENTER_TEXT_MESSAGE = "Please enter a search value";
	private static final SearchData DEFAULT_SEARCH_DATA =
		SearchData.createInvalidInputSearchData(ENTER_TEXT_MESSAGE);

	MemSearchPlugin plugin;
	boolean isMnemonic;

	private JButton nextButton;
	private JButton previousButton;
	private JButton allButton;
	private JTextField valueField;
	private GhidraComboBox<String> valueComboBox;
	private List<String> history = new LinkedList<>();
	private JLabel hexSeqField;
	private CardLayout formatOptionsLayout;
	private JRadioButton searchSelectionRadioButton;
	private JLabel alignLabel;
	private JTextField alignField;
	private JPanel formatOptionsPanel;
	private JRadioButton loadedBlocks;
	private JRadioButton allBlocks;
	private boolean navigatableHasSelection;

	private ChangeListener changeListener = e -> updateDisplay();

	private SearchData searchData = DEFAULT_SEARCH_DATA;
	private SearchFormat[] allFormats = new SearchFormat[] { new HexSearchFormat(changeListener),
		new AsciiSearchFormat(changeListener), new DecimalSearchFormat(changeListener),
		new BinarySearchFormat(changeListener), new RegExSearchFormat(changeListener) };
	private SearchFormat currentFormat = allFormats[0];
	private JRadioButton littleEndian;
	private JRadioButton bigEndian;

	private Container advancedPanel;
	private JRadioButton searchAllRadioButton;
	private List<JCheckBox> codeUnitTypesList;
	private JPanel mainPanel;
	private JToggleButton advancedButton;

	private boolean isSearching;
	private boolean hasValidSearchData;
	private boolean searchEnabled = true;

	MemSearchDialog(MemSearchPlugin plugin, boolean isBigEndian, boolean isMnemonic) {
		super("Search Memory", false, true, true, true);
		this.plugin = plugin;
		this.isMnemonic = isMnemonic;

		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_Memory"));
		mainPanel = buildMainPanel();
		addWorkPanel(mainPanel);
		buildButtons();
		setEndianess(isBigEndian);
		setAlignment(1);
		setUseSharedLocation(true);
	}

	void setBytes(byte[] bytes) {
		if (valueField != null) {
			valueField.setText(null);
		}
		String convertBytesToString = NumericUtilities.convertBytesToString(bytes, " ");
		valueField.setText(convertBytesToString);
	}

	void setAlignment(int alignment) {
		alignField.setText("" + alignment);
	}

	public void setSearchText(String maskedString) {
		valueField.setText(maskedString);
		updateDisplay();
	}

	void setEndianess(boolean isBigEndian) {
		if (isBigEndian) {
			bigEndian.setSelected(isBigEndian);
		}
		else {
			littleEndian.setSelected(true);
		}
		updateDisplay();
	}

	@Override
	public void taskCancelled(Task task) {
		super.taskCancelled(task);
		isSearching = false;
		updateSearchButtonEnablement();
		clearStatusText();
	}

	@Override
	public void taskCompleted(Task task) {
		super.taskCompleted(task);
		isSearching = false;
		updateSearchButtonEnablement();
	}

	void dispose() {
		close();
		this.plugin = null;
	}

	private void setEndianEnabled(boolean enabled) {
		littleEndian.setEnabled(enabled);
		bigEndian.setEnabled(enabled);
	}

	@Override
	protected void executeProgressTask(Task task, int delay) {
		super.executeProgressTask(task, delay);
	}

	void updateSearchButtonEnablement() {
		nextButton.setEnabled(searchEnabled && !isSearching && hasValidSearchData);
		previousButton.setEnabled(searchEnabled && !isSearching && hasValidSearchData &&
			currentFormat.supportsBackwardsSearch());
		allButton.setEnabled(searchEnabled && !isSearching && hasValidSearchData);
	}

	void setHasSelection(boolean hasSelection, boolean autoRestrictSelection) {
		searchSelectionRadioButton.setEnabled(hasSelection);
		if (navigatableHasSelection == hasSelection) {
			return;
		}
		if (autoRestrictSelection) {
			navigatableHasSelection = hasSelection;
			if (hasSelection && !isMnemonic) {
				searchSelectionRadioButton.setSelected(true);
			}
			else {
				searchAllRadioButton.setSelected(true);
			}
		}
	}

	@Override
	protected void dismissCallback() {
		valueField.setText(null);
		hexSeqField.setText(null);
		cancelCurrentTask();
		close();
	}

	void show(ComponentProvider provider) {
		clearStatusText();
		valueField.requestFocus();
		valueField.selectAll();
		PluginTool tool = plugin.getTool();
		tool.showDialog(MemSearchDialog.this, provider);
	}

	private void addToHistory(String input) {
		history.remove(input);
		history.add(0, input);
		truncateHistoryAsNeeded();
		updateCombo();
	}

	private void updateCombo() {
		String[] list = new String[history.size()];
		history.toArray(list);
		valueComboBox.setModel(new DefaultComboBoxModel<>(list));
	}

	private void truncateHistoryAsNeeded() {
		int maxEntries = DEFAULT_MAX_ENTRIES;
		int historySize = history.size();

		if (historySize > maxEntries) {
			int numToRemove = historySize - maxEntries;

			for (int i = 0; i < numToRemove; i++) {
				history.remove(history.size() - 1);
			}
		}
	}

	private CodeUnitSearchInfo createCodeUnitSearchInfo() {
		return new CodeUnitSearchInfo(codeUnitTypesList.get(0).isSelected(),
			codeUnitTypesList.get(1).isSelected(), codeUnitTypesList.get(2).isSelected());
	}

	private void nextPreviousCallback(boolean forward) {
		int alignment = 1;
		try {
			alignment = getAlignment();
		}
		catch (InvalidInputException e) {
			plugin.disableSearchAgain();
			setStatusText(e.getMessage());
			alignField.selectAll();
			return;
		}
		if (searchData.isValidSearchData()) {
			if (plugin.searchOnce(new SearchInfo(searchData, 1,
				searchSelectionRadioButton.isSelected(), forward, alignment, allBlocks.isSelected(),
				createCodeUnitSearchInfo(), plugin.createTaskListener()))) {
				addToHistory(valueField.getText());
				setStatusText("Searching...");
				isSearching = true;
				updateSearchButtonEnablement();
			}
		}
		else {
			plugin.disableSearchAgain();
			setStatusText(searchData.getStatusMessage());
		}
	}

	private void allCallback() {
		int alignment = 1;
		try {
			alignment = getAlignment();
		}
		catch (InvalidInputException e) {
			plugin.disableSearchAgain();
			setStatusText(e.getMessage());
			alignField.selectAll();
			return;
		}
		if (searchData.isValidSearchData()) {

			if (plugin.searchAll(new SearchAllSearchInfo(searchData, plugin.getSearchLimit(),
				searchSelectionRadioButton.isSelected(), true, alignment, allBlocks.isSelected(),
				createCodeUnitSearchInfo()))) {
				addToHistory(valueField.getText());
				setStatusText("Searching...");
				isSearching = true;
				updateSearchButtonEnablement();
			}
		}
		else {
			plugin.disableSearchAgain();
			setStatusText(searchData.getStatusMessage());
		}
	}

	private JPanel buildSearchPanel() {
		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
		labelPanel.setLayout(new GridLayout(0, 1));
		labelPanel.add(new GLabel("Search Value: "));
		labelPanel.add(new GLabel("Hex Sequence: "));

		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new GridLayout(0, 1));
		valueComboBox = new GhidraComboBox<>();
		valueComboBox.setEditable(true);
		valueField = (JTextField) valueComboBox.getEditor().getEditorComponent();

		valueField.setToolTipText(currentFormat.getToolTip());

		valueField.setDocument(new RestrictedInputDocument());
		valueField.addActionListener(ev -> {
			if (nextButton.isEnabled()) {
				nextPreviousCallback(true);
			}
		});

		inputPanel.add(valueComboBox);
		hexSeqField = new GDLabel();
		hexSeqField.setName("HexSequenceField");
		hexSeqField.setBorder(BorderFactory.createLoweredBevelBorder());
		inputPanel.add(hexSeqField);

		JPanel searchPanel = new JPanel(new BorderLayout());
		searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		searchPanel.add(labelPanel, BorderLayout.WEST);
		searchPanel.add(inputPanel, BorderLayout.CENTER);
		return searchPanel;
	}

	private SearchFormat findFormat(String name) {
		for (SearchFormat element : allFormats) {
			if (element.getName().equals(name)) {
				return element;
			}
		}
		return allFormats[0];
	}

	private JPanel buildMainPanel() {

		JPanel newMainPanel = new JPanel();

		newMainPanel.setLayout(new BorderLayout());
		newMainPanel.add(buildSearchPanel(), BorderLayout.NORTH);
		newMainPanel.add(buildOptionsPanel(), BorderLayout.CENTER);
		advancedPanel = buildAdvancedPanel();

		JPanel searchOptionsPanel = new JPanel(new BorderLayout());
		newMainPanel.add(searchOptionsPanel, BorderLayout.SOUTH);

		return newMainPanel;
	}

	private void setAdvancedPanelVisible(boolean visible) {
		if (visible) {
			mainPanel.add(advancedPanel, BorderLayout.EAST);
		}
		else {
			mainPanel.remove(advancedPanel);
		}
		repack();
	}

	private Container createSeparatorPanel() {
		JPanel panel = new JPanel(new GridLayout(1, 1));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 10));

		panel.add(new JSeparator(SwingConstants.VERTICAL));
		return panel;
	}

	private Container buildAdvancedPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 10));
		panel.add(createSeparatorPanel(), BorderLayout.WEST);
		panel.add(buildAdvancedPanelContents());

		return panel;
	}

	private Container buildAdvancedPanelContents() {
		JPanel panel = new JPanel(new VerticalLayout(5));

		// endieness
		panel.add(buildEndienessPanel());

		// defined/undefined data
		panel.add(buildCodeUnitTypesPanel());

		// alignment
		panel.add(buildAlignmentPanel());

		return panel;
	}

	private Container buildEndienessPanel() {
		ButtonGroup endianGroup = new ButtonGroup();
		littleEndian = new GRadioButton("Little Endian", true);
		bigEndian = new GRadioButton("Big Endian", false);
		endianGroup.add(bigEndian);
		endianGroup.add(littleEndian);

		littleEndian.addActionListener(ev -> {
			currentFormat.setEndieness(false);
			updateDisplay();
		});
		bigEndian.addActionListener(ev -> {
			currentFormat.setEndieness(true);
			updateDisplay();
		});

		JPanel endianPanel = new JPanel();
		endianPanel.setLayout(new BoxLayout(endianPanel, BoxLayout.Y_AXIS));
		endianPanel.add(littleEndian);
		endianPanel.add(bigEndian);
		endianPanel.setBorder(BorderFactory.createTitledBorder("Byte Order"));

		return endianPanel;
	}

	private Container buildCodeUnitTypesPanel() {
		final JCheckBox instructionsCheckBox = new GCheckBox("Instructions", true);
		final JCheckBox definedCheckBox = new GCheckBox("Defined Data", true);
		final JCheckBox undefinedCheckBox = new GCheckBox("Undefined Data", true);

		ItemListener stateListener = e -> validate();

		codeUnitTypesList = new ArrayList<>();
		codeUnitTypesList.add(instructionsCheckBox);
		codeUnitTypesList.add(definedCheckBox);
		codeUnitTypesList.add(undefinedCheckBox);

		instructionsCheckBox.addItemListener(stateListener);
		definedCheckBox.addItemListener(stateListener);
		undefinedCheckBox.addItemListener(stateListener);

		JPanel codeUnitTypePanel = new JPanel();
		codeUnitTypePanel.setLayout(new BoxLayout(codeUnitTypePanel, BoxLayout.Y_AXIS));
		codeUnitTypePanel.add(instructionsCheckBox);
		codeUnitTypePanel.add(definedCheckBox);
		codeUnitTypePanel.add(undefinedCheckBox);
		codeUnitTypePanel.setBorder(BorderFactory.createTitledBorder(CODE_UNIT_SCOPE_NAME));

		return codeUnitTypePanel;
	}

	private Component buildSelectionPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(new TitledBorder("Selection Scope"));

		searchSelectionRadioButton = new GRadioButton("Search Selection");
		searchAllRadioButton = new GRadioButton("Search All");

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(searchSelectionRadioButton);
		buttonGroup.add(searchAllRadioButton);

		searchAllRadioButton.setSelected(true);

		panel.add(searchAllRadioButton);
		panel.add(searchSelectionRadioButton);

		JPanel selectionPanel = new JPanel();
		selectionPanel.setLayout(new BorderLayout());
		selectionPanel.add(panel, BorderLayout.NORTH);
		return selectionPanel;
	}

	private Component buildAlignmentPanel() {
		alignLabel = new GDLabel("Alignment: ");
		alignField = new JTextField(5);
		alignField.setName("Alignment");
		alignField.setText("0");

		JPanel alignPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		alignPanel.add(alignLabel);
		alignPanel.add(alignField);
		return alignPanel;
	}

	/**
	 * Builds the basic format selection panel.
	 */
	private JPanel buildFormatPanel() {
		JPanel formatPanel = new JPanel();
		formatPanel.setBorder(BorderFactory.createTitledBorder("Format"));
		formatPanel.setLayout(new GridLayout(0, 1));

		ButtonGroup formatGroup = new ButtonGroup();
		ActionListener formatButtonListener = ev -> {
			String formatName = ((JRadioButton) ev.getSource()).getText();
			currentFormat = findFormat(formatName);
			formatOptionsLayout.show(formatOptionsPanel, currentFormat.getName());
			updateDisplay();
		};

		for (SearchFormat element : allFormats) {
			GRadioButton formatButton = new GRadioButton(element.getName(), true);
			formatButton.setToolTipText(element.getToolTip());

			formatGroup.add(formatButton);
			formatButton.addActionListener(formatButtonListener);
			formatPanel.add(formatButton);
			if (element.getName().equals("Binary") && isMnemonic) {
				formatButton.setSelected(true);
				currentFormat = element;
			}
		}
		return formatPanel;
	}

	private JPanel buildFormatOptionsPanel() {
		formatOptionsPanel = new JPanel();
		formatOptionsLayout = new CardLayout();
		formatOptionsPanel.setLayout(formatOptionsLayout);

		for (SearchFormat element : allFormats) {
			JPanel panel = element.getOptionsPanel();
			formatOptionsPanel.add(panel, element.getName());
		}
		return formatOptionsPanel;
	}

	/**
	 * builds the panel that contains the format Panel, options panel and the extras panel.
	 */
	private JPanel buildOptionsPanel() {
		JPanel formatPanel = buildFormatPanel();
		formatOptionsPanel = buildFormatOptionsPanel();
		JPanel extrasPanel = buildExtrasPanel();

		JPanel northPanel = new JPanel();
		northPanel.setLayout(new VariableRowHeightGridLayout(10, 10, 2));

		northPanel.add(formatPanel);
		northPanel.add(formatOptionsPanel);
		northPanel.add(extrasPanel);
		northPanel.add(buildSelectionPanel());

		advancedButton = new JToggleButton("Advanced >>");
		advancedButton.setName(ADVANCED_BUTTON_NAME);
		advancedButton.addActionListener(e -> {
			boolean selected = advancedButton.isSelected();
			if (selected) {
				advancedButton.setText("Advanced <<");
			}
			else {
				advancedButton.setText("Advanced >>");
			}

			setAdvancedPanelVisible(advancedButton.isSelected());
		});
		advancedButton.setFocusable(false);
		JPanel advancedButtonPanel = new JPanel();
		advancedButtonPanel.setLayout(new BoxLayout(advancedButtonPanel, BoxLayout.X_AXIS));
		advancedButtonPanel.add(Box.createHorizontalGlue());
		advancedButtonPanel.add(Box.createVerticalStrut(40));
		advancedButtonPanel.add(advancedButton);

		JPanel optionsPanel = new JPanel();
		optionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 20, 10));
		optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
		optionsPanel.add(northPanel);
//		optionsPanel.add( southPanel );
		optionsPanel.add(advancedButtonPanel);

		return optionsPanel;
	}

	/**
	 * builds the extras panel.
	 */
	private JPanel buildExtrasPanel() {
		ButtonGroup memoryBlockGroup = new ButtonGroup();
		loadedBlocks = new GRadioButton("Loaded Blocks", true);
		allBlocks = new GRadioButton("All Blocks", false);
		memoryBlockGroup.add(loadedBlocks);
		memoryBlockGroup.add(allBlocks);

		loadedBlocks.setToolTipText(HTMLUtilities.toHTML(
			"Only searches memory blocks that are loaded in a running executable.\n  " +
				"Ghidra now includes memory blocks for other data such as section headers.\n" +
				"This option exludes these OTHER (non loaded) blocks."));
		allBlocks.setToolTipText(
			"Searches all memory blocks including blocks that are not actually loaded in a running executable");

		JPanel directionPanel = new JPanel();
		directionPanel.setLayout(new BoxLayout(directionPanel, BoxLayout.Y_AXIS));
		directionPanel.add(loadedBlocks);
		directionPanel.add(allBlocks);
		directionPanel.setBorder(BorderFactory.createTitledBorder("Memory Block Types"));

		JPanel extrasPanel = new JPanel();
		extrasPanel.setLayout(new BorderLayout());
		extrasPanel.add(directionPanel, BorderLayout.NORTH);
		return extrasPanel;
	}

	private void buildButtons() {
		nextButton = new JButton("Next");
		nextButton.setMnemonic('N');
		nextButton.addActionListener(ev -> nextPreviousCallback(true));
		this.addButton(nextButton);

		previousButton = new JButton("Previous");
		previousButton.setMnemonic('P');
		previousButton.addActionListener(ev -> nextPreviousCallback(false));
		this.addButton(previousButton);

		allButton = new JButton("Search All");
		allButton.setMnemonic('A');
		allButton.addActionListener(ev -> allCallback());
		allButton.setName("Search All");
		this.addButton(allButton);

		addDismissButton();
		updateSearchButtonEnablement();

	}

	private void updateSearchData(SearchData newSearchData) {
		searchData = newSearchData;
		hexSeqField.setText(searchData.getHexString());
		validate();
	}

	private void validate() {

		if (!searchData.isValidSearchData() || !searchData.isValidInputData()) {
			setStatusText(searchData.getStatusMessage());
			hasValidSearchData = false;
		}
		else if (!isValidCodeUnitSearchType()) {
			setStatusText("You must select at least one type of code unit to search in " +
				CODE_UNIT_SCOPE_NAME);
			hasValidSearchData = false;
		}
		else {
			setStatusText("");
			hasValidSearchData = true;
		}
		updateSearchButtonEnablement();
	}

	private boolean isValidCodeUnitSearchType() {
		for (JCheckBox checkBox : codeUnitTypesList) {
			if (checkBox.isSelected()) {
				return true;
			}
		}
		return false;
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#getTaskScheduler()
	 */
	@Override
	protected TaskScheduler getTaskScheduler() {
		return super.getTaskScheduler();
	}

	private void updateDisplay() {
		clearStatusText();

		updateSearchData();

		setEndianEnabled(currentFormat.usesEndieness());
		updateSearchButtonEnablement();
		valueField.setToolTipText(currentFormat.getToolTip());
	}

	private void updateSearchData() {
		currentFormat.setEndieness(bigEndian.isSelected());
		SearchData inputData = currentFormat.getSearchData(valueField.getText());
		if (valueField.getText().trim().length() != 0 && inputData.isValidInputData()) {
			updateSearchData(inputData);
		}
		else {
			valueField.setText("");
			updateSearchData(DEFAULT_SEARCH_DATA);
		}
	}

	public int getAlignment() throws InvalidInputException {
		String alignStr = alignField.getText();
		int len = 0;
		try {
			Integer ilen = Integer.decode(alignStr);
			len = ilen.intValue();
		}
		catch (NumberFormatException e) {
			throw new InvalidInputException("The alignment must be a number greater than 0.");
		}
		if (len <= 0) {
			throw new InvalidInputException("The alignment must be a number greater than 0.");
		}
		return len;
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
			clearStatusText();

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(offs, currentText.length());
			String proposedText = beforeOffset + str + afterOffset;

			// show history
			String match = handleHistoryMatch(currentText, proposedText);
			if (match != null) {
				super.insertString(offs, match.substring(beforeOffset.length()), a);
				valueField.setSelectionStart(proposedText.length());
				valueField.setSelectionEnd(match.length());
				return;
			}

			// no history to show
			SearchData inputData = currentFormat.getSearchData(proposedText);
			if (inputData.isValidInputData()) {
				updateSearchData(inputData);
				super.insertString(offs, str, a);
			}
			else {
				setStatusText(inputData.getStatusMessage());
				Toolkit.getDefaultToolkit().beep();
			}
		}

		/**
		 * Called before the user deletes some text.  If the result is valid, the super
		 * method is called.
		 */
		@Override
		public void remove(int offs, int len) throws BadLocationException {
			clearStatusText();

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(len + offs, currentText.length());
			String proposedResult = beforeOffset + afterOffset;

			if (proposedResult.length() == 0) {
				updateSearchData(DEFAULT_SEARCH_DATA);
				super.remove(offs, len);
				return;
			}

			SearchData inputData = currentFormat.getSearchData(proposedResult);
			if (inputData.isValidInputData()) {
				super.remove(offs, len);
				updateSearchData(inputData);
			}
			else {
				Toolkit.getDefaultToolkit().beep();
			}
		}

		private String handleHistoryMatch(String currentText, String proposedText) {
			boolean textAppended = proposedText.startsWith(currentText);
			String match = findHistoryMatchString(proposedText);
			if (match != null && textAppended) {
				SearchData matchData = currentFormat.getSearchData(match);
				if (matchData.isValidInputData()) {
					updateSearchData(matchData);
					return match;
				}
			}
			return null;
		}

		private String findHistoryMatchString(String input) {
			Iterator<String> itr = history.iterator();
			while (itr.hasNext()) {
				String historyString = itr.next();
				if (historyString.startsWith(input)) {
					return historyString;
				}
			}
			return null;
		}
	}

	boolean getShowAdvancedOptions() {
		return advancedButton.isSelected();
	}

	void setShowAdvancedOptions(boolean selected) {
		if (advancedButton.isSelected() != selected) {
			advancedButton.doClick();
		}
	}

	public void setSearchEnabled(boolean b) {
		searchEnabled = b;
	}

	public void searchCompleted() {
		isSearching = false;
		updateSearchButtonEnablement();
	}

	public String getSearchText() {
		return valueComboBox.getText();
	}

}
