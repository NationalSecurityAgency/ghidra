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
package ghidra.app.plugin.core.searchtext;

import java.awt.*;
import java.awt.event.*;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.*;

import docking.*;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorComponent;

/**
 * Dialog for showing options to search text in a Program.
 */
class SearchTextDialog extends DialogComponentProvider {

	private static final int DEFAULT_MAX_ENTRIES = 10;

	private SearchTextPlugin plugin;
	private PluginTool tool;
	private JButton nextButton;
	private JButton previousButton;
	private JButton allButton;
	private JTextField valueField;
	private GhidraComboBox<String> valueComboBox;
	private List<String> history = new LinkedList<>();
	private JRadioButton programDatabaseSearchRB;
	private JRadioButton listingDisplaySearchRB;
	private JCheckBox searchSelectionCB;
	private JRadioButton searchFieldRB;
	private JRadioButton searchAllRB;
	private JCheckBox commentsCB;
	private JCheckBox labelsCB;
	private JCheckBox mnemonicsCB;
	private JCheckBox operandsCB;
	private JCheckBox dataMnemonicsCB;
	private JCheckBox dataOperandsCB;
	private JCheckBox functionsCB;

	private boolean changingState;
	private boolean forward;
	private boolean isBusy;
	private boolean searchEnabled = true;	// external turn on/off based on navigatable

	private JCheckBox caseSensitiveCB;

	private JRadioButton loadedBlocksButton;

	private JRadioButton allBlocksButton;

	/**
	 * Constructor
	 * @param plugin 
	 */
	SearchTextDialog(SearchTextPlugin plugin) {
		super("Search Program Text", false, true, true, true);
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_Text"));
		this.plugin = plugin;
		tool = plugin.getTool();
		addWorkPanel(createMainPanel());
		nextButton = new JButton("Next");
		nextButton.setMnemonic('N');
		nextButton.addActionListener(ev -> nextPrevious(true));
		this.addButton(nextButton);

		previousButton = new JButton("Previous");
		previousButton.setMnemonic('P');
		previousButton.addActionListener(ev -> nextPrevious(false));
		this.addButton(previousButton);

		allButton = new JButton("Search All");
		allButton.setMnemonic('a');
		allButton.addActionListener(ev -> {
			searchAll();
			valueField.requestFocus();
		});
		this.addButton(allButton);
		setUseSharedLocation(true);
		addDismissButton();
	}

	void dispose() {
		close();
		this.plugin = null;
	}

	@Override
	public void close() {
		super.close();
	}

	public void show(ComponentProvider componentProvider) {
		clearStatusText();
		valueField.requestFocus();
		valueField.selectAll();
		tool.showDialog(this, componentProvider);
		isBusy = false;
		updateSearchButtonsEnablement();
	}

	/**
	 * Called when user selects Cancel Button
	 */
	@Override
	protected void dismissCallback() {
		close();
		cancelCurrentTask();
	}

	@Override
	public void setStatusText(final String text) {
		if (SwingUtilities.isEventDispatchThread()) {
			super.setStatusText(text);
		}
		else {
			SwingUtilities.invokeLater(() -> setMessage(text));
		}
	}

	// overridden to increase visibility
	@Override
	protected void executeProgressTask(Task task, int delay) {
		super.executeProgressTask(task, delay);
	}

	// overridden to increase visibility
	@Override
	protected TaskMonitorComponent getTaskMonitorComponent() {
		return super.getTaskMonitorComponent();
	}

	// overridden to increase visibility
	@Override
	protected TaskScheduler getTaskScheduler() {
		return super.getTaskScheduler();
	}

	private void updateSearchButtonsEnablement() {
		allButton.setEnabled(!isBusy && searchEnabled);
		nextButton.setEnabled(!isBusy && searchEnabled);
		previousButton.setEnabled(!isBusy && searchEnabled);
	}

	void setSearchEnabled(boolean enabled) {
		searchEnabled = enabled;
		updateSearchButtonsEnablement();
	}

	void setHasSelection(boolean hasSelection) {
		searchSelectionCB.setEnabled(hasSelection);
		searchSelectionCB.setSelected(hasSelection);
	}

	boolean searchSelection() {
		return searchSelectionCB.isSelected();
	}

	private void setMessage(String msg) {
		super.setStatusText(msg);
	}

	private JPanel createMainPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout(10, 0));
		mainPanel.add(createSearchPanel(), BorderLayout.NORTH);
		mainPanel.add(createDetailsPanel(), BorderLayout.CENTER);
		return mainPanel;
	}

	private JPanel createSearchPanel() {
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 10, 4));
		panel.setLayout(new BorderLayout());

		valueComboBox = new GhidraComboBox<>();
		valueComboBox.setEditable(true);
		valueField = (JTextField) valueComboBox.getEditor().getEditorComponent();
		valueField.setColumns(20);
		valueField.setDocument(new AutoCompleteDocument());
		valueField.addActionListener(ev -> {
			if (nextButton.isEnabled()) {
				nextPrevious(true);	// go forward
				valueField.requestFocus();
			}
		});
		valueField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					setStatusText("");
				}
			}
		});

		JPanel searchPanel = new JPanel();
		BoxLayout bl = new BoxLayout(searchPanel, BoxLayout.X_AXIS);
		searchPanel.setLayout(bl);
		searchPanel.add(new GLabel("Search for:"));
		searchPanel.add(Box.createHorizontalStrut(5));
		searchPanel.add(valueComboBox);
		JPanel outerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		outerPanel.add(searchPanel);

		panel.add(outerPanel, BorderLayout.CENTER);
		return panel;
	}

	/*
	 * Create the inner panel that has the direction and the case sensitive panel
	 */
	private JPanel createDetailsPanel() {
		JPanel detailsPanel = new JPanel(new BorderLayout());

		detailsPanel.add(createSearchTypePanel(), BorderLayout.NORTH);
		detailsPanel.add(createDetailsGroupPanel(), BorderLayout.CENTER);

		return detailsPanel;
	}

	private JPanel createDetailsGroupPanel() {
		JPanel panel = new JPanel(new GridLayout(1, 2, 10, 10));
		panel.add(createFieldsPanel());
		panel.add(createRightPanel());
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		return panel;
	}

	private JPanel createRightPanel() {
		JPanel panel = new JPanel(new GridLayout(0, 1, 10, 10));
		panel.add(createDirectionPanel());
		panel.add(createOptionsPanel());
		return panel;
	}

	private JPanel createOptionsPanel() {
		JPanel panel = new JPanel(new VerticalLayout(3));

		caseSensitiveCB = new GCheckBox("Case Sensitive");
		caseSensitiveCB.setToolTipText(
			HTMLUtilities.toHTML("Select this if the search\n should be case sensitive."));
		panel.add(caseSensitiveCB);

		searchSelectionCB = new GCheckBox("Search Selection");
		panel.add(searchSelectionCB);

		panel.setBorder(BorderFactory.createTitledBorder("Options"));
		return panel;
	}

	private JPanel createFieldOptionsPanel() {
		JPanel optionsPanel = new JPanel();
		BoxLayout bl = new BoxLayout(optionsPanel, BoxLayout.Y_AXIS);
		optionsPanel.setLayout(bl);

		functionsCB = new GCheckBox("Functions");
		functionsCB.setToolTipText(HTMLUtilities.toHTML("Search in the Function Header fields"));

		commentsCB = new GCheckBox("Comments", true);
		commentsCB.setToolTipText(HTMLUtilities.toHTML("Search in any of the comment fields"));

		labelsCB = new GCheckBox("Labels");
		labelsCB.setToolTipText(HTMLUtilities.toHTML("Search in the Lable field"));

		mnemonicsCB = new GCheckBox("Instruction Mnemonics");
		mnemonicsCB.setToolTipText(
			HTMLUtilities.toHTML("Search in the Instruction Mnemonic field"));

		operandsCB = new GCheckBox("Instruction Operands");
		operandsCB.setToolTipText(HTMLUtilities.toHTML("Search in the Instruction Operand fields"));

		dataMnemonicsCB = new GCheckBox("Defined Data Mnemonics");
		dataMnemonicsCB.setToolTipText(
			HTMLUtilities.toHTML("Search in the Data Mnemonic and Value fields"));

		dataOperandsCB = new GCheckBox("Defined Data Values");
		dataOperandsCB.setToolTipText(
			HTMLUtilities.toHTML("Search in the Data Mnemonic and Value fields"));

		optionsPanel.add(functionsCB);
		optionsPanel.add(commentsCB);
		optionsPanel.add(labelsCB);
		optionsPanel.add(mnemonicsCB);
		optionsPanel.add(operandsCB);
		optionsPanel.add(dataMnemonicsCB);
		optionsPanel.add(dataOperandsCB);

		return optionsPanel;

	}

	private JPanel createFieldsPanel() {
		JPanel radioPanel = new JPanel(new VerticalLayout(10));

		ButtonGroup bg = new ButtonGroup();
		searchFieldRB = new GRadioButton("Selected Fields", true);
		searchFieldRB.setToolTipText(HTMLUtilities.toHTML("Search for specific fields. Use the\n" +
			"checkboxes to mark which fields to search.\n" +
			"This option applies to either the Program Database Search\n" +
			"or the Listing Display Match Search.\n\n" +
			"NOTE: Selecting all of these fields is NOT the same as selecting \"All Fields\".\n"));

		searchAllRB = new GRadioButton("All Fields", false);
		searchAllRB.setToolTipText(
			HTMLUtilities.toHTML("Search all the fields displayed in the Code Browser.\n" +
				"The option applies only to the Listing Display Search."));
		searchAllRB.addItemListener(e -> {
			if (changingState) {
				return;
			}
			changingState = true;
			boolean isSelected = e.getStateChange() == ItemEvent.SELECTED;
			enableCheckboxes(!isSelected);
			if (isSelected) {
				listingDisplaySearchRB.setSelected(true);
			}
			changingState = false;
		});

		bg.add(searchFieldRB);
		bg.add(searchAllRB);

		JPanel optionsPanel = createFieldOptionsPanel();
		Border b2 = BorderFactory.createEmptyBorder(0, 20, 10, 10);
		optionsPanel.setBorder(b2);

		radioPanel.add(searchFieldRB);
		radioPanel.add(optionsPanel);
		radioPanel.add(searchAllRB);
		radioPanel.setBorder(BorderFactory.createTitledBorder("Fields"));
		return radioPanel;
	}

	private JPanel createSearchTypePanel() {
		JPanel panel = new JPanel(new GridLayout(1, 2));
		panel.setBorder(BorderFactory.createTitledBorder("Search Type"));

		ButtonGroup bg = new ButtonGroup();

		programDatabaseSearchRB = new GRadioButton("Program Database", true);
		programDatabaseSearchRB.setToolTipText(HTMLUtilities.toHTML(
			"Searches comments, labels, instructions, function signatures, and data stored in the" +
				" program database.\n This search is much faster, but does not search all text displayed in the Code Browser\n" +
				" Listing window, which contains auto-generated and derived information.\n"));
		programDatabaseSearchRB.addItemListener(e -> {
			if (changingState) {
				return;
			}
			changingState = true;
			if (e.getStateChange() == ItemEvent.SELECTED) {
				searchFieldRB.setSelected(true);
				enableCheckboxes(true);
			}
			changingState = false;
		});

		listingDisplaySearchRB = new GRadioButton("Listing Display", false);
		listingDisplaySearchRB.setToolTipText(
			HTMLUtilities.toHTML("Searches the text displayed in the Code Browser\n" +
				"Listing Display. (Depending on which fields are selected)\n" +
				"Warning: this may be very slow!"));

		bg.add(programDatabaseSearchRB);
		bg.add(listingDisplaySearchRB);

		panel.add(programDatabaseSearchRB);
		panel.add(listingDisplaySearchRB);

		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		outerPanel.add(panel);
		return outerPanel;
	}

	/**
	 * Create the panel for the direction buttons.
	 */
	private JPanel createDirectionPanel() {

		JPanel directionPanel = new JPanel(new VerticalLayout(3));
		directionPanel.setBorder(BorderFactory.createTitledBorder("Memory Block Types"));

		ButtonGroup directionGroup = new ButtonGroup();
		loadedBlocksButton = new GRadioButton("Loaded Blocks", true);

		allBlocksButton = new GRadioButton("All Blocks", false);
		loadedBlocksButton.setToolTipText(HTMLUtilities.toHTML(
			"Only searches memory blocks that are loaded in a running executable.\n  " +
				"Ghidra now includes memory blocks for other data such as section headers.\n" +
				"This option exludes these OTHER (non loaded) blocks."));
		allBlocksButton.setToolTipText(
			"Searches all memory blocks including blocks that are not actually loaded in a running executable");

		directionGroup.add(loadedBlocksButton);
		directionGroup.add(allBlocksButton);

		directionPanel.add(loadedBlocksButton);
		directionPanel.add(allBlocksButton);
		return directionPanel;
	}

	/**
	 * Callback for the search next button.
	 */
	private void nextPrevious(boolean searchForward) {
		this.forward = searchForward;
		clearStatusText();

		if (!validate()) {
			return;
		}

		addToHistory(valueField.getText());

		plugin.next();

		plugin.searched();
		isBusy = true;
		updateSearchButtonsEnablement();
	}

	public SearchOptions getSearchOptions() {
		String value = valueField.getText();
		value = StringUtilities.fixMultipleAsterisks(value);
		if (searchAllRB.isSelected()) {
			return new SearchOptions(value, caseSensitiveCB.isSelected(), forward,
				allBlocksButton.isSelected());
		}
		return new SearchOptions(value, programDatabaseSearchRB.isSelected(),
			functionsCB.isSelected(), commentsCB.isSelected(), labelsCB.isSelected(),
			mnemonicsCB.isSelected(), operandsCB.isSelected(), dataMnemonicsCB.isSelected(),
			dataOperandsCB.isSelected(), caseSensitiveCB.isSelected(), forward,
			allBlocksButton.isSelected(), false);
	}

	/**
	 * Return true if a search value was entered AND at least one
	 * search option was selected.
	 */
	private boolean validate() {
		String value = valueField.getText();
		if (value.length() == 0) {
			setStatusText("Please enter a pattern to search for.");
			return false;
		}
		value = StringUtilities.fixMultipleAsterisks(value);
		if (UserSearchUtils.STAR.equals(value)) {
			setStatusText("Pattern must contain a non-wildcard character.");
			return false;
		}

		if (searchAllRB.isSelected()) {
			return true;
		}

		if (!commentsCB.isSelected() && !labelsCB.isSelected() && !mnemonicsCB.isSelected() &&
			!operandsCB.isSelected() && !dataMnemonicsCB.isSelected() &&
			!dataOperandsCB.isSelected() && !functionsCB.isSelected()) {

			setStatusText("Please select an option to search.");
			return false;
		}
		return true;
	}

	/**
	 * Search all callback.
	 */
	private void searchAll() {
		clearStatusText();

		addToHistory(valueField.getText());

		if (!validate()) {
			return;
		}
		plugin.searchAll(getSearchOptions());
		isBusy = true;
		updateSearchButtonsEnablement();
	}

	void searchAllFinished() {
		hideTaskMonitorComponent();
		isBusy = false;
		updateSearchButtonsEnablement();
	}

	@Override
	public void taskCompleted(Task task) {
		super.taskCompleted(task);
		isBusy = false;
		if (plugin != null) {
			searchEnabled = plugin.getNavigatable() != null;
			updateSearchButtonsEnablement();
		}
	}

	@Override
	public void taskCancelled(Task task) {
		super.taskCancelled(task);
		isBusy = false;
		if (plugin != null) {
			searchEnabled = plugin.getNavigatable() != null;
			updateSearchButtonsEnablement();
		}
	}

	public void repeatSearch() {
		nextPrevious(forward);
	}

	private void addToHistory(String input) {
		history.remove(input);
		history.add(0, input);
		truncateHistoryAsNeeded();
		updateCombo();
	}

	void truncateHistoryAsNeeded() {
		int maxEntries = DEFAULT_MAX_ENTRIES;
		int historySize = history.size();

		if (historySize > maxEntries) {
			int numToRemove = historySize - maxEntries;

			for (int i = 0; i < numToRemove; i++) {
				history.remove(history.size() - 1);
			}
		}
	}

	private String matchHistory(String input) {
		if (input == null) {
			return null;
		}

		Iterator<String> itr = history.iterator();
		String ret = null;
		while (ret == null && itr.hasNext()) {
			String cur = itr.next();
			if (cur.startsWith(input)) {
				ret = cur;
			}
		}

		return ret;
	}

	private void updateCombo() {
		String[] list = new String[history.size()];
		history.toArray(list);
		valueComboBox.setModel(new DefaultComboBoxModel<>(list));
	}

	private void enableCheckboxes(boolean enabled) {
		commentsCB.setEnabled(enabled);
		labelsCB.setEnabled(enabled);
		mnemonicsCB.setEnabled(enabled);
		operandsCB.setEnabled(enabled);
		dataMnemonicsCB.setEnabled(enabled);
		dataOperandsCB.setEnabled(enabled);
		functionsCB.setEnabled(enabled);
	}

	public void setValueFieldText(String selectedText) {
		valueField.setText(selectedText);
	}

	public void setCurrentField(ProgramLocation textField, boolean isInstruction) {
		if (textField instanceof CommentFieldLocation ||
			textField instanceof EolCommentFieldLocation ||
			textField instanceof PlateFieldLocation ||
			textField instanceof PostCommentFieldLocation) {
			commentsCB.setSelected(true);
		}
		if (textField instanceof LabelFieldLocation) {
			labelsCB.setSelected(true);
		}
		if (textField instanceof FunctionNameFieldLocation ||
			textField instanceof FunctionRepeatableCommentFieldLocation ||
			textField instanceof FunctionSignatureFieldLocation ||
			textField instanceof VariableCommentFieldLocation ||
			textField instanceof VariableLocFieldLocation ||
			textField instanceof VariableNameFieldLocation ||
			textField instanceof VariableTypeFieldLocation) {

			functionsCB.setSelected(true);
		}
		if (textField instanceof MnemonicFieldLocation && isInstruction) {
			mnemonicsCB.setSelected(true);
		}
		if (textField instanceof OperandFieldLocation && isInstruction) {
			operandsCB.setSelected(true);
		}
		if (textField instanceof MnemonicFieldLocation && !isInstruction) {
			dataMnemonicsCB.setSelected(true);
		}
		if (textField instanceof OperandFieldLocation && !isInstruction) {
			dataOperandsCB.setSelected(true);
		}
	}

	public class AutoCompleteDocument extends DefaultStyledDocument {

		private String previousInput;
		private boolean automated = false;

		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {

			super.insertString(offs, str, a);
			if (automated) {
				automated = false;
			}
			else {
				String input = valueField.getText();
				//If the text has changed
				if (!input.equals(previousInput)) {
					previousInput = input;
					String match = matchHistory(input);
					if (match != null && match.length() > input.length()) {
						automated = true;
						valueField.setText(match);
						valueField.setSelectionStart(input.length());
						valueField.setSelectionEnd(match.length());
					}
				}
			}
		}

	}

}
