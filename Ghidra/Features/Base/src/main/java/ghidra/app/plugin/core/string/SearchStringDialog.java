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
package ghidra.app.plugin.core.string;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.layout.PairLayout;

/**
 * Dialog that allows users to search for strings within a program.
 */
public class SearchStringDialog extends DialogComponentProvider {

	private IntegerTextField alignField;
	private IntegerTextField minLengthField;
	private JTextField wordModelField;
	private JCheckBox nullTerminateCheckbox;
	private JCheckBox pascalStringsCheckbox;
	private AddressSetView selectedAddressSet;
	private StringTablePlugin plugin;

	private JRadioButton loadedBlocksRB;
	private JRadioButton allBlocksRB;
	private JRadioButton searchSelectionRB;
	private JRadioButton searchAllRB;

	public SearchStringDialog(StringTablePlugin plugin, AddressSetView addressSet) {
		super("Search For Strings");
		this.plugin = plugin;
		this.selectedAddressSet = addressSet;

		addWorkPanel(buildWorkPanel());
		addOKButton();
		setOkButtonText("Search");
		addCancelButton();
		setRememberLocation(false);
		setRememberSize(false);
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "String_Search_Dialog"));
	}

	@Override
	protected void okCallback() {
		int minLength = minLengthField.getIntValue();
		if (minLength <= 1) {
			setStatusText("Please enter a valid minimum search length. Must be > 1");
			return;
		}

		StringTableOptions options = new StringTableOptions();
		options.setAlignment(Math.max(alignField.getIntValue(), 1));
		options.setMinStringSize(Math.max(minLengthField.getIntValue(), 1));
		options.setNullTerminationRequired(nullTerminateCheckbox.isSelected());
		options.setRequirePascal(pascalStringsCheckbox.isSelected());
		options.setUseLoadedBlocksOnly(loadedBlocksRB.isSelected());
		if (searchSelectionRB.isSelected()) {
			options.setAddressSet(selectedAddressSet);
		}

		String wordModelFile = wordModelField.getText();

		if (wordModelFile.matches("^\\s*$")) {
			options.setWordModelInitialized(false);
		}
		else {
			try {
				NGramUtils.startNewSession(wordModelFile, false);
				options.setWordModelInitialized(true);
				options.setWordModelFile(wordModelFile);
			}
			catch (IOException ioe) {
				setStatusText(
					"Select a valid model file (e.g., 'StringModel.sng') or leave blank.");
				return;
			}
		}

		plugin.createStringsProvider(options);
		close();
	}

	/**
	 * Creates the main UI panel.
	 */
	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		panel.add(buildLeftPanel(), BorderLayout.WEST);
		panel.add(Box.createHorizontalStrut(10), BorderLayout.CENTER);
		panel.add(buildRightPanel(), BorderLayout.EAST);

		return panel;
	}

	/**
	 * Returns a panel containing the widgets displayed on the left side of the main panel.
	 */
	private Component buildLeftPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.add(buildOptionsPanelLeft(), BorderLayout.NORTH);
		panel.add(Box.createVerticalStrut(15), BorderLayout.CENTER);
		panel.add(buildMemoryBlocksPanel(), BorderLayout.SOUTH);

		return panel;
	}

	/**
	 * Returns a panel containing the widgets on the right side of the main panel.
	 */
	private Component buildRightPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.add(buildOptionsPanelRight(), BorderLayout.NORTH);
		panel.add(Box.createVerticalStrut(15), BorderLayout.CENTER);
		panel.add(buildSelectionScopePanel(), BorderLayout.SOUTH);

		return panel;
	}

	/**
	 * Returns a panel containing the options widgets on the left side of the main
	 * panel.
	 * <li>Require Null Termination</li>
	 * <li>Pascal Strings</li>
	 */
	private JPanel buildOptionsPanelLeft() {

		JPanel panel = new JPanel(new GridLayout(3, 1, 10, 14));

		nullTerminateCheckbox = new GCheckBox("Require Null Termination");
		pascalStringsCheckbox = new GCheckBox("Pascal Strings");
		nullTerminateCheckbox.setSelected(true);

		panel.add(nullTerminateCheckbox);
		panel.add(pascalStringsCheckbox);

		return panel;
	}

	/**
	 * Returns a panel containing the options widgets on the right side of the main
	 * panel.
	 * <li>Minimum Length</li>
	 * <li>Alignment</li>
	 * <li>Word Model</li>
	 */
	private JPanel buildOptionsPanelRight() {

		JPanel panel = new JPanel(new PairLayout(10, 2));

		JLabel minLengthLabel = new GLabel("Minimum Length: ");
		minLengthLabel.setName("minLen");
		minLengthLabel.setToolTipText("<html>Searches for valid ascii or ascii unicode strings " +
			"greater or equal to minimum search length.<br> The null characters are not included " +
			"in the minimum string length.");
		panel.add(minLengthLabel);

		minLengthField = new IntegerTextField(5, 5L);
		minLengthField.getComponent().setName("minDefault");
		panel.add(minLengthField.getComponent());

		JLabel alignLabel = new GLabel("Alignment: ");
		alignLabel.setName("alignment");
		alignLabel.setToolTipText(
			"<html>Searches for strings that start on the given alignment<br>" +
				"value. The default alignment is processor dependent.");
		panel.add(alignLabel);

		alignField = new IntegerTextField(5, 1L);
		alignField.getComponent().setName("alignDefault");
		panel.add(alignField.getComponent());

		createModelFieldPanel(panel);

		return panel;
	}

	/**
	 * Creates the panel containing the Word Model options field.
	 * 
	 * @param panel the parent panel this is to be added to (uses Pair layout)
	 */
	private void createModelFieldPanel(JPanel panel) {

		JLabel modelLabel = new GLabel("Word Model: ");
		modelLabel.setName("wordModel");
		modelLabel.setToolTipText(
			"<html>" + "Strings Analyzer model used to detect high-confidence words.<br> " +
				"Model files are built using Ghidra's BuildStringModels class.<br><br>" +
				"(see help for updating model)");
		panel.add(modelLabel);

		JPanel modelFieldPanel = new JPanel();
		modelFieldPanel.setLayout(new BoxLayout(modelFieldPanel, BoxLayout.X_AXIS));
		wordModelField = new JTextField("StringModel.sng");
		wordModelField.setName("modelDefault");
		modelFieldPanel.add(wordModelField);

		// Set up a file chooser that allows the user to select a new *.sng file.
		JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				GhidraFileChooser chooser = new GhidraFileChooser(panel);
				chooser.setTitle("Select Word Model File");
				chooser.setMultiSelectionEnabled(false);
				chooser.setFileFilter(new ExtensionFileFilter("sng", "Word File"));

				File selectedFile = chooser.getSelectedFile();
				if (selectedFile == null) {
					return;
				}

				// Important to only save off the name of the file. The NGramUtils call that
				// loads the file will search for the file given this name.
				wordModelField.setText(selectedFile.getName());
			}
		});

		modelFieldPanel.add(browseButton);

		panel.add(modelFieldPanel);
	}

	/**
	 * Returns a panel containing the options for choosing what types of memory blocks
	 * to use when doing a search.
	 * <li>Loaded Blocks</li>
	 * <li>All Blocks</li>
	 */
	private JPanel buildMemoryBlocksPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder("Memory Block Types"));

		ButtonGroup memoryBlockGroup = new ButtonGroup();
		loadedBlocksRB = new GRadioButton("Loaded Blocks", true);
		allBlocksRB = new GRadioButton("All Blocks", false);
		memoryBlockGroup.add(loadedBlocksRB);
		memoryBlockGroup.add(allBlocksRB);

		loadedBlocksRB.setToolTipText(HTMLUtilities.toHTML(
			"Only searches memory blocks that are loaded in a running executable.\n  " +
				"Ghidra now includes memory blocks for other data such as section headers.\n" +
				"This option exludes these other (non-loaded) blocks."));
		allBlocksRB.setToolTipText(
			"Searches all memory blocks including blocks that are not actually loaded in a running executable");

		panel.add(loadedBlocksRB);
		panel.add(allBlocksRB);

		return panel;
	}

	/**
	 * Returns a panel containing the options for choosing the selection scope for the search.
	 * <li>Search All</li>
	 * <li>Search Selection</li>
	 */
	private JPanel buildSelectionScopePanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(new TitledBorder("Selection Scope"));

		searchSelectionRB = new GRadioButton("Search Selection");
		searchAllRB = new GRadioButton("Search All");

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(searchSelectionRB);
		buttonGroup.add(searchAllRB);

		searchAllRB.setSelected(true);
		searchSelectionRB.setSelected(hasSelection());
		panel.add(searchAllRB);
		panel.add(searchSelectionRB);

		// Disable the selection radio button if there is no selection.
		searchSelectionRB.setEnabled(hasSelection());

		JPanel selectionPanel = new JPanel();
		selectionPanel.setLayout(new BorderLayout());
		selectionPanel.add(panel, BorderLayout.NORTH);

		return selectionPanel;
	}

	/**
	 * Returns true if there is a user-selection in the listing.
	 */
	private boolean hasSelection() {
		return selectedAddressSet != null && !selectedAddressSet.isEmpty();
	}
}
