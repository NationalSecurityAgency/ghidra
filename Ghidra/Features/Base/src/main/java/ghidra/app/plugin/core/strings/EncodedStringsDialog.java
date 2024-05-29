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
package ghidra.app.plugin.core.strings;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.lang.Character.UnicodeScript;
import java.nio.charset.Charset;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.*;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.spinner.IntegerSpinner;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import generic.jar.ResourceFile;
import generic.theme.GThemeDefaults;
import generic.theme.Gui;
import ghidra.app.services.StringTranslationService;
import ghidra.app.services.StringTranslationService.TranslateOptions;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.Application;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.*;

public class EncodedStringsDialog extends DialogComponentProvider {

	private static final Map<String, AbstractStringDataType> CHARSET_TO_DT_MAP = Map.ofEntries(
		// charsets not in this map will use StringDataType and will
		// set the charset setting at the memory location of the string to be created
		Map.entry(CharsetInfo.USASCII, StringDataType.dataType),
		Map.entry(CharsetInfo.UTF8, StringUTF8DataType.dataType),
		Map.entry(CharsetInfo.UTF16, UnicodeDataType.dataType),
		Map.entry(CharsetInfo.UTF32, Unicode32DataType.dataType));

	private static final String BUTTON_FONT_ID = "font.plugin.strings.buttons";

	private final PluginTool tool;
	private final EncodedStringsPlugin plugin;
	private final Program program;
	private AddressSetView selectedAddresses;
	private EncodedStringsTableModel tableModel;
	private EncodedStringsThreadedTablePanel<EncodedStringsRow> threadedTablePanel;
	private GhidraTableFilterPanel<EncodedStringsRow> filterPanel;
	private GhidraTable table;

	private JPanel optionsPanel;
	private GhidraComboBox<String> charsetComboBox;
	private JToggleButton showAdvancedOptionsButton;
	private JToggleButton showScriptOptionsButton;
	private JToggleButton showTranslateOptionsButton;

	private GhidraComboBox<UnicodeScript> requiredUnicodeScript;
	private Map<UnicodeScript, String> scriptExampleStrings = new HashMap<>();
	private JToggleButton allowLatinScriptButton;
	private JToggleButton allowCommonScriptButton;
	private JToggleButton allowAnyScriptButton;
	private GCheckBox excludeStringsWithCodecErrorCB;
	private GCheckBox excludeStringsWithNonStdCtrlCharsCB;
	private IntegerSpinner minStringLengthSpinner;
	private GCheckBox alignStartOfStringCB;
	private GCheckBox breakOnRefCB;

	private GDHtmlLabel codecErrorsCountLabel;
	private GDHtmlLabel nonStdCtrlCharsErrorsCountLabel;
	private GDHtmlLabel stringModelFailedCountLabel;
	private GDHtmlLabel minLenFailedCountLabel;
	private GDHtmlLabel scriptFailedCountLabel;
	private GDHtmlLabel otherScriptsFailedCountLabel;
	private GDHtmlLabel latinScriptFailedCountLabel;
	private GDHtmlLabel commonScriptFailedCountLabel;
	private GDHtmlLabel advancedFailedCountLabel;

	private JButton createButton;

	private GhidraComboBox<StringTranslationService> translateComboBox;

	private EncodedStringsOptions currentOptions;
	private AtomicReference<List<Address>> previouslySelectedRowAddrs = new AtomicReference<>();
	private AtomicBoolean updateInProgressFlag = new AtomicBoolean();
	private AtomicReference<Integer> rowToSelect = new AtomicReference<>();

	private GCheckBox requireValidStringCB;
	private GhidraComboBox<String> stringModelFilenameComboBox;
	private TrigramStringValidator stringValidator;
	private String trigramModelFilename;

	private int optionsPanelRowCount;
	private int advOptsRow1;
	private int advOptsRow2;
	private int stringModelRow;
	private int scriptRow;
	private int translateRow;

	private EncodedStringsFilterStats prevStats = new EncodedStringsFilterStats();
	private ItemListener itemListener = this::comboboxItemListener;

	public EncodedStringsDialog(EncodedStringsPlugin plugin, Program program,
			AddressSetView selectedAddresses) {
		super(makeTitleString(selectedAddresses), false, true, true, true);
		setRememberSize(false);

		this.plugin = plugin;
		this.tool = plugin.getTool();
		this.program = program;
		this.selectedAddresses = selectedAddresses;
		setHelpLocation(EncodedStringsPlugin.HELP_LOCATION);

		build();
	}

	/**
	 * For test/screen shot use
	 *
	 * @param charsetName set the charset
	 */
	public void setSelectedCharset(String charsetName) {
		charsetComboBox.setSelectedItem(charsetName);
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setRequireValidStringOption(boolean b) {
		requireValidStringCB.setSelected(b);
		updateOptionsAndRefresh();
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setAllowLatinScriptOption(boolean b) {
		if (allowLatinScriptButton.isSelected() != b) {
			allowLatinScriptButton.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setAllowCommonScriptOption(boolean b) {
		if (allowCommonScriptButton.isSelected() != b) {
			allowCommonScriptButton.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setAllowAnyScriptOption(boolean b) {
		if (allowAnyScriptButton.isSelected() != b) {
			allowAnyScriptButton.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param requiredScript unicode script
	 */
	public void setRequiredScript(UnicodeScript requiredScript) {
		requiredUnicodeScript.setSelectedItem(requiredScript);
		updateOptionsAndRefresh();
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setShowAdvancedOptions(boolean b) {
		if (showAdvancedOptionsButton.isSelected() != b) {
			showAdvancedOptionsButton.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setShowScriptOptions(boolean b) {
		if (showScriptOptionsButton.isSelected() != b) {
			showScriptOptionsButton.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setExcludeCodecErrors(boolean b) {
		if (excludeStringsWithCodecErrorCB.isSelected() != b) {
			excludeStringsWithCodecErrorCB.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @param b boolean
	 */
	public void setExcludeNonStdCtrlChars(boolean b) {
		if (excludeStringsWithNonStdCtrlCharsCB.isSelected() != b) {
			excludeStringsWithNonStdCtrlCharsCB.doClick();
		}
	}

	/**
	 * For test/screen shot use
	 *
	 * @return table model
	 */
	public EncodedStringsTableModel getStringModel() {
		return tableModel;
	}

	/**
	 * For test/screen shot use
	 *
	 * @return button
	 */
	public JButton getCreateButton() {
		return createButton;
	}

	public void programClosed(Program p) {
		if (program == p) {
			close();
		}
	}

	private void buildScriptExamplesMap(Font f) {
		if (scriptExampleStrings.isEmpty()) {
			scriptExampleStrings.putAll(CharacterScriptUtils.getDisplayableScriptExamples(f, 7));
		}
	}

	private void build() {
		addWorkPanel(buildWorkPanel());
		createButton = new JButton("Create");
		createButton.setName("Create");

		createButton.addActionListener(e -> {
			if (isSingleStringMode()) {
				createStringsAndClose();
			}
			else {
				createStrings();
			}
		});
		addButton(createButton);

		addCancelButton();
		cancelButton.setText("Dismiss");
		setDefaultButton(createButton);
	}

	private JComponent buildWorkPanel() {
		optionsPanel = new JPanel(new PairLayout(5, 5));
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Options"));

		buildCharsetPickerComponents();
		buildOptionsButtonComponents();
		buildAdvancedOptionsComponents();
		buildScriptFilterComponents();
		buildTranslateComponents();

		boolean ssm = selectedAddresses.getNumAddresses() == 1;

		addRow(new GLabel("Charset:", SwingConstants.RIGHT), charsetComboBox,
			showScriptOptionsButton, showTranslateOptionsButton, showAdvancedOptionsButton,
			advancedFailedCountLabel);

		GLabel scriptLabel = new GLabel("Script:", SwingConstants.RIGHT);
		GLabel allowAddLabel = new GLabel("Allow Additional:");
		scriptRow =
			addRow(scriptLabel, requiredUnicodeScript, scriptFailedCountLabel, allowAddLabel,
				allowAnyScriptButton, otherScriptsFailedCountLabel, allowLatinScriptButton,
				latinScriptFailedCountLabel, allowCommonScriptButton, commonScriptFailedCountLabel);

		advOptsRow1 = addRow(null, excludeStringsWithCodecErrorCB, codecErrorsCountLabel,
			excludeStringsWithNonStdCtrlCharsCB, nonStdCtrlCharsErrorsCountLabel);
		stringModelRow = addRow(null, requireValidStringCB, stringModelFailedCountLabel,
			stringModelFilenameComboBox);
		if (ssm) {
			advOptsRow2 = addRow(null, alignStartOfStringCB, breakOnRefCB);
		}
		else {
			GLabel minLenLabel = new GLabel("Min Length:", SwingConstants.RIGHT);
			minLenLabel.setToolTipText(minStringLengthSpinner.getSpinner().getToolTipText());
			advOptsRow2 = addRow(null, minLenLabel, minStringLengthSpinner.getSpinner(),
				minLenFailedCountLabel, alignStartOfStringCB, breakOnRefCB);
		}
		translateRow = addRow(new GLabel("Translate:", SwingConstants.RIGHT), translateComboBox);

		setRowVisibility(advOptsRow1, showAdvancedOptionsButton.isSelected());
		setRowVisibility(advOptsRow2, showAdvancedOptionsButton.isSelected());
		setRowVisibility(stringModelRow, showAdvancedOptionsButton.isSelected());
		setRowVisibility(scriptRow, showScriptOptionsButton.isSelected());
		setRowVisibility(translateRow, showTranslateOptionsButton.isSelected());

		buildPreviewTableComponents();

		JPanel previewTablePanel = new JPanel(new BorderLayout());
		previewTablePanel.add(threadedTablePanel, BorderLayout.CENTER);
		previewTablePanel.add(filterPanel, BorderLayout.SOUTH);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(optionsPanel, BorderLayout.NORTH);
		panel.add(previewTablePanel, BorderLayout.CENTER);

		return panel;
	}

	private void buildPreviewTableComponents() {
		tableModel = new EncodedStringsTableModel(program, selectedAddresses);
		tableModel.addTableModelListener(e -> {
			Integer rowNum = rowToSelect.getAndSet(null);
			if (rowNum != null) {
				table.selectRow(rowNum);
				table.requestFocusInWindow();
			}
		});
		tableModel.addThreadedTableModelListener(new ThreadedTableModelListener() {

			@Override
			public void loadingStarted() {
				setStatusText("Filtering strings...");
				setCreateButtonInfo(0, 0);
				threadedTablePanel.showEmptyTableOverlay(false);
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				EncodedStringsFilterStats stats = tableModel.getStats();
				prevStats = stats.clone();
				int rowCount = tableModel.getRowCount();
				setStatusText("%s strings found, %d strings match, %d excluded%s.".formatted(
					stats.total, rowCount, stats.getTotalOmitted(),
					wasCancelled ? " (partial results)" : ""));
				List<Address> previousAddrs = previouslySelectedRowAddrs.getAndSet(null);
				if (previousAddrs != null) {
					setSelectedAddresses(previousAddrs);
				}
				selectedRowChange();

				codecErrorsCountLabel.setText(getErrorCountString(stats.codecErrors));
				nonStdCtrlCharsErrorsCountLabel.setText(getErrorCountString(stats.nonStdCtrlChars));
				stringModelFailedCountLabel.setText(getErrorCountString(stats.failedStringModel));
				minLenFailedCountLabel.setText(getErrorCountString(stats.stringLength));
				scriptFailedCountLabel.setText(getErrorCountString(stats.requiredScripts));
				latinScriptFailedCountLabel.setText(getErrorCountString(stats.latinScript));
				commonScriptFailedCountLabel.setText(getErrorCountString(stats.commonScript));
				otherScriptsFailedCountLabel.setText(getErrorCountString(stats.otherScripts));
				advancedFailedCountLabel
						.setText(getErrorCountString(stats.getTotalForAdvancedOptions()));

				updateRequiredScriptsList(stats);
				threadedTablePanel.showEmptyTableOverlay(rowCount == 0);
			}

			@Override
			public void loadPending() {
				// ignore
			}
		});

		JPanel emptyTableOverlay = new JPanel(new GridBagLayout());
		emptyTableOverlay.add(new GHtmlLabel("<html>No strings matched filter criteria..."),
			new GridBagConstraints());
		threadedTablePanel =
			new EncodedStringsThreadedTablePanel<>(tableModel, 1000, emptyTableOverlay);
		threadedTablePanel.setBorder(BorderFactory.createTitledBorder("Preview"));
		table = threadedTablePanel.getTable();
		table.setName("DataTable");
		table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		table.getSelectionModel().addListSelectionListener(e -> selectedRowChange());

		table.installNavigation(tool);

		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);
	}

	private void buildCharsetPickerComponents() {
		charsetComboBox = new GhidraComboBox<>();
		for (String charsetName : CharsetInfo.getInstance().getCharsetNames()) {
			charsetComboBox.addToModel(charsetName);
		}
		charsetComboBox.setSelectedItem(getDefault(EncodedStringsPlugin.CHARSET_OPTIONNAME,
			EncodedStringsPlugin.CHARSET_DEFAULT_VALUE));
		charsetComboBox.addItemListener(itemListener);
		charsetComboBox.setToolTipText("Which character set to use to decode the raw bytes.");
		charsetComboBox.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				// empty
			}

			@Override
			public void keyReleased(KeyEvent e) {
				// empty
			}

			@Override
			public void keyPressed(KeyEvent e) {
				// Note: we override the [ENTER] key handling to allow the user to invoke the
				// dialog and just hit enter to create the string without having to do any
				// clicking (otherwise the charset combobox consumes the keystroke)
				if (e.getKeyChar() == '\n') {
					e.consume();
					if (charsetComboBox.isPopupVisible()) {
						charsetComboBox.setPopupVisible(false);
					}
					else {
						EncodedStringsDialog.this.createButton.doClick();
					}
				}
			}
		});

	}

	private void buildOptionsButtonComponents() {
		showAdvancedOptionsButton = new JToggleButton("Advanced...");
		showAdvancedOptionsButton.setName("SHOW_ADVANCED_OPTIONS");
		showAdvancedOptionsButton.setToolTipText("Show advanced options.");
		showAdvancedOptionsButton.addActionListener(e -> {
			setRowVisibility(advOptsRow1, showAdvancedOptionsButton.isSelected());
			setRowVisibility(advOptsRow2, showAdvancedOptionsButton.isSelected());
			setRowVisibility(stringModelRow, showAdvancedOptionsButton.isSelected());
			advancedFailedCountLabel.setVisible(!showAdvancedOptionsButton.isSelected());
		});

		// the empty div ensures the initial preferred width of the dialog includes space to show a fail count
		advancedFailedCountLabel = new GDHtmlLabel("<html><div width=50></div>");
		advancedFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		advancedFailedCountLabel.setToolTipText(
			"Number of strings excluded due to filtering options in advanced options.");
		advancedFailedCountLabel.setVisible(!showAdvancedOptionsButton.isSelected());

		showScriptOptionsButton = new JToggleButton("A-Z,\u6211\u7684,\u062d\u064e\u0648\u0651");
		showScriptOptionsButton.setName("SHOW_SCRIPT_OPTIONS");
		showScriptOptionsButton.setToolTipText("Filter by character scripts (alphabets).");
		showScriptOptionsButton.addActionListener(e -> {
			setRowVisibility(scriptRow, showScriptOptionsButton.isSelected());
			updateOptionsAndRefresh();
		});

		showTranslateOptionsButton = new JToggleButton("Translate");
		showTranslateOptionsButton.setName("SHOW_TRANSLATE_OPTIONS");
		showTranslateOptionsButton.setToolTipText("Translate strings after creation.");
		showTranslateOptionsButton.addActionListener(e -> {
			setRowVisibility(translateRow, showTranslateOptionsButton.isSelected());
		});
	}

	private void buildAdvancedOptionsComponents() {
		boolean singleStringMode = isSingleStringMode();
		excludeStringsWithCodecErrorCB = new GCheckBox("Exclude codec errors");
		excludeStringsWithCodecErrorCB.setSelected(!singleStringMode);
		excludeStringsWithCodecErrorCB.addItemListener(this::checkboxItemListener);
		excludeStringsWithCodecErrorCB.setToolTipText("""
				<html>Exclude strings that have charset codec errors.<br>
				(bytes/sequences that are invalid for the chosen charset)""");

		codecErrorsCountLabel = new GDHtmlLabel();
		codecErrorsCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		codecErrorsCountLabel.setToolTipText("Number of strings excluded due to codec errors.");

		excludeStringsWithNonStdCtrlCharsCB = new GCheckBox("Exclude non-std ctrl chars");
		excludeStringsWithNonStdCtrlCharsCB.setSelected(!singleStringMode);
		excludeStringsWithNonStdCtrlCharsCB.setToolTipText("""
				<html>Exclude strings that contain non-standard control characters.<br>
				(ASCII 1..31, not including tab, CR, LF)""");
		excludeStringsWithNonStdCtrlCharsCB.addItemListener(this::checkboxItemListener);

		nonStdCtrlCharsErrorsCountLabel = new GDHtmlLabel();
		nonStdCtrlCharsErrorsCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		nonStdCtrlCharsErrorsCountLabel.setToolTipText(
			"Number of strings excluded due to non-standard control characters.");

		alignStartOfStringCB = new GCheckBox("Align start of string");
		alignStartOfStringCB.setToolTipText("""
				<html>If the chosen charset specifies a char size greater than 1, only look for<br>
				strings that begin on an aligned boundary.""");
		alignStartOfStringCB.setSelected(!singleStringMode);
		alignStartOfStringCB.addItemListener(this::checkboxItemListener);

		breakOnRefCB = new GCheckBox("Truncate at ref");
		breakOnRefCB.setSelected(true);
		breakOnRefCB.addItemListener(this::checkboxItemListener);
		breakOnRefCB.setToolTipText("Truncate strings at references.");

		minStringLengthSpinner = new IntegerSpinner(new SpinnerNumberModel( // spinner
			Long.valueOf(Math.min(5, selectedAddresses.getNumAddresses())), // initial 
			Long.valueOf(0), // min
			Long.valueOf(Math.min(99, selectedAddresses.getNumAddresses())), // max 
			Long.valueOf(1)), // inc
			3 /* columns */);
		minStringLengthSpinner.getSpinner()
				.setToolTipText(
					"Exclude strings that are shorter (in characters, not bytes) than this minimum");
		minStringLengthSpinner.getTextField().setShowNumberMode(false);
		minStringLengthSpinner.getSpinner().addChangeListener(e -> updateOptionsAndRefresh());

		minLenFailedCountLabel = new GDHtmlLabel();
		minLenFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		minLenFailedCountLabel.setToolTipText("Number of strings excluded due to length.");

		stringModelFilenameComboBox = new GhidraComboBox<>();
		stringModelFilenameComboBox.setEditable(true);
		for (String builtinStringModelFilename : getBuiltinStringModelFilenames()) {
			stringModelFilenameComboBox.addToModel(builtinStringModelFilename);
		}

		stringModelFilenameComboBox
				.setText(getDefault(EncodedStringsPlugin.STRINGMODEL_FILENAME_OPTIONNAME,
					EncodedStringsPlugin.STRINGMODEL_FILENAME_DEFAULT));
		stringModelFilenameComboBox.addItemListener(itemListener);
		stringModelFilenameComboBox.setToolTipText("""
				<html>Select the name of a built-in string model,<br>
				or<br>
				Enter the full path to a user-supplied .sng model file,<br>
				or<br>
				Clear the field for no string model.""");

		requireValidStringCB = new GCheckBox("Exclude invalid strings");
		requireValidStringCB.setSelected(false);
		requireValidStringCB.setToolTipText("Verify strings against the string model.");
		requireValidStringCB.addItemListener(this::checkboxItemListener);

		stringModelFailedCountLabel = new GDHtmlLabel();
		stringModelFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		stringModelFailedCountLabel
				.setToolTipText("Number of strings excluded due to failing string model check.");
	}

	private void buildScriptFilterComponents() {

		requiredUnicodeScript = new CharScriptComboBox();
		requiredUnicodeScript.setSelectedItem(CharacterScriptUtils.ANY_SCRIPT_ALIAS);
		requiredUnicodeScript.addItemListener(itemListener);
		requiredUnicodeScript.setToolTipText(
			"""
					<html>Require at least one character of this script (alphabet) to be present in the string.<p>
					<p>
					Use the <b>Allow Additional</b> toggle buttons (if currently not enabled) to<br>
					allow more strings to match.<p>
					<p>
					Note: character scripts that are drawable using the current font will have<br>
					some example characters displayed to the right of the name.""");

		scriptFailedCountLabel = new GDHtmlLabel();
		scriptFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		scriptFailedCountLabel
				.setToolTipText("Number of strings excluded due to failing script requirements.");

		allowLatinScriptButton = new JToggleButton("A-Z");
		allowLatinScriptButton.setName("ALLOW_LATIN_SCRIPT");
		Gui.registerFont(allowLatinScriptButton, BUTTON_FONT_ID);

		allowLatinScriptButton.setToolTipText(
			"Allow Latin characters (e.g. A-Z, etc) to also be present in the string.");
		allowLatinScriptButton.setSelected(true);
		allowLatinScriptButton.addItemListener(this::checkboxItemListener);

		latinScriptFailedCountLabel = new GDHtmlLabel();
		latinScriptFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		latinScriptFailedCountLabel.setToolTipText(
			"Number of strings excluded because they contained Latin characters.");

		allowCommonScriptButton = new JToggleButton("0-9,!?");
		allowCommonScriptButton.setName("ALLOW_COMMON_SCRIPT");
		Gui.registerFont(allowCommonScriptButton, BUTTON_FONT_ID);
		allowCommonScriptButton.setToolTipText(
			"Allow common characters (e.g. 0-9, space, punctuation, etc) to also be present in the string.");
		allowCommonScriptButton.setSelected(true);
		allowCommonScriptButton.addItemListener(this::checkboxItemListener);

		commonScriptFailedCountLabel = new GDHtmlLabel();
		commonScriptFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		commonScriptFailedCountLabel.setToolTipText(
			"Number of strings excluded because they contained Common (0-9, space, punctuation, etc) characters.");

		allowAnyScriptButton = new JToggleButton("Any");
		allowAnyScriptButton.setName("ALLOW_ANY_SCRIPT");
		Gui.registerFont(allowAnyScriptButton, BUTTON_FONT_ID);
		allowAnyScriptButton.setToolTipText(
			"Allow all other character scripts to also be present in the string.");
		allowAnyScriptButton.setSelected(true);
		allowAnyScriptButton.addItemListener(this::checkboxItemListener);

		otherScriptsFailedCountLabel = new GDHtmlLabel();
		otherScriptsFailedCountLabel.setForeground(GThemeDefaults.Colors.Messages.ERROR);
		otherScriptsFailedCountLabel.setToolTipText(
			"Number of strings excluded because they contained characters from other scripts (alphabets).");
	}

	private List<String> getBuiltinStringModelFilenames() {
		return List.of(EncodedStringsPlugin.STRINGMODEL_FILENAME_DEFAULT);
	}

	private void fixupComboBoxSizes() {
		// Make the charset and script comboboxes the same width
		requiredUnicodeScript.setPreferredSize(charsetComboBox.getPreferredSize());
	}

	private void buildTranslateComponents() {
		List<StringTranslationService> translationServices =
			StringTranslationService.getCurrentStringTranslationServices(tool);
		translateComboBox = new GhidraComboBox<>(translationServices);
		StringTranslationService defaultSTS = getDefaultTranslationService(translationServices);
		if (defaultSTS != null) {
			translateComboBox.setSelectedItem(defaultSTS);
		}

		translateComboBox.setRenderer(GListCellRenderer.createDefaultCellTextRenderer(
			sts -> sts != null ? sts.getTranslationServiceName() : ""));
	}

	private void setRowVisibility(int rowNum, boolean b) {
		Component leftComp = optionsPanel.getComponent(rowNum * 2);
		leftComp.setVisible(b);
		Component rightComp = optionsPanel.getComponent(rowNum * 2 + 1);
		rightComp.setVisible(b);
		if (b) {
			// if a row is going to take space from the dialog, check the table
			Swing.runLater(this::fixTooSmallTablePanel);
		}
	}

	private void fixTooSmallTablePanel() {
		int rowHeight = table.getRowHeight();
		Dimension tableSize = threadedTablePanel.getSize();
		int desiredMinTableHt = rowHeight * 4; // aprox 2 rows + header + filter input
		if (tableSize.height < desiredMinTableHt) {
			Dimension dlgSize = getDialogSize();
			dlgSize.height += (desiredMinTableHt - tableSize.height);
			setDialogSize(dlgSize);
		}
	}

	private int addRow(Component leftComponent, Component... rightComponents) {
		if (leftComponent == null) {
			leftComponent = new GLabel();
		}
		Component rightComponent;
		if (rightComponents.length > 1) {
			JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
			for (Component c : rightComponents) {
				if (c != null) {
					panel.add(c);
				}
			}
			rightComponent = panel;
		}
		else {
			rightComponent = rightComponents[0];
		}
		optionsPanel.add(leftComponent);
		optionsPanel.add(rightComponent);
		return optionsPanelRowCount++;
	}

	@Override
	protected void dialogShown() {
		fixupComboBoxSizes();
		updateOptionsAndRefresh();
	}

	@Override
	protected void cancelCallback() {
		saveDefaults();
		close();
	}

	@Override
	public void close() {
		super.close();
		dispose();
	}

	@Override
	public void dispose() {
		plugin.dialogClosed(this);
		table.dispose();
		super.dispose();
	}

	private void createStrings() {
		setActionItemEnablement(false);
		executeMonitoredRunnable("Creating Strings", true, true, 100, this::createStrings);
	}

	private void createStringsAndClose() {
		saveDefaults();
		setActionItemEnablement(false);
		executeMonitoredRunnable("Creating Strings", true, true, 100, this::createStringsAndClose);
	}

	private void setActionItemEnablement(boolean enabled) {
		createButton.setEnabled(enabled);
		cancelButton.setEnabled(enabled);
		table.removeNavigation();
		if (enabled) {
			table.installNavigation(tool);
		}
	}

	private void createStringsHelper(TaskMonitor monitor) {
		int count = 0;
		setStatusText("Creating strings...");
		int txId = program.startTransaction("Create Strings");
		boolean success = false;
		try {
			List<EncodedStringsRow> stringsToCreate = new ArrayList<>();
			int[] selectedRowNums = table.getSelectedRows();
			if (selectedRowNums.length == 0) {
				stringsToCreate.addAll(tableModel.getUnfilteredData());
			}
			else {
				stringsToCreate.addAll(tableModel.getRowObjects(selectedRowNums));
			}

			monitor.initialize(stringsToCreate.size());
			monitor.setMessage("Creating strings...");
			Settings settings = currentOptions.settings();
			List<ProgramLocation> newStrings = new ArrayList<>();
			for (EncodedStringsRow row : stringsToCreate) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.incrementProgress(1);
				try {
					Data data = DataUtilities.createData(program, row.sdi().getAddress(),
						currentOptions.stringDT(), row.sdi().getDataLength(), false,
						ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);

					// copy settings to new data instance
					for (String settingName : settings.getNames()) {
						Object settingValue = settings.getValue(settingName);
						data.setValue(settingName, settingValue);
					}

					count++;
					newStrings.add(new ProgramLocation(program, row.sdi().getAddress()));
				}
				catch (CodeUnitInsertionException e) {
					Msg.warn(this, "Failed to create string at " + row.sdi().getAddress());
				}
			}
			tool.setStatusInfo("Created %d strings.".formatted(count));
			tableModel.removeRows(stringsToCreate);
			if (selectedRowNums.length > 0 && selectedRowNums[0] < tableModel.getRowCount()) {
				// Re-select the current row after table update to enbiggen the user experience.
				// See table listener for the other end of this
				rowToSelect.set(selectedRowNums[0]);
			}
			StringTranslationService sts = getSelectedStringTranslationService(true);
			if (sts != null) {
				Swing.runLater(
					() -> sts.translate(program, newStrings, new TranslateOptions(true)));
			}
			success = true;
		}
		finally {
			program.endTransaction(txId, success);
		}
	}

	private void createStrings(TaskMonitor monitor) {
		createStringsHelper(monitor);
		Swing.runLater(() -> setActionItemEnablement(true));
	}

	private void createStringsAndClose(TaskMonitor monitor) {
		createStringsHelper(monitor);
		Swing.runLater(this::close);
	}

	private void setCreateButtonInfo(int rowCount, int selectedRowCount) {
		if (rowCount == 0) {
			createButton.setText("Create");
			createButton.setEnabled(false);
			return;
		}
		String createMessage = isSingleStringMode() ? "Create"
				: "Create %s"
						.formatted(rowCount == selectedRowCount || selectedRowCount == 0 ? "All"
								: "Selected (%d)".formatted(selectedRowCount));
		createButton.setEnabled(true);
		createButton.setText(createMessage);

	}

	private void selectedRowChange() {
		int rowCount = table.getRowCount();
		int selectedRowCount = table.getSelectedRowCount();
		setCreateButtonInfo(rowCount, selectedRowCount);
		if (selectedRowCount == 1) {
			int[] selectedRows = table.getSelectedRows();
			table.navigate(selectedRows[0], 0 /* location col */);
		}
	}

	private List<Address> getSelectedAddresses() {
		List<Address> result = new ArrayList<>();
		for (EncodedStringsRow row : tableModel.getRowObjects(table.getSelectedRows())) {
			result.add(row.sdi().getAddress());
		}
		return result;
	}

	private void setSelectedAddresses(List<Address> addrs) {
		Set<Address> addrSet = new HashSet<>(addrs);
		for (EncodedStringsRow row : tableModel.getModelData()) {
			if (addrSet.contains(row.sdi().getAddress())) {
				int viewIndex = tableModel.getViewIndex(row);
				if (viewIndex >= 0) {
					table.getSelectionManager().addSelectionInterval(viewIndex, viewIndex);
				}
			}
		}
	}

	private void suppressRecursiveCallbacks(AtomicBoolean flag, Runnable r) {
		if (flag.compareAndSet(false, true)) {
			r.run();
			flag.set(false);
		}
	}

	private void updateOptionsAndRefresh() {
		suppressRecursiveCallbacks(updateInProgressFlag, () -> {
			List<Address> selectedAddrs = getSelectedAddresses();
			if (!selectedAddrs.isEmpty()) {
				previouslySelectedRowAddrs.set(selectedAddrs);
			}

			updateOptions();
			tableModel.setOptions(currentOptions);
			selectedRowChange();
		});
	}

	private String getErrorCountString(int count) {
		return count > 0 ? "<html><sup>[%d]".formatted(count) : null;
	}

	private void updateOptions() {
		String charsetName = charsetComboBox.getSelectedItem().toString();
		if (!charsetExists(charsetName)) {
			charsetName = CharsetInfo.USASCII;
		}

		boolean scriptOptions = showScriptOptionsButton.isSelected();
		boolean excludeStringsWithErrors = excludeStringsWithCodecErrorCB.isSelected();
		boolean excludeStringsWithNonStdCtrlChars =
			excludeStringsWithNonStdCtrlCharsCB.isSelected();
		boolean alignStartofString = alignStartOfStringCB.isSelected();

		// override the strminlen if the address range selection would be too small
		int minStrLen = !isSingleStringMode()
				? (int) Math.min(minStringLengthSpinner.getTextField().getIntValue(),
					selectedAddresses.getNumAddresses())
				: -1; // single string mode - no min len

		AbstractStringDataType stringDT = CHARSET_TO_DT_MAP.get(charsetName);
		Settings settings = SettingsImpl.NO_SETTINGS;
		if (stringDT == null) {
			stringDT = StringDataType.dataType;
			settings = new SettingsImpl();
			CharsetSettingsDefinition.CHARSET.setCharset(settings, charsetName);
		}
		int charSize = CharsetInfo.getInstance().getCharsetCharSize(charsetName);

		updateTrigramStringValidator(stringModelFilenameComboBox.getText());
		boolean requireValidStrings = requireValidStringCB.isSelected();
		boolean breakOnRef = breakOnRefCB.isSelected();

		currentOptions = new EncodedStringsOptions(stringDT, settings, charsetName,
			scriptOptions ? getRequiredScripts() : null, scriptOptions ? getAllowedScripts() : null,
			excludeStringsWithErrors, excludeStringsWithNonStdCtrlChars, alignStartofString,
			charSize, minStrLen, breakOnRef, stringValidator, requireValidStrings);
	}

	private void updateTrigramStringValidator(String newTrigramModelFilename) {
		if (!newTrigramModelFilename.equals(trigramModelFilename)) {
			trigramModelFilename = newTrigramModelFilename;
			ResourceFile file = getTrigramStringModelFile(trigramModelFilename);
			try {
				stringValidator = file != null ? TrigramStringValidator.read(file) : null;
			}
			catch (IOException e) {
				Msg.error(this, "Error reading string model file", e);
				stringValidator = null;
			}
		}
	}

	private ResourceFile getTrigramStringModelFile(String filename) {
		if (filename == null || filename.isBlank()) {
			return null;
		}
		File f = new File(filename);
		ResourceFile rf = f.isAbsolute() && f.isFile() ? new ResourceFile(f)
				: Application.findDataFileInAnyModule(filename);
		if (rf == null) {
			Msg.error(this, "Unable to find string model file: %s".formatted(filename));
		}
		return rf;
	}

	private Set<UnicodeScript> getRequiredScripts() {
		Set<UnicodeScript> scripts = EnumSet.noneOf(UnicodeScript.class);
		UnicodeScript selectedUnicodeScript =
			(UnicodeScript) requiredUnicodeScript.getSelectedItem();
		if (selectedUnicodeScript != null &&
			selectedUnicodeScript != CharacterScriptUtils.ANY_SCRIPT_ALIAS) {
			scripts.add(selectedUnicodeScript);
		}
		return scripts;
	}

	private Set<UnicodeScript> getAllowedScripts() {
		Set<UnicodeScript> results = EnumSet.noneOf(UnicodeScript.class);
		if (allowAnyScriptButton.isSelected()) {
			results.addAll(EnumSet.allOf(UnicodeScript.class));
			results.remove(UnicodeScript.LATIN);
			results.remove(UnicodeScript.COMMON);
		}

		if (allowLatinScriptButton.isSelected()) {
			results.add(UnicodeScript.LATIN);
		}
		if (allowCommonScriptButton.isSelected()) {
			results.add(UnicodeScript.COMMON);
		}
		return results;
	}

	private String getDefault(String optionName, String defaultValue) {
		ToolOptions stringOptions = tool.getOptions(EncodedStringsPlugin.STRINGS_OPTION_NAME);
		return stringOptions.getString(optionName, defaultValue);
	}

	private StringTranslationService getDefaultTranslationService(
			List<StringTranslationService> translationServices) {
		String translationServiceName =
			getDefault(EncodedStringsPlugin.TRANSLATE_SERVICE_OPTIONNAME, null);
		if (translationServiceName != null) {
			for (StringTranslationService sts : translationServices) {
				if (translationServiceName.equals(sts.getTranslationServiceName())) {
					return sts;
				}
			}
		}
		return null;
	}

	private StringTranslationService getSelectedStringTranslationService(boolean ifEnabled) {
		boolean enabled = showTranslateOptionsButton.isSelected();
		return ifEnabled && !enabled ? null
				: (StringTranslationService) translateComboBox.getSelectedItem();
	}

	private void saveDefaults() {
		if (currentOptions == null) {
			return;
		}
		ToolOptions stringOptions = tool.getOptions(EncodedStringsPlugin.STRINGS_OPTION_NAME);

		stringOptions.setString(EncodedStringsPlugin.CHARSET_OPTIONNAME,
			currentOptions.charsetName());

		StringTranslationService sts = getSelectedStringTranslationService(false);
		stringOptions.setString(EncodedStringsPlugin.TRANSLATE_SERVICE_OPTIONNAME,
			sts != null ? sts.getTranslationServiceName() : null);

		stringOptions.setString(EncodedStringsPlugin.STRINGMODEL_FILENAME_OPTIONNAME,
			trigramModelFilename);
	}

	private void comboboxItemListener(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			updateOptionsAndRefresh();
		}
	}

	private void checkboxItemListener(ItemEvent e) {
		updateOptionsAndRefresh();
	}

	private void updateRequiredScriptsList(EncodedStringsFilterStats stats) {
		requiredUnicodeScript.removeItemListener(itemListener);

		UnicodeScript currentSelectedScript =
			(UnicodeScript) requiredUnicodeScript.getSelectedItem();

		requiredUnicodeScript.setModel(getScriptListModel(stats));
		if (stats.foundScriptCounts.containsKey(currentSelectedScript)) {
			requiredUnicodeScript.setSelectedItem(currentSelectedScript);
		}
		else {
			requiredUnicodeScript.setSelectedItem(CharacterScriptUtils.ANY_SCRIPT_ALIAS);
		}
		requiredUnicodeScript.addItemListener(itemListener);

	}

	private ComboBoxModel<UnicodeScript> getScriptListModel(EncodedStringsFilterStats stats) {
		List<UnicodeScript> scripts = new ArrayList<>(stats.foundScriptCounts.keySet());
		Collections.sort(scripts, (us1, us2) -> {
			int us1Count = stats.foundScriptCounts.get(us1);
			int us2Count = stats.foundScriptCounts.get(us2);
			return Integer.compare(us2Count, us1Count); // descending
		});
		scripts.add(0, CharacterScriptUtils.ANY_SCRIPT_ALIAS);

		return new DefaultComboBoxModel<>(new Vector<>(scripts));
	}

	private boolean isSingleStringMode() {
		return selectedAddresses.getNumAddresses() == 1;
	}

	/**
	 * Execute a non-modal task that has progress and can be cancelled.
	 * <p>
	 * See {@link #executeProgressTask(Task, int)}.
	 *
	 * @param taskTitle String title of task
	 * @param canCancel boolean flag, if true task can be canceled by the user
	 * @param hasProgress boolean flag, if true the task has a progress meter
	 * @param delay int number of milliseconds to delay before showing the task's
	 * progress
	 * @param runnable {@link MonitoredRunnable} to run
	 */
	private void executeMonitoredRunnable(String taskTitle, boolean canCancel, boolean hasProgress,
			int delay, MonitoredRunnable runnable) {
		Task task = new Task(taskTitle, canCancel, hasProgress, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				runnable.monitoredRun(monitor);
			}
		};
		executeProgressTask(task, delay);
	}

	private static String makeTitleString(AddressSetView addrs) {
		return "Search For Encoded Strings - %s (%s - %s)".formatted(
			formatLength(addrs.getNumAddresses(), "addresses"), addrs.getMinAddress(),
			addrs.getMaxAddress());
	}

	private static boolean charsetExists(String charsetName) {
		try {
			Charset charset = Charset.forName(charsetName);
			return charset != null;
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	private static String formatLength(long length, String unitSuffix) {
		int divisor = 1;
		String unitPrefix = "";
		if (length < 1000) {
			// nothing
		}
		else if (length < 1000000) {
			divisor = 1000;
			unitPrefix = "K";
		}
		else {
			divisor = 1000000;
			unitPrefix = "M";
		}

		return "%d%s %s".formatted(length / divisor, unitPrefix, unitSuffix);
	}

	private class CharScriptComboBox extends GhidraComboBox<UnicodeScript> {

		CharScriptComboBox() {
			super(List.of(CharacterScriptUtils.ANY_SCRIPT_ALIAS));

			Function<UnicodeScript, String> cellToTextMappingFunction = unicodeScript -> {
				buildScriptExamplesMap(getFont());
				if (unicodeScript == null) {
					return "";
				}
				if (unicodeScript == CharacterScriptUtils.ANY_SCRIPT_ALIAS) {
					return "<ANY>";
				}
				String name = unicodeScript.name();
				String example = scriptExampleStrings.getOrDefault(unicodeScript, "");
				if (!example.isEmpty()) {
					example = " \u2014 " + example;
				}
				int count = prevStats.foundScriptCounts.getOrDefault(unicodeScript, 0);
				return "%s%s (%d)".formatted(name, example, count);
			};

			setRenderer(GListCellRenderer.createDefaultCellTextRenderer(cellToTextMappingFunction));
		}
	}

}
