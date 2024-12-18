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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.text.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import ghidra.app.util.HelpTopics;
import ghidra.docking.util.LookAndFeelUtils;
import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.program.model.lang.Endian;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import help.Help;
import help.HelpService;

/**
 * Internal panel of the memory search window that manages the controls for the search settings.
 * This panel can be added or removed via a toolbar action. Not showing by default.
 */
class MemorySearchOptionsPanel extends JPanel {
	private SearchGuiModel model;
	private GCheckBox caseSensitiveCheckbox;
	private GCheckBox escapeSequencesCheckbox;
	private GCheckBox decimalUnsignedCheckbox;
	private GComboBox<Integer> decimalByteSizeCombo;
	private GComboBox<Charset> charsetCombo;
	private GComboBox<String> endianessCombo;
	private boolean isNimbus;

	MemorySearchOptionsPanel(SearchGuiModel model) {
		super(new BorderLayout());
		this.model = model;

		// if the look and feel is Nimbus, the spaceing it too big, so we use less spacing
		// between elements.
		isNimbus = LookAndFeelUtils.isUsingNimbusUI();

		JPanel scrolledPanel = new JPanel(new VerticalLayout(isNimbus ? 8 : 16));
		scrolledPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));

		scrolledPanel.add(buildByteOptionsPanel());
		scrolledPanel.add(buildDecimalOptions());
		scrolledPanel.add(buildStringOptions());
		scrolledPanel.add(buildCodeUnitScopePanel());
		scrolledPanel.add(buildMemorySearchRegionsPanel());

		JScrollPane scroll = new JScrollPane(scrolledPanel);
		scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);

		add(scroll, BorderLayout.CENTER);

		model.addChangeCallback(this::guiModelChanged);
		HelpService helpService = Help.getHelpService();
		helpService.registerHelp(this, new HelpLocation(HelpTopics.SEARCH, "Options"));

	}

	@Override
	public Dimension getPreferredSize() {
		Dimension size = super.getPreferredSize();
		size.width += 20;	// reserve space for the optional vertical scroll bar
		return size;
	}

	private JComponent buildMemorySearchRegionsPanel() {
		JPanel panel = new JPanel(new VerticalLayout(3));
		panel.setBorder(createBorder("Search Region Filter"));

		List<SearchRegion> choices = model.getMemoryRegionChoices();
		for (SearchRegion region : choices) {
			GCheckBox checkbox = new GCheckBox(region.getName());
			checkbox.setToolTipText(region.getDescription());
			checkbox.setSelected(model.isSelectedRegion(region));
			checkbox.addItemListener(e -> model.selectRegion(region, checkbox.isSelected()));
			panel.add(checkbox);
		}
		return panel;
	}

	private JComponent buildDecimalOptions() {
		JPanel panel = new JPanel(new VerticalLayout(3));
		panel.setBorder(createBorder("Decimal Options"));

		JPanel innerPanel = new JPanel(new PairLayout(5, 5));
		JLabel label = new JLabel("Size:");
		label.setToolTipText("Size of decimal values in bytes");
		innerPanel.add(label);

		Integer[] decimalSizes = new Integer[] { 1, 2, 3, 4, 5, 6, 7, 8, 16 };
		decimalByteSizeCombo = new GComboBox<>(decimalSizes);
		decimalByteSizeCombo.setSelectedItem(4);
		decimalByteSizeCombo.addItemListener(this::byteSizeComboChanged);
		decimalByteSizeCombo.setToolTipText("Size of decimal values in bytes");
		innerPanel.add(decimalByteSizeCombo);
		panel.add(innerPanel);

		decimalUnsignedCheckbox = new GCheckBox("Unsigned");
		decimalUnsignedCheckbox.setToolTipText(
			"Sets whether decimal values should be interpreted as unsigned values");
		decimalUnsignedCheckbox.addActionListener(
			e -> model.setDecimalUnsigned(decimalUnsignedCheckbox.isSelected()));

		panel.add(decimalUnsignedCheckbox);
		return panel;
	}

	private void byteSizeComboChanged(ItemEvent e) {
		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}
		int byteSize = (Integer) e.getItem();
		model.setDecimalByteSize(byteSize);
	}

	private JComponent buildCodeUnitScopePanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(createBorder("Code Type Filter"));
		GCheckBox instructionsCheckBox = new GCheckBox("Instructions");
		GCheckBox definedDataCheckBox = new GCheckBox("Defined Data");
		GCheckBox undefinedDataCheckBox = new GCheckBox("Undefined Data");
		instructionsCheckBox.setToolTipText(
			"If selected, include matches found in instructions");
		definedDataCheckBox.setToolTipText(
			"If selected, include matches found in defined data");
		undefinedDataCheckBox.setToolTipText(
			"If selected, include matches found in undefined data");
		instructionsCheckBox.setSelected(model.includeInstructions());
		definedDataCheckBox.setSelected(model.includeDefinedData());
		undefinedDataCheckBox.setSelected(model.includeUndefinedData());
		instructionsCheckBox.addActionListener(
			e -> model.setIncludeInstructions(instructionsCheckBox.isSelected()));
		definedDataCheckBox.addActionListener(
			e -> model.setIncludeDefinedData(definedDataCheckBox.isSelected()));
		undefinedDataCheckBox.addActionListener(
			e -> model.setIncludeUndefinedData(undefinedDataCheckBox.isSelected()));
		panel.add(instructionsCheckBox);
		panel.add(definedDataCheckBox);
		panel.add(undefinedDataCheckBox);
		return panel;
	}

	private JComponent buildByteOptionsPanel() {
		JPanel panel = new JPanel(new PairLayout(3, 2));
		panel.setBorder(createBorder("Byte Options"));

		String[] endianess = new String[] { "Big", "Little" };
		endianessCombo = new GComboBox<>(endianess);
		endianessCombo.setSelectedIndex(model.isBigEndian() ? 0 : 1);
		endianessCombo.addItemListener(this::endianessComboChanged);
		endianessCombo.setToolTipText("Selects the endianess");

		JTextField alignField = new JTextField(5);
		alignField.setDocument(new RestrictedInputDocument());
		alignField.setName("Alignment");
		alignField.setText(Integer.toString(model.getAlignment()));
		alignField.setToolTipText(
			"Filters out matches whose address is not divisible by the alignment value");

		panel.add(new JLabel("Endianess:"));
		panel.add(endianessCombo);
		panel.add(new JLabel("Alignment:"));
		panel.add(alignField);

		return panel;
	}

	private void endianessComboChanged(ItemEvent e) {
		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}
		String endianString = (String) e.getItem();
		Endian endian = Endian.toEndian(endianString);
		model.setBigEndian(endian.isBigEndian());
	}

	private JComponent buildStringOptions() {
		JPanel panel = new JPanel(new VerticalLayout(3));
		Charset[] supportedCharsets =
			{ StandardCharsets.US_ASCII, StandardCharsets.UTF_8, StandardCharsets.UTF_16 };

		charsetCombo = new GComboBox<>(supportedCharsets);
		charsetCombo.setName("Encoding Options");
		charsetCombo.setSelectedIndex(0);
		charsetCombo.addItemListener(this::encodingComboChanged);
		charsetCombo.setToolTipText("Character encoding for translating strings to bytes");

		JPanel innerPanel = new JPanel(new PairLayout(5, 5));
		JLabel label = new JLabel("Encoding:");
		label.setToolTipText("Character encoding for translating strings to bytes");
		innerPanel.add(label);
		innerPanel.add(charsetCombo);
		panel.add(innerPanel);

		caseSensitiveCheckbox = new GCheckBox("Case Sensitive");
		caseSensitiveCheckbox.setSelected(model.isCaseSensitive());
		caseSensitiveCheckbox.setToolTipText("Allows for case sensitive searching.");
		caseSensitiveCheckbox.addActionListener(
			e -> model.setCaseSensitive(caseSensitiveCheckbox.isSelected()));

		escapeSequencesCheckbox = new GCheckBox("Escape Sequences");
		escapeSequencesCheckbox.setSelected(model.useEscapeSequences());
		escapeSequencesCheckbox.setToolTipText(
			"Allows specifying control characters using escape sequences " +
				"(i.e., allows \\n to be searched for as a single line feed character).");
		escapeSequencesCheckbox.addActionListener(
			e -> model.setUseEscapeSequences(escapeSequencesCheckbox.isSelected()));

		panel.setBorder(createBorder("String Options"));
		panel.add(caseSensitiveCheckbox);
		panel.add(escapeSequencesCheckbox);
		return panel;
	}

	private void encodingComboChanged(ItemEvent e) {
		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}
		Charset charSet = (Charset) e.getItem();
		model.setStringCharset(charSet);
	}

	private void guiModelChanged(SearchSettings oldSettings) {
		endianessCombo.setSelectedItem(model.isBigEndian() ? "Big" : "Little");
		caseSensitiveCheckbox.setSelected(model.isCaseSensitive());
		escapeSequencesCheckbox.setSelected(model.useEscapeSequences());
		decimalByteSizeCombo.setSelectedItem(model.getDecimalByteSize());
		decimalUnsignedCheckbox.setSelected(model.isDecimalUnsigned());
		charsetCombo.setSelectedItem(model.getStringCharset());
	}

	private Border createBorder(String name) {
		TitledBorder outerBorder = BorderFactory.createTitledBorder(name);
		if (isNimbus) {
			return outerBorder;
		}
		Border innerBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);
		return BorderFactory.createCompoundBorder(outerBorder, innerBorder);
	}

	/**
	 * Custom Document that validates user input on the fly.
	 */
	private class RestrictedInputDocument extends DefaultStyledDocument {

		/**
		 * Called before new user input is inserted into the entry text field.  The super
		 * method is called if the input is accepted.
		 */
		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(offs, currentText.length());
			String proposedText = beforeOffset + str + afterOffset;
			int alignment = getValue(proposedText);
			if (alignment > 0) {
				super.insertString(offs, str, a);
				model.setAlignment(alignment);
			}

		}

		@Override
		public void remove(int offs, int len) throws BadLocationException {

			String currentText = getText(0, getLength());
			String beforeOffset = currentText.substring(0, offs);
			String afterOffset = currentText.substring(len + offs, currentText.length());
			String proposedResult = beforeOffset + afterOffset;
			int alignment = getValue(proposedResult);
			if (alignment > 0) {
				super.remove(offs, len);
				model.setAlignment(alignment);
			}
		}

		private int getValue(String proposedText) {
			if (proposedText.isBlank()) {
				return 1;
			}
			try {
				return Integer.parseInt(proposedText);
			}
			catch (NumberFormatException e) {
				return -1;
			}
		}
	}
}
