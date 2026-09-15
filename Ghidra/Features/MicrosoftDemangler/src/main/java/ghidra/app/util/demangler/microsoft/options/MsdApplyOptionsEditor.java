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
package ghidra.app.util.demangler.microsoft.options;

import java.awt.*;
import java.beans.PropertyEditorSupport;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import docking.options.editor.OptionsEditorAlignable;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import ghidra.app.util.demangler.microsoft.MsCInterpretation;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.PairLayout;

/**
 * Editor used presenting and receiving GUI changes to {@link MsdApplyOption}
 */
public class MsdApplyOptionsEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String USE_KNOWN_PATTERNS_LABEL = "Demangle Only Known Mangled Symbols";
	public static final String APPLY_SIGNATURE_LABEL = "Apply Function Signatures";
	public static final String APPLY_CALLING_CONVENTION_LABEL =
		"Apply Function Calling Conventions";

	public static final String MS_C_INTERPRETATION_LABEL = "C-Style Symbol Interpretation";

	private static final String[] NAMES = { USE_KNOWN_PATTERNS_LABEL, APPLY_SIGNATURE_LABEL,
		APPLY_CALLING_CONVENTION_LABEL, MS_C_INTERPRETATION_LABEL };

	// help tooltips
	private static final String USE_KNOWN_PATTERNS_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Only demangle symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.",
		75);
	private static final String APPLY_SIGNATURE_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Apply any recovered function signature, in addition to the function name",
		75);
	private static final String APPLY_CALLING_CONVENTION_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Apply any recovered function signature calling convention",
		75);
	private static final String MS_C_INTERPRETATION_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"When ambiguous, treat C-Style mangled symbol as: function, variable," +
			" or function if a function exists",
		75);

	private static final String[] DESCRIPTIONS = { USE_KNOWN_PATTERNS_TOOLTIP,
		APPLY_SIGNATURE_TOOLTIP, APPLY_CALLING_CONVENTION_TOOLTIP, MS_C_INTERPRETATION_TOOLTIP };

	private MsdApplyOption applyOption;

	private Component editorComponent;

	private JLabel interpretationLabel;
	private JLabel callingConventionLabel;
	private JLabel signatureLabel;
	private JLabel knownPatternsLabel;

	private JCheckBox knownPatternsCb;
	private JCheckBox signatureCb;
	private JCheckBox callingConventionCb;
	private JComboBox<MsCInterpretation> interpretationComboBox;

	public MsdApplyOptionsEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new PairLayout(0, 6));

		knownPatternsCb = new GCheckBox();
		knownPatternsCb.setSelected(false);
		knownPatternsCb.setToolTipText(USE_KNOWN_PATTERNS_TOOLTIP);
		knownPatternsLabel = new JLabel(USE_KNOWN_PATTERNS_LABEL, SwingConstants.RIGHT);
		knownPatternsLabel.setLabelFor(knownPatternsCb);
		knownPatternsLabel.setToolTipText(USE_KNOWN_PATTERNS_TOOLTIP);
		panel.add(knownPatternsLabel);
		panel.add(knownPatternsCb);

		signatureCb = new GCheckBox();
		signatureCb.setSelected(false);
		signatureCb.setToolTipText(APPLY_SIGNATURE_TOOLTIP);
		signatureLabel = new JLabel(APPLY_SIGNATURE_LABEL, SwingConstants.RIGHT);
		signatureLabel.setLabelFor(signatureCb);
		signatureLabel.setToolTipText(APPLY_SIGNATURE_TOOLTIP);
		panel.add(signatureLabel);
		panel.add(signatureCb);

		callingConventionCb = new GCheckBox();
		callingConventionCb.setSelected(false);
		callingConventionCb.setToolTipText(APPLY_CALLING_CONVENTION_TOOLTIP);
		callingConventionLabel = new JLabel(APPLY_CALLING_CONVENTION_LABEL, SwingConstants.RIGHT);
		callingConventionLabel.setLabelFor(callingConventionCb);
		callingConventionLabel.setToolTipText(APPLY_CALLING_CONVENTION_TOOLTIP);
		panel.add(callingConventionLabel);
		panel.add(callingConventionCb);

		interpretationComboBox = new GComboBox<>(MsCInterpretation.values());
		interpretationComboBox.setSelectedItem(false);
		interpretationComboBox.setToolTipText(MS_C_INTERPRETATION_TOOLTIP);
		interpretationLabel = new JLabel(MS_C_INTERPRETATION_LABEL, SwingConstants.RIGHT);
		interpretationLabel.setLabelFor(interpretationComboBox);
		interpretationLabel.setToolTipText(MS_C_INTERPRETATION_TOOLTIP);
		panel.add(interpretationLabel);
		panel.add(interpretationComboBox);

		knownPatternsCb.addItemListener(e -> firePropertyChange());
		signatureCb.addItemListener(e -> {
			signatureChangeListener();
			firePropertyChange();
		});
		callingConventionCb.addItemListener(e -> firePropertyChange());
		interpretationComboBox.addItemListener(e -> firePropertyChange());

		Border emptyBorder = BorderFactory.createEmptyBorder(0, 0, 0, 0);
		TitledBorder titledNoLineBorder = BorderFactory.createTitledBorder(
			emptyBorder,          // The invisible base border
			"Apply Options",      // The title text
			TitledBorder.LEADING, // Title justification (e.g., LEADING, CENTER, TRAILING)
			TitledBorder.TOP,     // Title position (e.g., TOP, BOTTOM)
			null, 				  // Optional: Font
			null           		  // Optional: Title color
		);

		// Use an outer panel so we can offset the main panel
		JPanel outerPanel = new AlignablePanel(new BorderLayout());

		panel.setBorder(BorderFactory.createEmptyBorder(5, 20, 0, 0));

		outerPanel.add(panel, BorderLayout.CENTER);
		outerPanel.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(10, 0, 10, 0), titledNoLineBorder));

		return outerPanel;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof MsdApplyOption option)) {
			return;
		}
		applyOption = option;
		setLocalValues(applyOption);
		firePropertyChange();
	}

	private void setLocalValues(MsdApplyOption applyOptions) {
		boolean knownPatterns = applyOptions.demangleOnlyKnownPatterns();
		if (knownPatterns != knownPatternsCb.isSelected()) {
			knownPatternsCb.setSelected(knownPatterns);
		}

		boolean applySignature = applyOptions.applySignature();
		if (applySignature != signatureCb.isSelected()) {
			signatureCb.setSelected(applySignature);
		}

		boolean applyCc = applyOptions.applyCallingConvention();
		if (applyCc != callingConventionCb.isSelected()) {
			callingConventionCb.setSelected(applyCc);
		}

		MsCInterpretation interpretation = applyOptions.getInterpretation();
		if (interpretation != interpretationComboBox.getSelectedItem()) {
			interpretationComboBox.setSelectedItem(interpretation);
		}

		signatureChangeListener();
	}

	private void signatureChangeListener() {
		// Calling convention enabled only if signature is selected
		boolean signatureEnabled = signatureCb.isSelected();
		callingConventionCb.setEnabled(signatureEnabled);
	}

	private MsdApplyOption cloneNamespaceValues() {
		MsdApplyOption newOptions = new MsdApplyOption(knownPatternsCb.isSelected(),
			signatureCb.isSelected(), callingConventionCb.isSelected(),
			(MsCInterpretation) interpretationComboBox.getSelectedItem());
		return newOptions;
	}

	@Override
	public String[] getOptionDescriptions() {
		return DESCRIPTIONS;
	}

	@Override
	public String[] getOptionNames() {
		return NAMES;
	}

	@Override
	public Object getValue() {
		return cloneNamespaceValues();
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	// Allows us to mimic the alignment of the normal options for this custom editor and any other
	// custom editor in the same view as us
	private class AlignablePanel extends JPanel implements OptionsEditorAlignable {

		AlignablePanel(LayoutManager layout) {
			super(layout);
		}

		@Override
		public Dimension getPreferredAlignmentSize() {
			//
			// Use all labels and components to find the overall preferred size.
			//
			int maxWidth = 0;
			int maxHeight = 0;
			Dimension size = getPairDimension(knownPatternsLabel, knownPatternsCb);
			maxWidth = Math.max(size.width, maxWidth);
			maxHeight = Math.max(size.height, maxHeight);

			size = getPairDimension(signatureLabel, signatureCb);
			maxWidth = Math.max(size.width, maxWidth);
			maxHeight = Math.max(size.height, maxHeight);

			size = getPairDimension(callingConventionLabel, callingConventionCb);
			maxWidth = Math.max(size.width, maxWidth);
			maxHeight = Math.max(size.height, maxHeight);

			size = getPairDimension(interpretationLabel, interpretationComboBox);
			maxWidth = Math.max(size.width, maxWidth);
			maxHeight = Math.max(size.height, maxHeight);

			return new Dimension(maxWidth, maxHeight);
		}

		private Dimension getPairDimension(JLabel label, JComponent c) {
			// Note: this code is taken from DefaultOptionComponent
			Dimension dimension = label.getPreferredSize();
			int labelWidth = dimension.width;
			int labelHeight = dimension.height;
			int maxHeight = Math.max(labelHeight, c.getPreferredSize().height);
			return new Dimension(labelWidth, maxHeight);
		}

		@Override
		public void setPreferredAlignmentSize(Dimension size) {
			// This is called after all preferred sizes have been retrieved and combined
			knownPatternsLabel.setPreferredSize(size);
			signatureLabel.setPreferredSize(size);
			callingConventionLabel.setPreferredSize(size);
			interpretationLabel.setPreferredSize(size);
		}
	}
}
