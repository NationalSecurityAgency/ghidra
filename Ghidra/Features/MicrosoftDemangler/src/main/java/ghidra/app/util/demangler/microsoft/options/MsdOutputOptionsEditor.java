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
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.PairLayout;

/**
 * Editor used presenting and receiving GUI changes to {@link MsdOutputOption}
 */
public class MsdOutputOptionsEditor extends PropertyEditorSupport implements CustomOptionsEditor {

	private static final String USE_ENCODED_ANON_NS_LABEL = "Use Encoded Anonymous Namespace";
	private static final String APPLY_UDT_ARG_TAGS_LABEL = "Apply UDT Argument Type Tags";

	private static final String[] NAMES = { USE_ENCODED_ANON_NS_LABEL, APPLY_UDT_ARG_TAGS_LABEL };

	// help tooltips
	private static final String USE_ENCODED_ANON_NS_TOOLTIP =
		HTMLUtilities.toWrappedHTML(
			"Instead of a variation of <B>Anonymous Namespace</B>, uses the encoded numeric " +
				"identifier to output an <B>_anon_ABCD1234</B> name form.",
			75);

	private static final String APPLY_UDT_ARG_TAGS_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Applies a user-defined type's (UDT) class/enum/struct/union tag when the UDT is a " +
			"template or function argument.",
		75);

	private static final String[] DESCRIPTIONS = { USE_ENCODED_ANON_NS_TOOLTIP,
		APPLY_UDT_ARG_TAGS_TOOLTIP };

	private MsdOutputOption msOutputOption;

	private Component editorComponent;

	private JCheckBox useEncodedAnonNsCb;
	private JCheckBox useUdtTagsCb;
	private JLabel useEncodedAnonNsLabel;
	private JLabel useUdtTagsLabel;

	public MsdOutputOptionsEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new PairLayout(0, 6));

		useEncodedAnonNsCb = new GCheckBox();
		useEncodedAnonNsCb.setSelected(true);
		useEncodedAnonNsCb.setToolTipText(USE_ENCODED_ANON_NS_TOOLTIP);
		useEncodedAnonNsLabel = new JLabel(USE_ENCODED_ANON_NS_LABEL, SwingConstants.RIGHT);
		useEncodedAnonNsLabel.setLabelFor(useEncodedAnonNsCb);
		useEncodedAnonNsLabel.setToolTipText(USE_ENCODED_ANON_NS_TOOLTIP);
		panel.add(useEncodedAnonNsLabel);
		panel.add(useEncodedAnonNsCb);

		useUdtTagsCb = new GCheckBox();
		useUdtTagsCb.setSelected(false);
		useUdtTagsCb.setToolTipText(APPLY_UDT_ARG_TAGS_TOOLTIP);
		useUdtTagsLabel = new JLabel(APPLY_UDT_ARG_TAGS_LABEL, SwingConstants.RIGHT);
		useUdtTagsLabel.setLabelFor(useUdtTagsCb);
		useUdtTagsLabel.setToolTipText(APPLY_UDT_ARG_TAGS_TOOLTIP);
		panel.add(useUdtTagsLabel);
		panel.add(useUdtTagsCb);

		useEncodedAnonNsCb.addItemListener(e -> firePropertyChange());
		useUdtTagsCb.addItemListener(e -> firePropertyChange());

		Border emptyBorder = BorderFactory.createEmptyBorder(0, 0, 0, 0);
		TitledBorder titledNoLineBorder = BorderFactory.createTitledBorder(
			emptyBorder,          // The invisible base border
			"Output Options",     // The title text
			TitledBorder.LEADING, // Title justification (e.g., LEADING, CENTER, TRAILING)
			TitledBorder.TOP,     // Title position (e.g., TOP, BOTTOM)
			null,				  // Optional: Font
			null          		  // Optional: Title color
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
		if (!(value instanceof MsdOutputOption option)) {
			return;
		}
		msOutputOption = option;
		setLocalValues(msOutputOption);
		firePropertyChange();
	}

	private void setLocalValues(MsdOutputOption outputOptions) {
		boolean useEncoded = outputOptions.getUseEncodedAnonymousNamespace();
		if (useEncoded != useEncodedAnonNsCb.isSelected()) {
			useEncodedAnonNsCb.setSelected(useEncoded);
		}
		boolean applyComplexTag = outputOptions.getApplyUdtArgumentTypeTag();
		if (applyComplexTag != useUdtTagsCb.isSelected()) {
			useUdtTagsCb.setSelected(applyComplexTag);
		}
	}

	private MsdOutputOption cloneNamespaceValues() {
		MsdOutputOption newOption =
			new MsdOutputOption(useEncodedAnonNsCb.isSelected(), useUdtTagsCb.isSelected());
		return newOption;
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
			Dimension size = getPairDimension(useEncodedAnonNsLabel, useEncodedAnonNsCb);
			maxWidth = Math.max(size.width, maxWidth);
			maxHeight = Math.max(size.height, maxHeight);

			size = getPairDimension(useUdtTagsLabel, useUdtTagsCb);
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
			useEncodedAnonNsLabel.setPreferredSize(size);
			useUdtTagsLabel.setPreferredSize(size);
		}
	}
}
