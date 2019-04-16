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
package docking.widgets.filter;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import docking.DisabledComponentLayerFactory;
import docking.widgets.InlineComponentTitledPanel;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.util.HelpLocation;
import ghidra.util.layout.*;

/**
 * Dialog that allows the user to select options related to table filtering. It consists
 * of the following sections:
 * 
 * 		Filter Strategy: 		Allows the user to define how filter terms are applied to strings. 
 * 		Filter Options:			Various generic filter settings.
 * 		Multi-Term Filtering:	Options defining how to interpret filter text when multiple terms
 * 								are entered.
 */
public class FilterOptionsEditorDialog extends DialogComponentProvider {

	private FilterOptions initialFilterOptions;
	private FilterOptions resultFilterOptions;

	private FilterStrategyPanel filterStrategyPanel;
	private BooleanPanel booleanPanel;
	private InvertPanel invertPanel;
	private MultiTermPanel multiTermPanel;
	private JLayer<?> multiTermDisabledPanel;

	public FilterOptionsEditorDialog(FilterOptions filterOptions) {
		super("Text Filter Options");
		this.initialFilterOptions = filterOptions;

		addWorkPanel(createMainPanel());

		filterStrategyPanel.setFilterStrategy(filterOptions.getTextFilterStrategy());
		multiTermPanel.setEvalMode(filterOptions.getMultitermEvaluationMode());
		multiTermPanel.setDelimiter(filterOptions.getDelimitingCharacter());

		updatedEnablementForNonRegularExpressionOptions(
			filterStrategyPanel.getFilterStrategy() != TextFilterStrategy.REGULAR_EXPRESSION);

		multiTermPanel.setMultitermEnabled(filterOptions.isMultiterm());

		addOKButton();
		addCancelButton();
		setRememberSize(false);
		setHelpLocation(new HelpLocation("Trees", "Filter_Options"));
	}

	@Override
	protected void okCallback() {

		resultFilterOptions = new FilterOptions(filterStrategyPanel.getFilterStrategy(),
			booleanPanel.isGlobbing(), booleanPanel.isCaseSensitive(), invertPanel.isInverted(),
			multiTermPanel.isMultitermEnabled(), multiTermPanel.getDelimiter(),
			multiTermPanel.getEvalMode());

		close();
	}

	public FilterOptions getResultFilterOptions() {
		return resultFilterOptions;
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel(new VerticalLayout(3));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

		filterStrategyPanel = new FilterStrategyPanel();
		panel.add(filterStrategyPanel);

		booleanPanel = new BooleanPanel();
		panel.add(booleanPanel);

		invertPanel = new InvertPanel();
		panel.add(invertPanel);

		multiTermPanel = new MultiTermPanel();
		panel.add(multiTermPanel);

		multiTermDisabledPanel = DisabledComponentLayerFactory.getDisabledLayer(multiTermPanel);
		panel.add(multiTermDisabledPanel);

		return panel;
	}

	protected void updatedEnablementForNonRegularExpressionOptions(boolean b) {
		booleanPanel.setCaseSensitiveCBEnabled(b);
		booleanPanel.setGlobbingCBEnabled(b);

		multiTermDisabledPanel.setEnabled(b);
	}

	/**
	 * Contains widgets for specifying how to interpret filter terms. Possible selections are:
	 * 		- Contains
	 * 		- Starts With
	 * 		- Matches Exactly
	 * 		- Regular Expression
	 * 
	 */
	class FilterStrategyPanel extends JPanel {

		private TextFilterStrategy filterStrategy;

		public FilterStrategyPanel() {
			createPanel();
		}

		public void setFilterStrategy(TextFilterStrategy filterStrategy) {
			this.filterStrategy = filterStrategy;
		}

		public TextFilterStrategy getFilterStrategy() {
			return this.filterStrategy;
		}

		private void createPanel() {
			setLayout(new PairLayout(2, 2));
			setBorder(BorderFactory.createTitledBorder("Text Filter Strategy"));
			ButtonGroup buttonGroup = new ButtonGroup();
			GRadioButton startsWithButton = new GRadioButton("Starts With");
			GRadioButton containsButton = new GRadioButton("Contains");
			GRadioButton matchesExactlyButton = new GRadioButton("Matches Exactly");
			GRadioButton regularExpressionButton = new GRadioButton("Regular Expression");

			startsWithButton.setToolTipText(
				"The filter will match all entries that start with the entered filter text.");
			containsButton.setToolTipText(
				"The filter will match all entries that contain the entered filter text.");
			matchesExactlyButton.setToolTipText(
				"The filter will match all entries that exactly match the entered filter text.");
			regularExpressionButton.setToolTipText(
				"The filter will match all entries that match a regular expression generated from the filter text.");

			buttonGroup.add(startsWithButton);
			buttonGroup.add(containsButton);
			buttonGroup.add(matchesExactlyButton);
			buttonGroup.add(regularExpressionButton);

			startsWithButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent ev) {
					filterStrategy = TextFilterStrategy.STARTS_WITH;
					updatedEnablementForNonRegularExpressionOptions(true);
				}
			});

			containsButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent ev) {
					filterStrategy = TextFilterStrategy.CONTAINS;
					updatedEnablementForNonRegularExpressionOptions(true);
				}
			});
			matchesExactlyButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent ev) {
					filterStrategy = TextFilterStrategy.MATCHES_EXACTLY;
					updatedEnablementForNonRegularExpressionOptions(true);
				}
			});
			regularExpressionButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent ev) {
					filterStrategy = TextFilterStrategy.REGULAR_EXPRESSION;
					updatedEnablementForNonRegularExpressionOptions(false);
				}
			});

			switch (initialFilterOptions.getTextFilterStrategy()) {
				case STARTS_WITH:
					startsWithButton.setSelected(true);
					break;
				case MATCHES_EXACTLY:
					matchesExactlyButton.setSelected(true);
					break;
				case REGULAR_EXPRESSION:
					regularExpressionButton.setSelected(true);
					break;
				case CONTAINS:
				default:
					containsButton.setSelected(true);
					break;
			}

			add(containsButton);
			add(new GIconLabel(FilterOptions.getIcon(TextFilterStrategy.CONTAINS)));
			add(startsWithButton);
			add(new GIconLabel(FilterOptions.getIcon(TextFilterStrategy.STARTS_WITH)));
			add(matchesExactlyButton);
			add(new GIconLabel(FilterOptions.getIcon(TextFilterStrategy.MATCHES_EXACTLY)));
			add(regularExpressionButton);
			add(new GIconLabel(FilterOptions.getIcon(TextFilterStrategy.REGULAR_EXPRESSION)));
		}
	}

	/**
	 * Contains widgets for controlling various filtering attributes. The following options are
	 * provided: 
	 * 		- Case Sensitive
	 * 		- Allow Globbing
	 */
	class BooleanPanel extends JPanel {

		private JCheckBox caseSensitiveCheckbox;
		private JCheckBox globbingCheckbox;

		public BooleanPanel() {
			createPanel();
		}

		public boolean isCaseSensitive() {
			return caseSensitiveCheckbox.isSelected();
		}

		public boolean isGlobbing() {
			return globbingCheckbox.isSelected();
		}

		public void setCaseSensitive(boolean val) {
			caseSensitiveCheckbox.setSelected(val);
		}

		public void setGlobbing(boolean val) {
			globbingCheckbox.setSelected(val);
		}

		public void setCaseSensitiveCBEnabled(boolean enabled) {
			caseSensitiveCheckbox.setEnabled(enabled);
		}

		public void setGlobbingCBEnabled(boolean enabled) {
			globbingCheckbox.setEnabled(enabled);
		}

		private void createPanel() {
			this.setLayout(new HorizontalLayout(6));
			setBorder(BorderFactory.createEmptyBorder(10, 4, 0, 4));

			caseSensitiveCheckbox = new GCheckBox("Case Sensitive");
			caseSensitiveCheckbox.setToolTipText(
				"Toggles whether the case of the filter text matters in the match.  NOTE: does not apply to regular expressons.");
			if (initialFilterOptions.isCaseSensitive()) {
				caseSensitiveCheckbox.setSelected(true);
			}

			globbingCheckbox = new GCheckBox("Allow Globbing");
			globbingCheckbox.setToolTipText(
				"Toggles whether globbing chars (?*) are literal or wildcards");
			if (initialFilterOptions.isGlobbingAllowed()) {
				globbingCheckbox.setSelected(true);
			}
			if (initialFilterOptions.getTextFilterStrategy() == TextFilterStrategy.REGULAR_EXPRESSION) {
				caseSensitiveCheckbox.setEnabled(false);
				globbingCheckbox.setEnabled(false);
			}

			add(caseSensitiveCheckbox);
			add(globbingCheckbox);
		}
	}

	/**
	 * Contains widgets for setting whether the filter should be inverted.
	 */
	class InvertPanel extends JPanel {

		private JCheckBox invertCheckbox;

		public InvertPanel() {
			createPanel();
		}

		public boolean isInverted() {
			return invertCheckbox.isSelected();
		}

		private void createPanel() {
			this.setLayout(new HorizontalLayout(6));
			setBorder(BorderFactory.createEmptyBorder(10, 4, 10, 4));

			invertCheckbox = new GCheckBox("Invert Filter");
			invertCheckbox.setToolTipText("<html>" +
				"Inverts the match.  For example, <i>contains</i> becomes <i>does not contain</i>.");
			if (initialFilterOptions.isInverted()) {
				invertCheckbox.setSelected(true);
			}

			add(invertCheckbox);
		}
	}

	/**
	 * Contains widgets for configuring multi-term filtering. This has two main
	 * sections for setting the delimiter and setting the mode. The former allows the user to 
	 * select a delimiter from a predefined set of characters. The latter allows them to 
	 * define how multiple terms are logically applied; eg: 'AND' means that all filter terms
	 * must be matched, 'OR' means any single term must match.
	 */
	class MultiTermPanel extends InlineComponentTitledPanel {

		private JLayer<?> optionsPaneDisableLayer;

		private JCheckBox enableCheckbox;
		private List<JRadioButton> modeButtons = new ArrayList<>();
		private JComboBox<String> delimiterCharacterCB;
		private MultitermEvaluationMode evalMode = MultitermEvaluationMode.AND;

		public MultiTermPanel() {

			super(new GCheckBox("Enable Multi-Term Filtering", true),
				BorderFactory.createEtchedBorder());

			enableCheckbox = (JCheckBox) getTitleComponent();
			enableCheckbox.addActionListener(e -> setOptionsEnabled(enableCheckbox.isSelected()));

			createPanel();
		}

		public MultitermEvaluationMode getEvalMode() {
			return evalMode;
		}

		/**
		 * Sets the eval mode to what is given. This is done by activating the
		 * appropriate radio button associated with that mode.
		 * 
		 * @param evalMode
		 */
		public void setEvalMode(MultitermEvaluationMode evalMode) {
			this.evalMode = evalMode;

			// Find the radio button that matches the mode type passed
			// in and set it to be selected.
			for (JRadioButton rb : modeButtons) {
				if (rb.getText().equals(evalMode.name())) {
					rb.setSelected(true);
				}
			}
		}

		public void setMultitermEnabled(boolean enabled) {
			enableCheckbox.setSelected(enabled);
			setOptionsEnabled(enabled);
		}

		public void setOptionsEnabled(boolean enabled) {
			optionsPaneDisableLayer.setEnabled(enabled);
		}

		public boolean isMultitermEnabled() {
			return enableCheckbox.isSelected();
		}

		public char getDelimiter() {
			return delimiterCharacterCB.getSelectedItem().toString().charAt(0);
		}

		/**
		 * Sets the character to use for the delimiter. If the character is not found in 
		 * the set of acceptable delimiters, the delimiter is not changed.
		 * 
		 * @param delimiter the character to use as the delimiter
		 */
		public void setDelimiter(char delimiter) {
			int count = delimiterCharacterCB.getItemCount();
			for (int i = 0; i < count; i++) {
				if (delimiterCharacterCB.getItemAt(i).equals(String.valueOf(delimiter))) {
					delimiterCharacterCB.setSelectedIndex(i);
				}
			}
		}

		/**
		 * Creates the main panel for this dialog.
		 */
		private void createPanel() {

			getContentPane().setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));

			JPanel outerPanel = new JPanel();
			outerPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));

			JPanel optionsPanel = new JPanel();
			optionsPanel.setLayout(new PairLayout());

			// Delimiter Row
			JLabel delimiterCharacterFieldName = new GLabel("Delimiter:");
			delimiterCharacterFieldName.setToolTipText(
				"Set the character used to separate filter terms.");

			delimiterCharacterCB = new GComboBox<>(FilterOptions.VALID_MULTITERM_DELIMITERS_ARRAY);
			delimiterCharacterCB.setRenderer(new DelimiterListCellRenderer());

			JPanel fixedSizePanel = new JPanel();
			fixedSizePanel.setLayout(new FlowLayout(FlowLayout.LEFT));
			fixedSizePanel.add(delimiterCharacterCB);

			optionsPanel.add(delimiterCharacterFieldName);
			optionsPanel.add(fixedSizePanel);

			// Mode Row
			JLabel label = new GLabel("Evaluation Mode:");

			JPanel buttonGroupPanel = new JPanel();
			buttonGroupPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
			ButtonGroup modeBtnGroup = new ButtonGroup();
			MultitermEvaluationMode[] modes = MultitermEvaluationMode.values();
			for (MultitermEvaluationMode mode : modes) {
				GRadioButton modeRB = new GRadioButton(mode.name());
				modeRB.setToolTipText(mode.getDescription());
				modeRB.addActionListener(e -> {
					evalMode = MultitermEvaluationMode.valueOf(mode.name());
				});
				modeButtons.add(modeRB);
				modeBtnGroup.add(modeRB);
				buttonGroupPanel.add(modeRB);
			}

			optionsPanel.add(label);
			optionsPanel.add(buttonGroupPanel);

			optionsPanel.setBorder(new EmptyBorder(0, 22, 0, 0));

			outerPanel.add(optionsPanel);
			add(outerPanel);

			optionsPaneDisableLayer = DisabledComponentLayerFactory.getDisabledLayer(outerPanel);
			add(optionsPaneDisableLayer);
		}

		private class DelimiterListCellRenderer extends GListCellRenderer<String> {

			public DelimiterListCellRenderer() {
				setHTMLRenderingEnabled(true);
			}

			@Override
			protected String getItemText(String value) {

				char char0 = value.length() > 0 ? value.charAt(0) : ' ';
				String delimiterName =
					FilterOptions.DELIMITER_NAME_MAP.getOrDefault(char0, "<i>Unrecognized</i>");
				return String.format("<html><font face=monospace>%s</font> &nbsp;&nbsp; <i>%s</i>",
					char0 == ' ' ? "&nbsp;" : char0, delimiterName);
			}
		}
	}

}
