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
package ghidra.feature.vt.gui.provider.matchtable;

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DockingWindowManager;
import docking.help.HelpService;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.GhidraOptions;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.*;

/**
 * The ApplyMarkupPropertyEditor provides a custom GUI layout for the options that are used when 
 * applying version tracking markup.
 */
public class ApplyMarkupPropertyEditor implements OptionsEditor {

	// help tooltips
	private static final String DATA_MATCH_DATA_TYPE_TOOLTIP =
		"<HTML>The apply action for the <b>data type on a data match</b> when performing bulk apply operations</HTML>";
	private static final String LABELS_TOOLTIP =
		"<HTML>The apply action for <b>labels</b> when performing bulk apply operations</HTML>";
	private static final String FUNCTION_NAME_TOOLTIP =
		"<HTML>The apply action for <b>function name</b> when performing bulk apply operations</HTML>";
	private static final String FUNCTION_SIGNATURE_TOOLTIP =
		"<HTML>The apply action for the <b>function signature</b> " +
			"when performing bulk apply operations</HTML>";
	private static final String PLATE_COMMENT_TOOLTIP =
		"<HTML>The apply action for <b>plate comments</b> when performing bulk apply operations</HTML>";
	private static final String PRE_COMMENT_TOOLTIP =
		"<HTML>The apply action for <b>pre comments</b> when performing bulk apply operations</HTML>";
	private static final String END_OF_LINE_COMMENT_TOOLTIP =
		"<HTML>The apply action for <b>end of line comments</b> when performing bulk apply operations</HTML>";
	private static final String REPEATABLE_COMMENT_TOOLTIP =
		"<HTML>The apply action for <b>repeatable comments</b> when performing bulk apply operations</HTML>";
	private static final String POST_COMMENT_TOOLTIP =
		"<HTML>The apply action for <b>post comments</b> when performing bulk apply operations</HTML>";
	private static final String FUNCTION_RETURN_TYPE_TOOLTIP =
		"<HTML>The apply action for <b>function return type</b> when the function signature is applied</HTML>";
	private static final String INLINE_TOOLTIP =
		"<HTML>The apply action to use for the <b>function inline flag</b> " +
			"when applying the function signature</HTML>";
	private static final String NO_RETURN_TOOLTIP =
		"<HTML>The apply action to use for the <b>function no return flag</b> " +
			"when applying the function signature</HTML>";
	private static final String CALLING_CONVENTION_TOOLTIP =
		"<HTML>The apply action to use for the <b>function calling convention</b> " +
			"when applying the function signature</HTML>";
	private static final String CALL_FIXUP_TOOLTIP =
		"<HTML>The apply action for <b>whether or not to apply call fixup</b> " +
			"when applying the function signature</HTML>";
	private static final String VAR_ARGS_TOOLTIP =
		"<HTML>The apply action to use for the <b>var args flag</b> " +
			"when applying the function signature</HTML>";
	private static final String PARAMETER_DATA_TYPES_TOOLTIP =
		"<HTML>The apply action for <b>function parameter data types</b> when applying the function signature</HTML>";
	private static final String PARAMETER_NAMES_TOOLTIP =
		"<HTML>The apply action for <b>function parameter names</b> when applying the function signature</HTML>";
	private static final String PARAMETER_NAME_PRIORITY_TOOTIP =
		"<HTML>Choose whether a parameter name with a User source type or Import source type is highest " +
			"priority when determining whether to replace the name or not when using the priority.</HTML>";
	private static final String HIGHEST_NAME_PRIORITY_TOOLTIP =
		"<HTML>The apply action for <b>which source type is the highest priority</b> " +
			"when applying parameter names using a priority replace</HTML>";
	private static final String USER_PRIORITY_TOOLTIP =
		"<HTML>Parameter Name Source Type Priority <br>from highest to lowest:<br>" +
			"<blockquote>User Defined<br>Imported<br>Analysis<br>default (i.e. param_...)</blockquote></HTML>";
	private static final String IMPORT_PRIORITY_TOOLTIP =
		"<HTML>Parameter Name Source Type Priority <br>from highest to lowest:<br>" +
			"<blockquote>Imported<br>User Defined<br>Analysis<br>default (i.e. param_...)</blockquote></HTML>";
	private static final String PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY_TOOLTIP =
		"<HTML>When function signature parameter names are being replaced based on source type priority, " +
			"replace the destination name with the source name if their source types are the same.</HTML>";
	private static final String PARAMETER_COMMENTS_TOOLTIP =
		"<HTML>The apply action for <b>parameter comments</b> when applying the function signature</HTML>";
	private static final String IGNORE_EXCLUDED_TOOLTIP =
		"<HTML>Markup items whose \"apply option\" is set to <b>Do Not Apply</b> should be" +
			" changed to a status of <b>Ignored</b> by applying a match.</HTML>";
	private static final String IGNORE_INCOMPLETE_TOOLTIP =
		"<HTML>Markup items that are <b>incomplete</b> (for example, no destination address is specified) " +
			"should be changed to a status of <b>Ignored</b> by applying a match.</HTML>";

	private JComponent editorComponent;

	private JLabel dataMatchDataTypeLabel;
	private JLabel functionNameLabel;
	private JLabel functionSignatureLabel;
	private JLabel returnTypeLabel;
	private JLabel inlineLabel;
	private JLabel noReturnLabel;
	private JLabel callingConventionLabel;
	private JLabel callFixupLabel;
	private JLabel parameterDataTypesLabel;
	private JLabel parameterNamesLabel;
	private JLabel parameterCommentsLabel;
	private JLabel varArgsLabel;
	private JLabel labelsLabel;
	private JLabel plateCommentsLabel;
	private JLabel preCommentsLabel;
	private JLabel endOfLineCommentsLabel;
	private JLabel repeatableCommentsLabel;
	private JLabel postCommentsLabel;

	private JComboBox<Enum<?>> dataMatchDataTypeComboBox;
	private JComboBox<Enum<?>> functionNameComboBox;
	private JComboBox<Enum<?>> functionSignatureComboBox;
	private JComboBox<Enum<?>> returnTypeComboBox;
	private JComboBox<Enum<?>> callingConventionComboBox;
	private JComboBox<Enum<?>> inlineComboBox;
	private JComboBox<Enum<?>> noReturnComboBox;
	private JComboBox<Enum<?>> callFixupComboBox;
	private JComboBox<Enum<?>> parameterDataTypesComboBox;
	private JComboBox<Enum<?>> parameterNamesComboBox;
	private JComboBox<Enum<?>> parameterCommentsComboBox;
	private JRadioButton userHighestPriorityRB;
	private JRadioButton importHighestPriorityRB;
	private ButtonGroup priorityButtonGroup;
	private JCheckBox replaceIfSameSourceCheckBox;
	private JComboBox<Enum<?>> varArgsComboBox;
	private JComboBox<Enum<?>> labelsComboBox;
	private JComboBox<Enum<?>> plateCommentsComboBox;
	private JComboBox<Enum<?>> preCommentsComboBox;
	private JComboBox<Enum<?>> endOfLineCommentsComboBox;
	private JComboBox<Enum<?>> postCommentsComboBox;
	private JComboBox<Enum<?>> repeatableCommentsComboBox;
	private JCheckBox ignoreExcludedCheckBox;
	private JCheckBox ignoreIncompleteCheckBox;

	private ActionListener defaultActionListener;

	private ToolOptions originalOptions;
	private PropertyChangeListener listener;
	private boolean unappliedChanges = false;
	private VTController controller;

	public ApplyMarkupPropertyEditor(VTController controller) {
		this.controller = controller;
		this.originalOptions = controller.getOptions();
		editorComponent = buildEditor();
		setEditorValues(originalOptions);
		setupHelp();
	}

	@Override
	public void dispose() {
		// stub
	}

	private void setupHelp() {
		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation applyMatchOptionsHelpLocation =
			new HelpLocation(VTPlugin.HELP_TOPIC_NAME, "Match_Apply_Options");
		helpService.registerHelp(editorComponent, applyMatchOptionsHelpLocation);
	}

	private JComponent buildEditor() {

		JPanel panel = new JPanel();
		panel.setLayout(new VerticalLayout(5));

		JPanel pair1 = new JPanel(new VariableHeightPairLayout(3, 5));
		pair1.add(createNonCommentMarkupSubPanel());
		pair1.add(createCommentsSubPanel());

		JPanel pair2 = new JPanel(new VariableHeightPairLayout(3, 5));
		pair2.add(createFunctionSignatureSubPanel());
		pair2.add(createParametersSubPanel());

		panel.add(pair1);
		panel.add(createSeparator());
		panel.add(pair2);
		panel.add(createSeparator());
		panel.add(createIgnoreCheckBoxPanel());

		// TODO More needs to be done with the layout here.
		panel.setBorder(BorderFactory.createTitledBorder("Apply Markup Options"));
		JScrollPane scrollPane = new JScrollPane(panel);

		return scrollPane;
	}

	private Component createSeparator() {
		JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
		JPanel borderPanel = new JPanel(new BorderLayout());
		borderPanel.setBorder(BorderFactory.createEmptyBorder(20, 50, 20, 50));
		borderPanel.add(separator);
		return borderPanel;
	}

	private Component createIgnoreCheckBoxPanel() {
		createIgnoreCheckBoxes();
		setupIgnoreMarkupItemsListeners();

		JPanel panel = new JPanel();
		panel.add(ignoreExcludedCheckBox);
		panel.add(ignoreIncompleteCheckBox);
		return panel;
	}

	private void createIgnoreCheckBoxes() {
		ignoreIncompleteCheckBox = new GCheckBox("Set Incomplete Markup Items To Ignored");
		ignoreIncompleteCheckBox.setToolTipText(IGNORE_INCOMPLETE_TOOLTIP);

		ignoreExcludedCheckBox = new GCheckBox("Set Excluded Markup Items To Ignored");
		ignoreExcludedCheckBox.setToolTipText(IGNORE_EXCLUDED_TOOLTIP);
	}

	private void setupIgnoreMarkupItemsListeners() {
		ignoreExcludedCheckBox.addActionListener(defaultActionListener);
		ignoreIncompleteCheckBox.addActionListener(defaultActionListener);
	}

	private JPanel createFunctionSignatureSubPanel() {

		createFunctionSignatureDetailLabels();
		createFunctionSignatureDetailChoices();
		setupFunctionSignatureDetailChoiceListeners();

		JPanel outerPanel = new JPanel();
		outerPanel.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createTitledBorder(null, "Function Signature Details",
			TitledBorder.LEFT, TitledBorder.DEFAULT_POSITION));
		panel.setLayout(new PairLayout(3, 5));

		panel.add(returnTypeLabel);
		panel.add(returnTypeComboBox);

		panel.add(inlineLabel);
		panel.add(inlineComboBox);

		panel.add(noReturnLabel);
		panel.add(noReturnComboBox);

		panel.add(callingConventionLabel);
		panel.add(callingConventionComboBox);

		panel.add(callFixupLabel);
		panel.add(callFixupComboBox);

		panel.add(varArgsLabel);
		panel.add(varArgsComboBox);

		outerPanel.add(panel);
		return outerPanel;
	}

	private void createFunctionSignatureDetailLabels() {

		returnTypeLabel = new GDLabel("Return Type", SwingConstants.RIGHT);
		returnTypeLabel.setToolTipText(FUNCTION_RETURN_TYPE_TOOLTIP);

		inlineLabel = new GDLabel("Inline", SwingConstants.RIGHT);
		inlineLabel.setToolTipText(INLINE_TOOLTIP);

		noReturnLabel = new GDLabel("No Return", SwingConstants.RIGHT);
		noReturnLabel.setToolTipText(NO_RETURN_TOOLTIP);

		callingConventionLabel = new GDLabel("Calling Convention", SwingConstants.RIGHT);
		callingConventionLabel.setToolTipText(CALLING_CONVENTION_TOOLTIP);

		callFixupLabel = new GDLabel("Call Fixup", SwingConstants.RIGHT);
		callFixupLabel.setToolTipText(CALL_FIXUP_TOOLTIP);

		varArgsLabel = new GDLabel("Var Args", SwingConstants.RIGHT);
		varArgsLabel.setToolTipText(VAR_ARGS_TOOLTIP);

	}

	private void createFunctionSignatureDetailChoices() {

		returnTypeComboBox = createComboBox(VTOptionDefines.FUNCTION_RETURN_TYPE,
			DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
		returnTypeComboBox.setToolTipText(FUNCTION_RETURN_TYPE_TOOLTIP);

		inlineComboBox = createComboBox(VTOptionDefines.INLINE, DEFAULT_OPTION_FOR_INLINE);
		inlineComboBox.setToolTipText(INLINE_TOOLTIP);

		noReturnComboBox = createComboBox(VTOptionDefines.NO_RETURN, DEFAULT_OPTION_FOR_NO_RETURN);
		noReturnComboBox.setToolTipText(NO_RETURN_TOOLTIP);

		callingConventionComboBox = createComboBox(VTOptionDefines.CALLING_CONVENTION,
			CallingConventionChoices.SAME_LANGUAGE);
		callingConventionComboBox.setToolTipText(CALLING_CONVENTION_TOOLTIP);

		callFixupComboBox =
			createComboBox(VTOptionDefines.CALL_FIXUP, DEFAULT_OPTION_FOR_CALL_FIXUP);
		callFixupComboBox.setToolTipText(CALL_FIXUP_TOOLTIP);

		varArgsComboBox = createComboBox(VTOptionDefines.VAR_ARGS, DEFAULT_OPTION_FOR_VAR_ARGS);
		varArgsComboBox.setToolTipText(VAR_ARGS_TOOLTIP);
	}

	private void setupFunctionSignatureDetailChoiceListeners() {
		returnTypeComboBox.addActionListener(defaultActionListener);
		inlineComboBox.addActionListener(defaultActionListener);
		noReturnComboBox.addActionListener(defaultActionListener);
		callingConventionComboBox.addActionListener(defaultActionListener);
		callFixupComboBox.addActionListener(defaultActionListener);
		varArgsComboBox.addActionListener(defaultActionListener);
	}

	private JPanel createParametersSubPanel() {
		createParameterLabels();
		createParameterChoices();
		setupParameterChoiceListeners();

		JPanel outerPanel = new JPanel();
		outerPanel.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createTitledBorder(null, "Function Parameter Details",
			TitledBorder.LEFT, TitledBorder.DEFAULT_POSITION));
		panel.setLayout(new VariableHeightPairLayout(3, 5));

		panel.add(parameterDataTypesLabel);
		panel.add(parameterDataTypesComboBox);

		panel.add(parameterNamesLabel);
		panel.add(parameterNamesComboBox);

		panel.add(new GLabel(" "));
		panel.add(createPrioritySubPanel());

		panel.add(parameterCommentsLabel);
		panel.add(parameterCommentsComboBox);

		outerPanel.add(panel);
		return outerPanel;
	}

	private void createParameterLabels() {
		parameterDataTypesLabel = new GDLabel("Parameter Data Types", SwingConstants.RIGHT);
		parameterDataTypesLabel.setToolTipText(PARAMETER_DATA_TYPES_TOOLTIP);

		parameterNamesLabel = new GDLabel("Parameter Names", SwingConstants.RIGHT);
		parameterNamesLabel.setToolTipText(PARAMETER_NAMES_TOOLTIP);

		parameterCommentsLabel = new GDLabel("Parameter Comments", SwingConstants.RIGHT);
		parameterCommentsLabel.setToolTipText(PARAMETER_COMMENTS_TOOLTIP);
	}

	private void createParameterChoices() {

		parameterDataTypesComboBox = createComboBox(VTOptionDefines.PARAMETER_DATA_TYPES,
			DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);
		parameterDataTypesComboBox.setToolTipText(PARAMETER_DATA_TYPES_TOOLTIP);

		parameterNamesComboBox =
			createComboBox(VTOptionDefines.PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES);
		parameterNamesComboBox.setToolTipText(PARAMETER_NAMES_TOOLTIP);

		parameterCommentsComboBox = createComboBox(VTOptionDefines.PARAMETER_COMMENTS,
			DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);
		parameterCommentsComboBox.setToolTipText(PARAMETER_COMMENTS_TOOLTIP);

		userHighestPriorityRB = createRadioButton("User ");
		userHighestPriorityRB.setToolTipText(USER_PRIORITY_TOOLTIP);

		importHighestPriorityRB = createRadioButton("Import");
		importHighestPriorityRB.setToolTipText(IMPORT_PRIORITY_TOOLTIP);

		priorityButtonGroup = new ButtonGroup();
		priorityButtonGroup.add(userHighestPriorityRB);
		priorityButtonGroup.add(importHighestPriorityRB);

		replaceIfSameSourceCheckBox = createCheckBox("Also Replace If Same Source Type");
		replaceIfSameSourceCheckBox.setToolTipText(
			PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY_TOOLTIP);
	}

	private void setupParameterChoiceListeners() {
		parameterDataTypesComboBox.addActionListener(defaultActionListener);
		parameterNamesComboBox.addActionListener(defaultActionListener);
		userHighestPriorityRB.addActionListener(defaultActionListener);
		importHighestPriorityRB.addActionListener(defaultActionListener);
		replaceIfSameSourceCheckBox.addActionListener(defaultActionListener);
		parameterCommentsComboBox.addActionListener(defaultActionListener);
	}

	private JPanel createPrioritySubPanel() {
		JPanel outerPanel = new JPanel();
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createTitledBorder(null, "Parameter Name Priority",
			TitledBorder.LEFT, TitledBorder.DEFAULT_POSITION));
		panel.setLayout(new VerticalLayout(5));
		panel.setToolTipText(PARAMETER_NAME_PRIORITY_TOOTIP);

		Box buttonBox = new Box(BoxLayout.X_AXIS);
		JLabel highestPriorityLabel = new GDLabel(" Highest: ");
		highestPriorityLabel.setToolTipText(HIGHEST_NAME_PRIORITY_TOOLTIP);
		buttonBox.add(highestPriorityLabel);
		buttonBox.add(userHighestPriorityRB);
		buttonBox.add(importHighestPriorityRB);
		panel.add(buttonBox);
		panel.add(replaceIfSameSourceCheckBox);

		outerPanel.add(panel);
		return outerPanel;
	}

	private JPanel createNonCommentMarkupSubPanel() {

		createNonCommentMarkupLabels();
		createNonCommentMarkupChoices();
		setupNonCommentMarkupChoiceListeners();

		JPanel outerPanel = new JPanel();
		outerPanel.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		JPanel panel = new JPanel();
		panel.setLayout(new PairLayout(3, 5));

		panel.add(dataMatchDataTypeLabel);
		panel.add(dataMatchDataTypeComboBox);
		panel.add(labelsLabel);
		panel.add(labelsComboBox);
		panel.add(functionNameLabel);
		panel.add(functionNameComboBox);
		panel.add(functionSignatureLabel);
		panel.add(functionSignatureComboBox);

		outerPanel.add(panel);
		return outerPanel;
	}

	private void createNonCommentMarkupLabels() {
		dataMatchDataTypeLabel = new GDLabel("Data Match Data Type", SwingConstants.RIGHT);
		dataMatchDataTypeLabel.setToolTipText(DATA_MATCH_DATA_TYPE_TOOLTIP);

		labelsLabel = new GDLabel("Labels", SwingConstants.RIGHT);
		labelsLabel.setToolTipText(LABELS_TOOLTIP);

		functionNameLabel = new GDLabel("Function Name", SwingConstants.RIGHT);
		functionNameLabel.setToolTipText(FUNCTION_NAME_TOOLTIP);

		functionSignatureLabel = new GDLabel("Function Signature", SwingConstants.RIGHT);
		functionSignatureLabel.setToolTipText(FUNCTION_SIGNATURE_TOOLTIP);
	}

	private void createNonCommentMarkupChoices() {
		dataMatchDataTypeComboBox = createComboBox(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE);
		dataMatchDataTypeComboBox.setToolTipText(DATA_MATCH_DATA_TYPE_TOOLTIP);

		labelsComboBox = createComboBox(VTOptionDefines.LABELS, DEFAULT_OPTION_FOR_LABELS);
		labelsComboBox.setToolTipText(LABELS_TOOLTIP);

		functionNameComboBox =
			createComboBox(VTOptionDefines.FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		functionNameComboBox.setToolTipText(FUNCTION_NAME_TOOLTIP);

		functionSignatureComboBox = createComboBox(VTOptionDefines.FUNCTION_SIGNATURE,
			DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		functionSignatureComboBox.setToolTipText(FUNCTION_SIGNATURE_TOOLTIP);
	}

	private void setupNonCommentMarkupChoiceListeners() {
		dataMatchDataTypeComboBox.addActionListener(defaultActionListener);
		labelsComboBox.addActionListener(defaultActionListener);
		functionNameComboBox.addActionListener(defaultActionListener);
		functionSignatureComboBox.addActionListener(defaultActionListener);
	}

	private JPanel createCommentsSubPanel() {
		createCommentLabels();
		createCommentChoices();
		setupCommentChoiceListeners();

		JPanel outerPanel = new JPanel();
		outerPanel.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		JPanel panel = new JPanel();
		panel.setLayout(new PairLayout(3, 5));

		panel.add(plateCommentsLabel);
		panel.add(plateCommentsComboBox);

		panel.add(preCommentsLabel);
		panel.add(preCommentsComboBox);

		panel.add(endOfLineCommentsLabel);
		panel.add(endOfLineCommentsComboBox);

		panel.add(repeatableCommentsLabel);
		panel.add(repeatableCommentsComboBox);

		panel.add(postCommentsLabel);
		panel.add(postCommentsComboBox);

		outerPanel.add(panel);
		return outerPanel;
	}

	private void createCommentLabels() {
		plateCommentsLabel = new GDLabel("Plate Comments", SwingConstants.RIGHT);
		plateCommentsLabel.setToolTipText(PLATE_COMMENT_TOOLTIP);

		preCommentsLabel = new GDLabel("Pre-Comments", SwingConstants.RIGHT);
		preCommentsLabel.setToolTipText(PRE_COMMENT_TOOLTIP);

		endOfLineCommentsLabel = new GDLabel("End of Line Comments", SwingConstants.RIGHT);
		endOfLineCommentsLabel.setToolTipText(END_OF_LINE_COMMENT_TOOLTIP);

		repeatableCommentsLabel = new GDLabel("Repeatable Comments", SwingConstants.RIGHT);
		repeatableCommentsLabel.setToolTipText(REPEATABLE_COMMENT_TOOLTIP);

		postCommentsLabel = new GDLabel("Post Comments", SwingConstants.RIGHT);
		postCommentsLabel.setToolTipText(POST_COMMENT_TOOLTIP);
	}

	private void createCommentChoices() {
		plateCommentsComboBox =
			createComboBox(VTOptionDefines.PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS);
		plateCommentsComboBox.setToolTipText(PLATE_COMMENT_TOOLTIP);

		preCommentsComboBox =
			createComboBox(VTOptionDefines.PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS);
		preCommentsComboBox.setToolTipText(PRE_COMMENT_TOOLTIP);

		endOfLineCommentsComboBox =
			createComboBox(VTOptionDefines.END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS);
		endOfLineCommentsComboBox.setToolTipText(END_OF_LINE_COMMENT_TOOLTIP);

		repeatableCommentsComboBox = createComboBox(VTOptionDefines.REPEATABLE_COMMENT,
			DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS);
		repeatableCommentsComboBox.setToolTipText(REPEATABLE_COMMENT_TOOLTIP);

		postCommentsComboBox =
			createComboBox(VTOptionDefines.POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS);
		postCommentsComboBox.setToolTipText(POST_COMMENT_TOOLTIP);
	}

	private void setupCommentChoiceListeners() {
		plateCommentsComboBox.addActionListener(defaultActionListener);
		preCommentsComboBox.addActionListener(defaultActionListener);
		endOfLineCommentsComboBox.addActionListener(defaultActionListener);
		repeatableCommentsComboBox.addActionListener(defaultActionListener);
		postCommentsComboBox.addActionListener(defaultActionListener);
	}

	private void updateOptions(ToolOptions options) {
		updateNonCommentMarkupOptions(options);
		updateCommentOptions(options);
		updateFunctionSignatureOptions(options);
		updateParameterOptions(options);
		updateIgnoreMarkupOptions(options);
	}

	private void updateNonCommentMarkupOptions(ToolOptions options) {

		ReplaceDataChoices dataMatchDataTypeChoice =
			(ReplaceDataChoices) dataMatchDataTypeComboBox.getSelectedItem();
		options.setEnum(DATA_MATCH_DATA_TYPE, dataMatchDataTypeChoice);

		LabelChoices labelsChoice = (LabelChoices) labelsComboBox.getSelectedItem();
		options.setEnum(LABELS, labelsChoice);

		FunctionNameChoices functionNameChoice =
			(FunctionNameChoices) functionNameComboBox.getSelectedItem();
		options.setEnum(FUNCTION_NAME, functionNameChoice);

		FunctionSignatureChoices functionSignatureChoice =
			(FunctionSignatureChoices) functionSignatureComboBox.getSelectedItem();
		options.setEnum(FUNCTION_SIGNATURE, functionSignatureChoice);
	}

	private void updateCommentOptions(ToolOptions options) {

		CommentChoices plateCommentChoice =
			(CommentChoices) plateCommentsComboBox.getSelectedItem();
		options.setEnum(PLATE_COMMENT, plateCommentChoice);

		CommentChoices preCommentChoice = (CommentChoices) preCommentsComboBox.getSelectedItem();
		options.setEnum(PRE_COMMENT, preCommentChoice);

		CommentChoices endOfLineCommentChoice =
			(CommentChoices) endOfLineCommentsComboBox.getSelectedItem();
		options.setEnum(END_OF_LINE_COMMENT, endOfLineCommentChoice);

		CommentChoices repeatableCommentChoice =
			(CommentChoices) repeatableCommentsComboBox.getSelectedItem();
		options.setEnum(REPEATABLE_COMMENT, repeatableCommentChoice);

		CommentChoices postCommentChoice = (CommentChoices) postCommentsComboBox.getSelectedItem();
		options.setEnum(POST_COMMENT, postCommentChoice);
	}

	private void updateFunctionSignatureOptions(ToolOptions options) {

		ParameterDataTypeChoices returnTypeChoice =
			(ParameterDataTypeChoices) returnTypeComboBox.getSelectedItem();
		options.setEnum(FUNCTION_RETURN_TYPE, returnTypeChoice);

		ReplaceChoices inlineChoice = (ReplaceChoices) inlineComboBox.getSelectedItem();
		options.setEnum(INLINE, inlineChoice);

		ReplaceChoices noReturnChoice = (ReplaceChoices) noReturnComboBox.getSelectedItem();
		options.setEnum(NO_RETURN, noReturnChoice);

		CallingConventionChoices callingConventionChoice =
			(CallingConventionChoices) callingConventionComboBox.getSelectedItem();
		options.setEnum(CALLING_CONVENTION, callingConventionChoice);

		ReplaceChoices callFixupChoice = (ReplaceChoices) callFixupComboBox.getSelectedItem();
		options.setEnum(CALL_FIXUP, callFixupChoice);

		ReplaceChoices varArgsChoice = (ReplaceChoices) varArgsComboBox.getSelectedItem();
		options.setEnum(VAR_ARGS, varArgsChoice);
	}

	private void updateParameterOptions(ToolOptions options) {

		ParameterDataTypeChoices parameterDataTypeChoice =
			(ParameterDataTypeChoices) parameterDataTypesComboBox.getSelectedItem();
		options.setEnum(PARAMETER_DATA_TYPES, parameterDataTypeChoice);

		SourcePriorityChoices parameterNameChoice =
			(SourcePriorityChoices) parameterNamesComboBox.getSelectedItem();
		options.setEnum(PARAMETER_NAMES, parameterNameChoice);

		HighestSourcePriorityChoices highestPriorityChoice = (userHighestPriorityRB.isSelected())
				? HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST
				: HighestSourcePriorityChoices.IMPORT_PRIORITY_HIGHEST;
		options.setEnum(HIGHEST_NAME_PRIORITY, highestPriorityChoice);

		boolean replaceIfSameSource = replaceIfSameSourceCheckBox.isSelected();
		options.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, replaceIfSameSource);

		CommentChoices parameterCommentChoice =
			(CommentChoices) parameterCommentsComboBox.getSelectedItem();
		options.setEnum(PARAMETER_COMMENTS, parameterCommentChoice);
	}

	private void updateIgnoreMarkupOptions(Options options) {

		boolean ignoreExcludedMarkup = ignoreExcludedCheckBox.isSelected();
		options.setBoolean(IGNORE_EXCLUDED_MARKUP_ITEMS, ignoreExcludedMarkup);

		boolean ignoreIncompleteMarkup = ignoreIncompleteCheckBox.isSelected();
		options.setBoolean(IGNORE_INCOMPLETE_MARKUP_ITEMS, ignoreIncompleteMarkup);
	}

	private void setEditorValues(ToolOptions options) {
		setEditorNonCommentMarkupValues(options);
		setEditorCommentValues(options);
		setEditorFunctionSignatureValues(options);
		setEditorParameterValues(options);
		setEditorIgnoreMarkupValues(options);
	}

	private void setEditorNonCommentMarkupValues(ToolOptions options) {

		ReplaceDataChoices dataMatchDataTypeChoice =
			options.getEnum(DATA_MATCH_DATA_TYPE, DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE);
		if (dataMatchDataTypeChoice != dataMatchDataTypeComboBox.getSelectedItem()) {
			dataMatchDataTypeComboBox.setSelectedItem(dataMatchDataTypeChoice);
		}

		LabelChoices labelsChoice = options.getEnum(LABELS, DEFAULT_OPTION_FOR_LABELS);
		if (labelsChoice != labelsComboBox.getSelectedItem()) {
			labelsComboBox.setSelectedItem(labelsChoice);
		}

		FunctionNameChoices functionNameChoice =
			options.getEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		if (functionNameChoice != functionNameComboBox.getSelectedItem()) {
			functionNameComboBox.setSelectedItem(functionNameChoice);
		}

		FunctionSignatureChoices functionSignatureChoice =
			options.getEnum(FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		if (functionSignatureChoice != functionSignatureComboBox.getSelectedItem()) {
			functionSignatureComboBox.setSelectedItem(functionSignatureChoice);
		}
	}

	private void setEditorCommentValues(ToolOptions options) {

		CommentChoices plateCommentChoice =
			options.getEnum(PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS);
		if (plateCommentChoice != plateCommentsComboBox.getSelectedItem()) {
			plateCommentsComboBox.setSelectedItem(plateCommentChoice);
		}

		CommentChoices preCommentChoice =
			options.getEnum(PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS);
		if (preCommentChoice != preCommentsComboBox.getSelectedItem()) {
			preCommentsComboBox.setSelectedItem(preCommentChoice);
		}

		CommentChoices endOfLineCommentChoice =
			options.getEnum(END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS);
		if (endOfLineCommentChoice != endOfLineCommentsComboBox.getSelectedItem()) {
			endOfLineCommentsComboBox.setSelectedItem(endOfLineCommentChoice);
		}

		CommentChoices repeatableCommentChoice =
			options.getEnum(REPEATABLE_COMMENT, DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS);
		if (repeatableCommentChoice != repeatableCommentsComboBox.getSelectedItem()) {
			repeatableCommentsComboBox.setSelectedItem(repeatableCommentChoice);
		}

		CommentChoices postCommentChoice =
			options.getEnum(POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS);
		if (postCommentChoice != postCommentsComboBox.getSelectedItem()) {
			postCommentsComboBox.setSelectedItem(postCommentChoice);
		}
	}

	private void setEditorFunctionSignatureValues(ToolOptions options) {

		ParameterDataTypeChoices returnTypeChoice =
			options.getEnum(FUNCTION_RETURN_TYPE, DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
		if (returnTypeChoice != returnTypeComboBox.getSelectedItem()) {
			returnTypeComboBox.setSelectedItem(returnTypeChoice);
		}

		ReplaceChoices inlineChoice = options.getEnum(INLINE, DEFAULT_OPTION_FOR_INLINE);
		if (inlineChoice != inlineComboBox.getSelectedItem()) {
			inlineComboBox.setSelectedItem(inlineChoice);
		}

		ReplaceChoices noReturnChoice = options.getEnum(NO_RETURN, DEFAULT_OPTION_FOR_NO_RETURN);
		if (noReturnChoice != noReturnComboBox.getSelectedItem()) {
			noReturnComboBox.setSelectedItem(noReturnChoice);
		}

		CallingConventionChoices callingConventionChoice =
			options.getEnum(CALLING_CONVENTION, DEFAULT_OPTION_FOR_CALLING_CONVENTION);
		if (callingConventionChoice != callingConventionComboBox.getSelectedItem()) {
			callingConventionComboBox.setSelectedItem(callingConventionChoice);
		}

		ReplaceChoices callFixupChoice = options.getEnum(CALL_FIXUP, DEFAULT_OPTION_FOR_CALL_FIXUP);
		if (callFixupChoice != callFixupComboBox.getSelectedItem()) {
			callFixupComboBox.setSelectedItem(callFixupChoice);
		}

		ReplaceChoices varArgsChoice = options.getEnum(VAR_ARGS, DEFAULT_OPTION_FOR_VAR_ARGS);
		if (varArgsChoice != varArgsComboBox.getSelectedItem()) {
			varArgsComboBox.setSelectedItem(varArgsChoice);
		}
	}

	private void setEditorParameterValues(ToolOptions options) {

		ParameterDataTypeChoices parameterDataTypeChoice =
			options.getEnum(PARAMETER_DATA_TYPES, DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);
		if (parameterDataTypeChoice != parameterDataTypesComboBox.getSelectedItem()) {
			parameterDataTypesComboBox.setSelectedItem(parameterDataTypeChoice);
		}

		SourcePriorityChoices parameterNameChoice =
			options.getEnum(PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES);
		if (parameterNameChoice != parameterNamesComboBox.getSelectedItem()) {
			parameterNamesComboBox.setSelectedItem(parameterNameChoice);
		}

		HighestSourcePriorityChoices highestPriorityChoice =
			options.getEnum(HIGHEST_NAME_PRIORITY, DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY);
		if (highestPriorityChoice == HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST) {
			userHighestPriorityRB.setSelected(true);
		}
		else {
			importHighestPriorityRB.setSelected(true);
		}

		boolean replaceIfSameSource = options.getBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
			DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);
		if (replaceIfSameSource != replaceIfSameSourceCheckBox.isSelected()) {
			replaceIfSameSourceCheckBox.setSelected(replaceIfSameSource);
		}

		CommentChoices parameterCommentChoice =
			options.getEnum(PARAMETER_COMMENTS, DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);
		if (parameterCommentChoice != parameterCommentsComboBox.getSelectedItem()) {
			parameterCommentsComboBox.setSelectedItem(parameterCommentChoice);
		}
	}

	private void setEditorIgnoreMarkupValues(Options options) {

		boolean ignoreExcludedMarkup = options.getBoolean(IGNORE_EXCLUDED_MARKUP_ITEMS,
			DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS);
		if (ignoreExcludedMarkup != ignoreExcludedCheckBox.isSelected()) {
			ignoreExcludedCheckBox.setSelected(ignoreExcludedMarkup);
		}

		boolean ignoreIncompleteMarkup = options.getBoolean(IGNORE_INCOMPLETE_MARKUP_ITEMS,
			DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS);
		if (ignoreIncompleteMarkup != ignoreIncompleteCheckBox.isSelected()) {
			ignoreIncompleteCheckBox.setSelected(ignoreIncompleteMarkup);
		}
	}

	private JComboBox<Enum<?>> createComboBox(final String optionName, final Enum<?> choiceEnum) {
		EnumEditor editor = new EnumEditor();
		editor.setValue(choiceEnum);
		Enum<?>[] enums = editor.getEnums();

		final JComboBox<Enum<?>> applyComboBox = new GComboBox<>(enums);
		applyComboBox.addActionListener(e -> changesMade(true));

		return applyComboBox;
	}

	private JCheckBox createCheckBox(String optionName) {
		JCheckBox applyCheckBox = new GCheckBox(optionName);
		applyCheckBox.addChangeListener(e -> changesMade(true));

		return applyCheckBox;
	}

	private JRadioButton createRadioButton(final String optionName) {
		final GRadioButton applyRadioButton = new GRadioButton(optionName);
		applyRadioButton.addActionListener(e -> changesMade(true));

		return applyRadioButton;
	}

	// signals that there are unapplied changes
	private void changesMade(boolean changes) {
		// FIXME Is this ok? complete?
		if (listener != null) {
			listener.propertyChange(new PropertyChangeEvent(this, GhidraOptions.APPLY_ENABLED,
				unappliedChanges, changes));
		}
		unappliedChanges = changes;
	}

	@Override
	public void apply() throws InvalidInputException {
		updateOptions(originalOptions);
	}

	@Override
	public void cancel() {
		// no changes to undo
	}

	@Override
	public void reload() {
		originalOptions = controller.getOptions();
		setEditorValues(originalOptions);
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.listener = listener;
	}

	@Override
	public JComponent getEditorComponent(Options options, EditorStateFactory editorStateFactory) {
		return editorComponent;
	}
}
