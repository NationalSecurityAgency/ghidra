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
package ghidra.app.plugin.core.function;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.exception.CancelledException;

/**
 * <code>EditFunctionSignatureDialog</code> provides an abstract implementation 
 * a function signature editor.  Use of this editor requires the presence of the tool-based
 * datatype manager service.
 */
public abstract class AbstractEditFunctionSignatureDialog extends DialogComponentProvider {

	private static final String NONE_CHOICE = "-NONE-";
	private static int SIGNATURE_COLUMNS = 60;

	protected JLabel signatureLabel;
	protected JTextField signatureField;
	protected JComboBox<String> callingConventionComboBox;
	protected JComboBox<String> callFixupComboBox;
	protected JCheckBox inlineCheckBox;
	protected JCheckBox noReturnCheckBox;

	protected boolean allowInLine;
	protected boolean allowNoReturn;
	protected boolean allowCallFixup;

	protected PluginTool tool;

	// Due to delayed initialization and tests not actually displaying dialog 
	// we will track function info initialization
	boolean initialized = false;

	/**
	 * Abstract function signature editor
	 *
	 * @param tool A reference to the active tool.
	 * @param title The title of the dialog.
	 * @param allowInLine true if in-line attribute control should be included
	 * @param allowNoReturn true if no-return attribute control should be added
	 * @param allowCallFixup true if call-fixup choice should be added
	 */
	public AbstractEditFunctionSignatureDialog(PluginTool tool, String title, boolean allowInLine,
			boolean allowNoReturn, boolean allowCallFixup) {

		super(title, true, true, true, false);
		this.tool = tool;
		this.allowInLine = allowInLine;
		this.allowNoReturn = allowNoReturn;
		this.allowCallFixup = allowCallFixup;

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setRememberSize(true);
	}

	@Override
	public JComponent getComponent() {
		setFunctionInfo(); //delay update for after construction
		return super.getComponent();
	}

	/**
	 * @return DataTypeManager associated with function or function definition
	 */
	protected abstract DataTypeManager getDataTypeManager();

	/**
	 * @return optional initial function signature which can assist parse with
	 * identifying referenced datatypes within signature
	 */
	protected abstract FunctionSignature getFunctionSignature();

	/**
	 * @return the initial signature string for the dialog
	 */
	protected abstract String getPrototypeString();

	/**
	 * @return initial calling convention name
	 */
	protected abstract String getCallingConventionName();

	/**
	 * @return list of acceptable calling convention names
	 */
	protected abstract List<String> getCallingConventionNames();

	/**
	 * @return initial in-line attribute value
	 */
	protected boolean isInline() {
		return false;
	}

	/**
	 * @return initial no-return attribute value
	 */
	protected boolean hasNoReturn() {
		return false;
	}

	/**
	 * @return initial call-fixup name or null if n/a
	 */
	protected abstract String getCallFixupName();

	/**
	 * @return array of allowed call fixup names or null
	 */
	protected abstract String[] getSupportedCallFixupNames();

	/**
	 * Method must be invoked following construction to fetch function info 
	 * and update components.
	 */
	private void setFunctionInfo() {
		if (initialized) {
			return;
		}
		initialized = true;

		signatureField.setText(getPrototypeString());
		setCallingConventionChoices();
		callingConventionComboBox.setSelectedItem(getCallingConventionName());
		if (allowInLine) {
			inlineCheckBox.setSelected(isInline());
		}
		if (allowNoReturn) {
			noReturnCheckBox.setSelected(hasNoReturn());
		}
		if (allowCallFixup) {
			setCallFixupChoices();

			String callFixupName = getCallFixupName();
			if (callFixupName != null) {
				callFixupComboBox.setSelectedItem(callFixupName);
			}
		}
	}

	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2));
		mainPanel.add(buildSignaturePanel());
		mainPanel.add(buildAttributePanel());
		if (allowCallFixup) {
			installCallFixupWidget(mainPanel);
		}
		return mainPanel;
	}

	private void installCallFixupWidget(JPanel parentPanel) {
		JPanel callFixupPanel = buildCallFixupPanel();
		parentPanel.add(callFixupPanel != null ? callFixupPanel : buildSpacerPanel());
	}

	private JPanel buildSignaturePanel() {
		JPanel signaturePanel = new JPanel();
		signaturePanel.setLayout(new BoxLayout(signaturePanel, BoxLayout.X_AXIS));

		signatureField = new JTextField(SIGNATURE_COLUMNS);
		signatureLabel = new GDLabel("Signature:");
		signaturePanel.add(signatureLabel);
		signaturePanel.add(signatureField);

		signaturePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return signaturePanel;
	}

	private Component buildSpacerPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		panel.add(Box.createVerticalStrut(20));

		return panel;
	}

	private JPanel buildAttributePanel() {
		JPanel attributePanel = new JPanel();
		attributePanel.setLayout(new BoxLayout(attributePanel, BoxLayout.X_AXIS));
		attributePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		installCallingConventionWidget(attributePanel);
		if (allowInLine) {
			installInlineWidget(attributePanel);
		}
		if (allowNoReturn) {
			installNoReturnWidget(attributePanel);
		}
		attributePanel.add(Box.createGlue());

		return attributePanel;
	}

	private void installCallingConventionWidget(JPanel parentPanel) {
		callingConventionComboBox = new GhidraComboBox<>();
		parentPanel.add(new GLabel("Calling Convention:"));
		parentPanel.add(callingConventionComboBox);
	}

	private void installInlineWidget(JPanel parentPanel) {
		inlineCheckBox = new GCheckBox("Inline");
		inlineCheckBox.addChangeListener(e -> {
			if (inlineCheckBox.isSelected() && callFixupComboBox != null) {
				callFixupComboBox.setSelectedItem(NONE_CHOICE);
			}
		});
		parentPanel.add(inlineCheckBox);
	}

	private void installNoReturnWidget(JPanel parentPanel) {
		noReturnCheckBox = new GCheckBox("No Return");
		parentPanel.add(noReturnCheckBox);
	}

	private JPanel buildCallFixupPanel() {

		if (allowCallFixup) {
			return null;
		}

		JPanel callFixupPanel = new JPanel();
		callFixupPanel.setLayout(new BoxLayout(callFixupPanel, BoxLayout.X_AXIS));

		callFixupComboBox = new GhidraComboBox<>();
		callFixupComboBox.addItemListener(e -> {
			if (e.getStateChange() == ItemEvent.DESELECTED) {
				return;
			}
			if (!NONE_CHOICE.equals(e.getItem())) {
				inlineCheckBox.setSelected(false);
			}
		});

		callFixupPanel.add(new GLabel("Call-Fixup:"));
		callFixupPanel.add(callFixupComboBox);

		callFixupPanel.add(Box.createGlue());
		callFixupPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return callFixupPanel;
	}

	/**
	 * @return plugin tool for which dialog was constructed
	 */
	protected PluginTool getTool() {
		return tool;
	}

	private String getSignature() {
		return signatureField.getText();
	}

	private void setCallingConventionChoices() {
		callingConventionComboBox.removeAllItems();
		for (String element : getCallingConventionNames()) {
			callingConventionComboBox.addItem(element);
		}
	}

	/**
	 * @return current calling convention selection from dialog
	 */
	protected String getCallingConvention() {
		return (String) callingConventionComboBox.getSelectedItem();
	}

	/**
	 * @return current in-line attribute value from dialog
	 */
	protected boolean isInlineSelected() {
		return inlineCheckBox != null ? inlineCheckBox.isSelected() : false;
	}

	/**
	 * @return current no-return attribute value from dialog
	 */
	protected boolean hasNoReturnSelected() {
		return noReturnCheckBox != null ? noReturnCheckBox.isSelected() : false;
	}

	private void setCallFixupChoices() {
		String[] callFixupNames = getSupportedCallFixupNames();
		callFixupComboBox.addItem(NONE_CHOICE);
		if (callFixupNames != null) {
			for (String element : callFixupNames) {
				callFixupComboBox.addItem(element);
			}
		}
	}

	/**
	 * @return current call fixup selection from dialog or null
	 */
	protected String getCallFixupSelection() {
		if (callFixupComboBox != null) {
			String callFixup = (String) callFixupComboBox.getSelectedItem();
			if (callFixup != null && !NONE_CHOICE.equals(callFixup)) {
				return callFixup;
			}
		}
		return null;
	}

	/**
	 * This method gets called when the user clicks on the OK Button.  The base
	 * class calls this method.  This method will invoke {@link #applyChanges()} 
	 * and close dialog if that method returns true.  If false is returned, the
	 * {@link #applyChanges()} method should display a status message to indicate
	 * the failure.
	 */
	@Override
	protected void okCallback() {
		// only close the dialog if the user made valid changes
		try {
			if (applyChanges()) {
				close();
			}
		}
		catch (CancelledException e) {
			// ignore - do not close
		}
	}

	@Override
	protected void cancelCallback() {
		setStatusText("");
		close();
	}

	/**
	 * Called when the user initiates changes that need to be applied to the 
	 * underlying function or function definition
	 *
	 * @return true if applied successfully, otherwise false which will keep 
	 * dialog displayed (a status message should bet set)
	 * @throws CancelledException if operation cancelled by user
	 */
	protected abstract boolean applyChanges() throws CancelledException;

	/**
	 * Perform parse of current user-specified function signature (see {@link #getSignature()})
	 * and return valid {@link FunctionDefinitionDataType} if parse successful.
	 * @return function definition data type if parse successful, otherwise null
	 * @throws CancelledException if function signature entry cancelled
	 */
	protected final FunctionDefinitionDataType parseSignature() throws CancelledException {
		setFunctionInfo(); // needed for testing which never shows dialog
		FunctionSignatureParser parser = new FunctionSignatureParser(
			getDataTypeManager(), tool.getService(DataTypeManagerService.class));
		try {
			// FIXME: Parser returns FunctionDefinition which only supports GenericCallingConventions
			return parser.parse(getFunctionSignature(), getSignature());
		}
		catch (ParseException e) {
			setStatusText("Invalid Signature: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Determine if user-specified function signature has been modified from original
	 * @return true if modified signature has been entered, else false
	 */
	protected final boolean isSignatureChanged() {
		return !getSignature().equals(getPrototypeString());
	}

	/**
	 * Determine if user has changed the selected calling convention from the original
	 * @return true if a change in the selected calling convention has been made
	 */
	protected final boolean isCallingConventionChanged() {
		String current = getCallingConventionName();
		if (current == null && this.getCallingConvention() == null) {
			return false;
		}
		if (current == null && this.getCallingConvention().equals("default")) {
			return false;
		}
		if (current == null && this.getCallingConvention().equals("unknown")) {
			return false;
		}
		if (current == null) {
			return true;
		}
		if (current.equals(getCallingConvention())) {
			return false;
		}
		return true;
	}

	@Override
	protected void dialogShown() {
		signatureField.selectAll();
	}
}
