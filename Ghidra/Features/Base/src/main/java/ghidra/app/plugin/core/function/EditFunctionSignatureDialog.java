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
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * <code>EditFunctionSignatureDialog</code> provides the ability to edit function
 * signatures.  Use of this editor requires the presence of the tool-based
 * datatype manager service.
 */
public class EditFunctionSignatureDialog extends DialogComponentProvider {

	private static final String NONE_CHOICE = "-NONE-";

	protected JLabel signatureLabel;
	protected JTextField signatureField;
	protected JComboBox<String> callingConventionComboBox;
	protected JComboBox<String> callFixupComboBox;
	protected JCheckBox inlineCheckBox;
	protected JCheckBox noReturnCheckBox;

	protected PluginTool tool;
	protected Function function;
	protected String oldFunctionName;
	protected String oldFunctionSignature;

	/**
	 * This class is not meant to be instantiated directly, but rather by
	 * subclasses.
	 *
	 * @param plugin A reference to the FunctionPlugin.
	 * @param title The title of the dialog.
	 * @param function the function which is having its signature edited.
	 */
	public EditFunctionSignatureDialog(PluginTool tool, String title, final Function function) {

		super(title, true, true, true, false);
		this.tool = tool;
		this.function = function;
		this.oldFunctionName = function.getName();
		this.oldFunctionSignature = function.getSignature().getPrototypeString();

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setFunctionInfo();
		setRememberSize(true);
	}

	protected void setFunctionInfo() {
		setSignature(function.getSignature().getPrototypeString());
		setCallingConvention(function.getCallingConventionName());
		setInlineSelected(function.isInline());
		inlineCheckBox.setEnabled(!getAffectiveFunction(function).isExternal());
		setNoReturnSelected(function.hasNoReturn());
	}

	/**
	 * Get the effective function to which changes will be made.  This
	 * will be the same as function unless it is a thunk in which case
	 * the returned function will be the ultimate non-thunk function.
	 * @param f
	 * @return non-thunk function
	 */
	protected Function getAffectiveFunction(Function f) {
		return f.isThunk() ? f.getThunkedFunction(true) : f;
	}

	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2));
		mainPanel.add(buildSignaturePanel());
		mainPanel.add(buildAttributePanel());

		installCallFixupWidget(mainPanel);

		return mainPanel;
	}

	protected void installCallFixupWidget(JPanel parentPanel) {
		JPanel callFixupPanel = buildCallFixupPanel();
		parentPanel.add(callFixupPanel != null ? callFixupPanel : buildSpacerPanel());
	}

	private JPanel buildSignaturePanel() {
		JPanel signaturePanel = new JPanel();
		signaturePanel.setLayout(new BoxLayout(signaturePanel, BoxLayout.X_AXIS));

		String signature = function.getPrototypeString(false, false);
		signatureField = new JTextField(signature.length()); // add some extra room to edit
		signatureField.setText(signature);
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
		installInlineWidget(attributePanel);
		installNoReturnWidget(attributePanel);
		attributePanel.add(Box.createGlue());

		return attributePanel;
	}

	protected void installCallingConventionWidget(JPanel parentPanel) {
		callingConventionComboBox = new GhidraComboBox<>();
		List<String> callingConventions =
			function.getProgram().getFunctionManager().getCallingConventionNames();
		String[] choices = callingConventions.toArray(new String[callingConventions.size()]);
		setCallingConventionChoices(choices);
		parentPanel.add(new GLabel("Calling Convention:"));
		parentPanel.add(callingConventionComboBox);
	}

	protected void installInlineWidget(JPanel parentPanel) {
		inlineCheckBox = new GCheckBox("Inline");
		inlineCheckBox.addChangeListener(e -> {
			if (inlineCheckBox.isSelected() && callFixupComboBox != null) {
				callFixupComboBox.setSelectedItem(NONE_CHOICE);
			}
		});
		parentPanel.add(inlineCheckBox);
	}

	protected void installNoReturnWidget(JPanel parentPanel) {
		noReturnCheckBox = new GCheckBox("No Return");
		parentPanel.add(noReturnCheckBox);
	}

	private JPanel buildCallFixupPanel() {

		String[] callFixupNames =
			function.getProgram().getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames();
		if (callFixupNames.length == 0) {
			return null;
		}

		JPanel callFixupPanel = new JPanel();
		callFixupPanel.setLayout(new BoxLayout(callFixupPanel, BoxLayout.X_AXIS));

		callFixupComboBox = new GhidraComboBox<>();
		callFixupComboBox.addItem(NONE_CHOICE);
		for (String element : callFixupNames) {
			callFixupComboBox.addItem(element);
		}

		callFixupComboBox.addItemListener(e -> {
			if (e.getStateChange() == ItemEvent.DESELECTED) {
				return;
			}
			if (!NONE_CHOICE.equals(e.getItem())) {
				inlineCheckBox.setSelected(false);
			}
		});

		String callFixupName = function.getCallFixup();
		if (callFixupName != null) {
			callFixupComboBox.setSelectedItem(callFixupName);
		}

		callFixupPanel.add(new GLabel("Call-Fixup:"));
		callFixupPanel.add(callFixupComboBox);

		callFixupPanel.add(Box.createGlue());
		callFixupPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return callFixupPanel;
	}

	protected PluginTool getTool() {
		return tool;
	}

	protected Program getProgram() {
		return function.getProgram();
	}

	protected Function getFunction() {
		return function;
	}

	public String getSignature() {
		return signatureField.getText();
	}

	protected void setSignature(String signature) {
		signatureField.setText(signature);
	}

	protected void setCallingConventionChoices(String[] callingConventions) {
		callingConventionComboBox.removeAllItems();
		for (String element : callingConventions) {
			callingConventionComboBox.addItem(element);
		}
	}

	protected String getCallingConvention() {
		return (String) callingConventionComboBox.getSelectedItem();
	}

	protected void setCallingConvention(String callingConvention) {
		callingConventionComboBox.setSelectedItem(callingConvention);
	}

	protected boolean isInlineSelected() {
		return inlineCheckBox.isSelected();
	}

	protected void setInlineSelected(boolean selected) {
		inlineCheckBox.setSelected(selected);
	}

	protected boolean hasNoReturnSelected() {
		return noReturnCheckBox.isSelected();
	}

	protected void setNoReturnSelected(boolean selected) {
		noReturnCheckBox.setSelected(selected);
	}

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
	 * class calls this method.
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
	 * Called when the user initiates changes that need to be put into a
	 * command and executed.
	 *
	 * @return true if the command was successfully created.
	 * @throws CancelledException if operation cancelled by user
	 */
	protected boolean applyChanges() throws CancelledException {
		// create the command
		Command command = createCommand();

		if (command == null) {
			return false;
		}

		// run the command
		if (!getTool().execute(command, getProgram())) {
			setStatusText(command.getStatusMsg());
			return false;
		}

		setStatusText("");
		return true;
	}

	protected FunctionDefinitionDataType parseSignature() throws CancelledException {
		FunctionSignatureParser parser = new FunctionSignatureParser(
			getProgram().getDataTypeManager(), tool.getService(DataTypeManagerService.class));
		try {
			return parser.parse(getFunction().getSignature(), getSignature());
		}
		catch (ParseException e) {
			setStatusText("Invalid Signature: " + e.getMessage());
		}
		return null;
	}

	private Command createCommand() throws CancelledException {

		Command cmd = null;
		if (!getSignature().equals(this.oldFunctionSignature) || !isSameCallingConvention() ||
			(function.getSignatureSource() == SourceType.DEFAULT)) {

			FunctionDefinitionDataType definition = parseSignature();
			cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition,
				SourceType.USER_DEFINED, true, true);
		}

		CompoundCmd compoundCommand = new CompoundCmd("Update Function Signature");

		compoundCommand.add(new Command() {
			String errMsg = null;

			@Override
			public boolean applyTo(DomainObject obj) {
				try {
					String conventionName = getCallingConvention();
					if ("unknown".equals(conventionName)) {
						conventionName = null;
					}
					else if ("default".equals(conventionName)) {
						conventionName = function.getDefaultCallingConventionName();
					}
					function.setCallingConvention(conventionName);
					return true;
				}
				catch (InvalidInputException e) {
					errMsg = "Invalid calling convention. " + e.getMessage();
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					return false;
				}
			}

			@Override
			public String getName() {
				return "Update Function Calling Convention";
			}

			@Override
			public String getStatusMsg() {
				return errMsg;
			}
		});
		compoundCommand.add(new Command() {
			@Override
			public boolean applyTo(DomainObject obj) {
				function.setInline(isInlineSelected());
				return true;
			}

			@Override
			public String getName() {
				return "Update Function Inline Flag";
			}

			@Override
			public String getStatusMsg() {
				return null;
			}
		});
		compoundCommand.add(new Command() {
			@Override
			public boolean applyTo(DomainObject obj) {
				function.setNoReturn(hasNoReturnSelected());
				return true;
			}

			@Override
			public String getName() {
				return "Update Function No Return Flag";
			}

			@Override
			public String getStatusMsg() {
				return null;
			}
		});
		compoundCommand.add(new Command() {
			@Override
			public boolean applyTo(DomainObject obj) {
				function.setCallFixup(getCallFixupSelection());
				return true;
			}

			@Override
			public String getName() {
				return "Update Function Call-Fixup";
			}

			@Override
			public String getStatusMsg() {
				return null;
			}
		});
		if (cmd != null) {
			compoundCommand.add(cmd);
		}
		return compoundCommand;
	}

	private boolean isSameCallingConvention() {
		PrototypeModel conv = function.getCallingConvention();
		if (conv == null && this.getCallingConvention() == null) {
			return true;
		}
		if (conv == null && this.getCallingConvention().equals("default")) {
			return true;
		}
		if (conv == null && this.getCallingConvention().equals("unknown")) {
			return true;
		}
		if (conv == null) {
			return false;
		}
		if (conv.getName().equals(this.getCallingConvention())) {
			return true;
		}
		return false;
	}

	@Override
	protected void dialogShown() {
		signatureField.selectAll();
	}
}
