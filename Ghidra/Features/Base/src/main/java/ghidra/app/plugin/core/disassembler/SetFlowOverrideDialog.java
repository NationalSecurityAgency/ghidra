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
package ghidra.app.plugin.core.disassembler;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.ProgramSelection;

class SetFlowOverrideDialog extends DialogComponentProvider {

	private static final String DEFAULT_CHOICE = "-DEFAULT-";

	private GhidraComboBox<Object> flowOverrideComboBox;

	private PluginTool tool;
	private Instruction instruction;
	private Program program;
	private ProgramSelection selection;

	/**
	 * Constructor
	 * @param tool plugin tool
	 * @param instruction the instruction which is having its flow modified.
	 */
	SetFlowOverrideDialog(PluginTool tool, Instruction instruction) {

		super("Modify Instruction Flow: " + instruction.getMinAddress(), true, false, true, false);
		this.tool = tool;
		this.instruction = instruction;
		this.program = instruction.getProgram();

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setRememberSize(false);
	}

	/**
	 * Constructor
	 * @param tool plugin tool
	 * @param Program program
	 * @param selection program selection
	 */
	SetFlowOverrideDialog(PluginTool tool, Program program, ProgramSelection selection) {

		super("Modify Instruction Flow on Selection", true, false, true, false);
		this.tool = tool;
		this.program = program;
		this.selection = selection;

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setRememberSize(false);
	}

	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2));
		if (instruction != null) {
			mainPanel.add(buildCurrentFlowPanel());
		}
		mainPanel.add(buildFlowOverridePanel());
		if (instruction != null && instruction.getFlowType().isConditional()) {
			mainPanel.add(buildNotePanel("*Conditional flow will be preserved"));
		}
		return mainPanel;
	}

	private JPanel buildCurrentFlowPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		FlowType flowType = instruction.getFlowType();

		panel.add(new GLabel(
			"Current Flow: " + flowType.getName() + (flowType.isConditional() ? "*" : "")));

		panel.add(Box.createGlue());
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return panel;
	}

	private JPanel buildNotePanel(String note) {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		panel.add(new GLabel(note));

		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return panel;
	}

	private JPanel buildFlowOverridePanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		flowOverrideComboBox = new GhidraComboBox<>();
		flowOverrideComboBox.addItem(DEFAULT_CHOICE);
		for (FlowOverride element : FlowOverride.values()) {
			if (element == FlowOverride.NONE) {
				continue; // skip
			}
			flowOverrideComboBox.addItem(element);
		}

		FlowOverride flowOverride = instruction != null ? instruction.getFlowOverride() : null;
		if (flowOverride == null) {
			flowOverrideComboBox.setSelectedItem(DEFAULT_CHOICE);
		}
		else {
			flowOverrideComboBox.setSelectedItem(flowOverride);
		}

		panel.add(new GLabel("Instruction Flow:"));
		panel.add(flowOverrideComboBox);

		panel.add(Box.createGlue());
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return panel;
	}

	protected PluginTool getTool() {
		return tool;
	}

	/**
	 * This method gets called when the user clicks on the OK Button.  The base
	 * class calls this method.
	 */
	@Override
	protected void okCallback() {
		// only close the dialog if the user made valid changes
		if (executeCommand()) {
			close();
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
	 */
	private boolean executeCommand() {

		FlowOverride flow = FlowOverride.NONE;
		Object choice = flowOverrideComboBox.getSelectedItem();
		if (!DEFAULT_CHOICE.equals(choice)) {
			flow = (FlowOverride) choice;
		}

		if (instruction == null) {
			tool.executeBackgroundCommand(new SetFlowOverrideCmd(selection, flow), program);
		}
		else if (instruction.getFlowOverride() == flow) {
			return true;
		}
		else {
			tool.executeBackgroundCommand(new SetFlowOverrideCmd(instruction.getMinAddress(), flow),
				program);
		}
		return true;
	}

}
